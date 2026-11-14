"""NUP LayeredFS mod patcher: overlay mod files onto a container.

Applies mod directories (LayeredFS romfs/exefs or Atmosphere contents) directly
to an existing .nup container. Unchanged files are streamed directly from the
source container, while replaced and added files are integrated into the virtual
tree, compressed, and atomically verified.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shutil
import struct
import time
from typing import Callable, Final, IO, cast
import zstandard

from . import format as F
from . import meta as M
from .access import app_meta, iter_children, localized_icons, localized_titles
from .discover import DirObj, FileObj, PackInput, Tree, build_virtual_tree
from .pack import pack_virtual
from .read import BoundedMmapReader, NupReader, PackageInfo
from .switchfs.errors import CancelledError, UnpackError
from .switchfs.unpack import Progress
from .verify import verify

ProgressFn = Callable[[Progress], None]
CancelFn = Callable[[], bool]

_EXCLUDE_FILENAMES: Final = frozenset({".ds_store", "thumbs.db", "desktop.ini"})


@dataclass(slots=True)
class PatchResult:
    container_path: Path
    package_title_id: int
    files_replaced: int
    files_added: int
    total_files: int


def _replace_retry(tmp: str, path: str, attempts: int = 6) -> None:
    """Safely replace path with tmp on Windows, retrying transient PermissionError."""
    for attempt in range(attempts):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(0.25 * (attempt + 1))


def _collect_mod_tree(root: Path) -> dict[str, Path]:
    """Gather all files under root mapped to normalized forward-slash paths."""
    has_romfs = (root / "romfs").is_dir()
    has_exefs = (root / "exefs").is_dir()

    files: dict[str, Path] = {}
    for p in root.rglob("*"):
        if not p.is_file() or p.is_symlink():
            continue
        cur = p
        has_symlink_ancestor = False
        while cur != root and cur != cur.parent:
            if cur.is_symlink() or (hasattr(os.path, "isjunction") and os.path.isjunction(cur)):
                has_symlink_ancestor = True
                break
            cur = cur.parent
        if has_symlink_ancestor:
            continue
        if p.name.lower() in _EXCLUDE_FILENAMES:
            continue
        rel = p.relative_to(root).as_posix()
        if any(part in ("..", ".") or ":" in part for part in rel.split("/")):
            continue
        if has_romfs or has_exefs:
            if rel.startswith("romfs/") or rel.startswith("exefs/"):
                files[rel] = p
            elif not has_exefs and not rel.startswith("exefs/"):
                files[f"romfs/{rel}"] = p
        else:
            if rel in ("main.npdm", "main", "rtld", "sdk") or rel.startswith("subsdk"):
                files[f"exefs/{rel}"] = p
            else:
                files[f"romfs/{rel}"] = p
    return files


def _scan_mod_directory(mod_dir: Path) -> tuple[dict[str, Path], int | None]:
    """Scan a mod directory, returning (files_map, detected_title_id)."""
    # 1. Atmosphere contents layout: mod_dir/contents/<16-hex tid>/...
    contents_dir = mod_dir / "contents"
    if contents_dir.is_dir():
        for sub in contents_dir.iterdir():
            if sub.is_dir() and len(sub.name) == 16:
                try:
                    tid = int(sub.name, 16)
                    return _collect_mod_tree(sub), tid
                except ValueError:
                    pass

    # 2. Direct <16-hex tid> subdirectory
    for sub in mod_dir.iterdir():
        if sub.is_dir() and len(sub.name) == 16:
            if (sub / "romfs").is_dir() or (sub / "exefs").is_dir():
                try:
                    tid = int(sub.name, 16)
                    return _collect_mod_tree(sub), tid
                except ValueError:
                    pass

    # 3. Direct mod directory
    return _collect_mod_tree(mod_dir), None


def _resolve_target_package(
    packages: list[PackageInfo],
    spec: str | int | None,
    detected_tid: int | None,
) -> PackageInfo:
    """Resolve which package to apply the mod to."""
    if spec is not None:
        if isinstance(spec, int):
            for p in packages:
                if p.title_id == spec:
                    return p
            raise F.NupError(f"patch: title ID 0x{spec:016X} not found in container")
        spec_s = str(spec).strip()
        if spec_s.isdigit() and len(spec_s) < 6:
            idx = int(spec_s)
            if 0 <= idx < len(packages):
                return packages[idx]
            raise F.NupError(f"patch: package index {idx} out of range ({len(packages)} packages)")
        if len(spec_s) == 16:
            try:
                tid = int(spec_s, 16)
                for p in packages:
                    if p.title_id == tid:
                        return p
                raise F.NupError(f"patch: title ID {spec_s} not found in container")
            except ValueError:
                pass
        for kind_val, kind_name in F.KIND_NAMES.items():
            if spec_s.lower() == kind_name:
                found = next((p for p in packages if p.kind == kind_val), None)
                if found is not None:
                    return found
                raise F.NupError(f"patch: no {kind_name} package found in container")
        raise F.NupError(f"patch: unrecognized package selector {spec!r}")

    if detected_tid is not None:
        for p in packages:
            if p.title_id == detected_tid:
                return p

    base_pkg = next((p for p in packages if p.kind == F.KIND_BASE), None)
    if base_pkg is not None:
        return base_pkg
    return packages[0]


def _collect_package_files(r: NupReader, dir_idx: int, prefix: str = "") -> list[tuple[str, int]]:
    """Recursively collect (rel_path, file_index) for all files under a directory."""
    out: list[tuple[str, int]] = []
    for child in iter_children(r, dir_idx):
        name_str = child.name.decode("utf-8", "surrogateescape")
        rel = f"{prefix}/{name_str}" if prefix else name_str
        if child.is_dir:
            out.extend(_collect_package_files(r, child.index, rel))
        else:
            out.append((rel, child.index))
    return out


def _make_nup_reader(
    r: NupReader,
    file_index: int,
    size: int,
    codec: F.Codec,
    eoff: int,
    esz: int,
) -> Callable[[int, int], bytes]:
    """Create a stream reader for an existing file in a .nup container."""
    if size == 0:
        return lambda pos, n: b""
    if codec == F.CODEC_RAW:
        return lambda pos, n: r._mm[eoff + pos : eoff + pos + min(n, max(0, size - pos))]
    # ZSTD: use fast memory cache for small files, and streaming reader for large files
    if size <= 16 * 1024 * 1024:
        buf_box: list[bytes | None] = [None]

        def read_at_cached(pos: int, n: int) -> bytes:
            if n <= 0 or pos >= size:
                return b""
            if buf_box[0] is None:
                buf_box[0] = r.read_file(file_index)
            data = buf_box[0]
            assert data is not None
            return data[pos : pos + min(n, size - pos)]

        return read_at_cached

    class StreamingZstdReader:
        def __init__(self) -> None:
            self._reader: IO[bytes] | None = None
            self._bmr: BoundedMmapReader | None = None
            self._pos = 0

        def _reset(self) -> None:
            if self._reader is not None:
                try:
                    self._reader.close()
                except Exception:
                    pass
            dctx = zstandard.ZstdDecompressor()
            self._bmr = BoundedMmapReader(r._mm, eoff, esz, chunk_size=65536)
            self._reader = cast(IO[bytes], dctx.stream_reader(cast(IO[bytes], self._bmr)))
            self._pos = 0

        def read_at_stream(self, pos: int, n: int) -> bytes:
            if n <= 0 or pos >= size:
                return b""
            if self._reader is None or pos < self._pos:
                self._reset()
            assert self._reader is not None
            while self._pos < pos:
                skip_len = min(65536, pos - self._pos)
                skipped = self._reader.read(skip_len)
                if not skipped:
                    return b""
                self._pos += len(skipped)
            buf = bytearray()
            while len(buf) < n and self._pos < size:
                step = min(65536, n - len(buf))
                chunk = self._reader.read(step)
                if not chunk:
                    break
                buf.extend(chunk)
                self._pos += len(chunk)
            return bytes(buf)

    streamer = StreamingZstdReader()
    return streamer.read_at_stream


def _make_disk_reader(path: Path, open_handles: list[IO[bytes]]) -> Callable[[int, int], bytes]:
    """Create a stream reader for a file on disk."""
    fh_box: list[IO[bytes] | None] = [None]

    def read_at(pos: int, n: int) -> bytes:
        if n <= 0:
            return b""
        if fh_box[0] is None:
            fh = open(path, "rb")
            fh_box[0] = fh
            open_handles.append(fh)
        fh_active = fh_box[0]
        assert fh_active is not None
        fh_active.seek(pos)
        return fh_active.read(n)

    return read_at


def patch(
    container_path: Path | str,
    mod_dir: Path | str,
    out_path: Path | str | None = None,
    *,
    package: str | int | None = None,
    threads: int = -1,
    level: int = 19,
    replace: bool = False,
    fast: bool = False,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> PatchResult:
    """Apply a LayeredFS mod directory to an existing .nup container."""
    container_p = Path(container_path)
    mod_p = Path(mod_dir)

    if not container_p.is_file():
        raise F.NupError(f"container file not found: {container_p}")
    if not mod_p.is_dir():
        raise F.NupError(f"mod directory not found: {mod_p}")

    is_inplace = (out_path is None or Path(out_path).resolve() == container_p.resolve())
    final_out_p = container_p if is_inplace else Path(out_path)  # type: ignore[arg-type]

    if not is_inplace and final_out_p.exists() and not replace:
        raise F.NupError(f"output file already exists: {final_out_p}")

    def check_cancel() -> None:
        if cancel is not None and cancel():
            raise CancelledError()

    check_cancel()

    # 1. Scan mod files
    prog = Progress(stage="scan")
    if progress:
        progress(prog)

    mod_files, detected_tid = _scan_mod_directory(mod_p)
    if not mod_files:
        raise F.NupError(f"no mod files found in {mod_p}")

    # 2. Open existing container
    r = NupReader(str(container_p))
    open_handles: list[IO[bytes]] = []
    temp_files: list[Path] = []
    staging_dir = final_out_p.parent
    part_path = staging_dir / f"{final_out_p.name}.partial"

    try:
        target_pkg = _resolve_target_package(r.packages, package, detected_tid)

        roots: list[DirObj] = []
        packages: list[PackInput] = []

        files_replaced = 0
        files_added = 0
        total_target_files = 0

        # Build virtual tree for each package
        for p in r.packages:
            check_cancel()
            pkg_raw_files = _collect_package_files(r, p.root_dir)

            if p.index == target_pkg.index:
                # Target package: overlay mod files
                consumed_mods: set[str] = set()
                target_entries: list[tuple[str, Callable[[int, int], bytes], int]] = []

                npdm_bytes: bytes | None = None
                build_id_bytes: bytes | None = None

                for rel, fi in pkg_raw_files:
                    if rel in mod_files:
                        # Replaced by mod
                        mpath = mod_files[rel]
                        msize = os.path.getsize(mpath)
                        mread = _make_disk_reader(mpath, open_handles)
                        target_entries.append((rel, mread, msize))
                        consumed_mods.add(rel)
                        files_replaced += 1
                        if rel == "exefs/main.npdm":
                            npdm_bytes = mpath.read_bytes()
                        elif rel == "exefs/main" and msize >= 0x60:
                            head = mread(0, 0x60)
                            if head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0":
                                build_id_bytes = head[0x40:0x60]
                    else:
                        # Unchanged
                        name, size, sha, eoff, esz, codec = r.files[fi]
                        nread = _make_nup_reader(r, fi, size, codec, eoff, esz)
                        target_entries.append((rel, nread, size))
                        if rel == "exefs/main.npdm" and npdm_bytes is None:
                            npdm_bytes = r.read_file(fi)
                        elif rel == "exefs/main" and size >= 0x60 and build_id_bytes is None:
                            head = nread(0, 0x60)
                            if head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0":
                                build_id_bytes = head[0x40:0x60]

                # Append newly added files from mod
                for rel, mpath in sorted(mod_files.items()):
                    if rel not in consumed_mods:
                        msize = os.path.getsize(mpath)
                        mread = _make_disk_reader(mpath, open_handles)
                        target_entries.append((rel, mread, msize))
                        files_added += 1
                        if rel == "exefs/main.npdm" and npdm_bytes is None:
                            npdm_bytes = mpath.read_bytes()
                        elif rel == "exefs/main" and msize >= 0x60 and build_id_bytes is None:
                            head = mread(0, 0x60)
                            if head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0":
                                build_id_bytes = head[0x40:0x60]

                total_target_files = len(target_entries)
                root_obj = build_virtual_tree(target_entries)
                roots.append(root_obj)
                packages.append(PackInput(
                    kind=p.kind,
                    src=container_p.name,
                    title_id=p.title_id,
                    version=p.version,
                    flags=p.flags,
                    npdm=npdm_bytes,
                    build_id=build_id_bytes,
                ))
            else:
                # Non-target package: preserve as-is
                other_entries: list[tuple[str, Callable[[int, int], bytes], int]] = []
                o_npdm: bytes | None = None
                o_bid: bytes | None = None

                for rel, fi in pkg_raw_files:
                    name, size, sha, eoff, esz, codec = r.files[fi]
                    nread = _make_nup_reader(r, fi, size, codec, eoff, esz)
                    other_entries.append((rel, nread, size))
                    if rel == "exefs/main.npdm":
                        o_npdm = r.read_file(fi)
                    elif rel == "exefs/main" and size >= 0x60:
                        head = nread(0, 0x60)
                        if head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0":
                            o_bid = head[0x40:0x60]

                root_obj = build_virtual_tree(other_entries)
                roots.append(root_obj)
                packages.append(PackInput(
                    kind=p.kind,
                    src=container_p.name,
                    title_id=p.title_id,
                    version=p.version,
                    flags=p.flags,
                    npdm=o_npdm,
                    build_id=o_bid,
                ))

        tree = Tree(artifacts=set())
        tree.assign(roots)

        # App metadata from base/target package
        base_or_target = next((p for p in r.packages if p.kind == F.KIND_BASE), target_pkg)
        meta_dict = app_meta(r, base_or_target)
        nacp_title = meta_dict.get(F.TLV_TITLE_NAME, b"").decode("utf-8", "replace") or None
        nacp_pub = meta_dict.get(F.TLV_PUBLISHER, b"").decode("utf-8", "replace") or None
        nacp_ver = meta_dict.get(F.TLV_DISPLAY_VERSION, b"").decode("utf-8", "replace") or None

        meta_names: dict[str | None, str] | None = None
        titles_map = localized_titles(r, base_or_target)
        if titles_map:
            meta_names = {k.decode("latin1") if k else None: v.decode("utf-8", "replace") for k, v in titles_map.items()}
        elif nacp_title:
            meta_names = {None: nacp_title}

        meta_icons: dict[str | None, str] | None = None
        icons_map = localized_icons(r, base_or_target)
        if icons_map:
            meta_icons = {}
            for lang_tag, raw_icon in icons_map.items():
                tag_str = lang_tag.decode("latin1") if lang_tag else None
                tmp_ic = staging_dir / f".tmp_{os.getpid()}_{tag_str or 'def'}_icon.dat"
                temp_files.append(tmp_ic)
                tmp_ic.write_bytes(raw_icon)
                meta_icons[tag_str] = str(tmp_ic)
        elif F.TLV_ICON in meta_dict:
            tmp_ic = staging_dir / f".tmp_{os.getpid()}_def_icon.dat"
            temp_files.append(tmp_ic)
            tmp_ic.write_bytes(meta_dict[F.TLV_ICON])
            meta_icons = {None: str(tmp_ic)}

        prog.stage = "pack"
        prog.total = len(tree.files)
        prog.bytes_total = sum(f.size for f in tree.files)
        prog.done = 0
        prog.bytes_done = 0
        if progress:
            progress(prog)

        def on_pack_progress(done: int, total: int, fnode: FileObj) -> None:
            check_cancel()
            prog.done = done
            prog.total = total
            prog.current = fnode.name.decode("utf-8", "replace")
            prog.bytes_done += fnode.size
            if prog.bytes_done > prog.bytes_total:
                prog.bytes_total = prog.bytes_done
            if progress:
                progress(prog)

        if is_inplace:
            target_pack_out = staging_dir / f".tmp_{os.getpid()}_{time.time_ns()}.nup"
            temp_files.append(target_pack_out)
        else:
            target_pack_out = final_out_p

        pack_virtual(
            str(target_pack_out),
            packages,
            roots,
            tree,
            dump_label=container_p.name,
            level=level,
            replace=True,
            display_version=nacp_ver,
            publisher=nacp_pub,
            names=meta_names,
            icons=meta_icons,
            progress=on_pack_progress,
            threads=threads,
        )

        # Verification step
        if not fast:
            prog.stage = "verify"
            prog.current = "Deep SHA-256 verification"
            if progress:
                progress(prog)
            ok, problems = verify(str(target_pack_out), deep=True)
            if not ok:
                raise F.NupError(f"patched container verification failed: {problems}")

        if is_inplace:
            for fh in open_handles:
                try:
                    fh.close()
                except OSError:
                    pass
            open_handles.clear()
            r.close()
            _replace_retry(str(target_pack_out), str(final_out_p))
            if target_pack_out in temp_files:
                temp_files.remove(target_pack_out)

        prog.stage = "done"
        prog.done = prog.total
        prog.current = ""
        if progress:
            progress(prog)

        return PatchResult(
            container_path=final_out_p,
            package_title_id=target_pkg.title_id,
            files_replaced=files_replaced,
            files_added=files_added,
            total_files=total_target_files,
        )

    finally:
        # Close open disk handles
        for fh in open_handles:
            try:
                fh.close()
            except OSError:
                pass
        # Close reader
        try:
            r.close()
        except Exception:
            pass
        # Sweep temp files
        for tmp in temp_files:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        # Sweep partial file if failed
        try:
            part_path.unlink(missing_ok=True)
        except OSError:
            pass
