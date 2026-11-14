"""One-shot direct dump -> .nup archive conversion without intermediate disk files.

Streams decrypted and BKTR-merged content directly from Switch dump containers
(NSP/NSZ/XCI/XCZ/NCA) into compressed NUP file extents in memory.
Supports single dumps, multi-package dumps, explicit update/DLC lists,
and auto-discovering/merging sibling packages into a single consolidated .nup.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
import time
from typing import Callable, Final, IO, Sequence

from . import format as F
from .discover import DirObj, FileObj, PackInput, Tree, build_virtual_tree
from .pack import pack_virtual
from .switchfs.bktr import BktrReader, load_bktr
from .switchfs.cnmt import ContentType, MetaType
from .switchfs.errors import CancelledError, UnpackError
from .switchfs.keys import Keyset
from .switchfs.nacp import Nacp, parse_nacp
from .switchfs.nca import Nca, SectionReader
from .switchfs.ncz import is_ncz, ncz_to_nca
from .switchfs.reader import ReadAt, SliceReader, read_exact
from .switchfs.romfs import RomFs
from .switchfs.unpack import (
    Progress,
    _Entry,
    _ProgressSink,
    _detect_kind,
    _find_exefs_section,
    _get_base_romfs_reader,
    _keygen,
    _list_pfs0,
    _list_xci,
    _open_file,
    _parse_meta_entry,
    _peek_header,
    _probe_nca_titlekey,
    _resolve_base,
    _resolve_titlekey,
    _slice_reader,
    read_at_file,
    _NTYPE_PROGRAM,
    _NTYPE_META,
    _NTYPE_CONTROL,
    _NTYPE_MANUAL,
    _NTYPE_DATA,
    _NTYPE_PUBLIC_DATA,
    _DUMP_SUFFIXES,
)
from .verify import verify

ProgressFn = Callable[[Progress], None]
CancelFn = Callable[[], bool]


@dataclass(slots=True)
class _ConvertWork:
    entry: _Entry
    nca_type: int
    titlekey: bytes | None
    is_ncz: bool = False
    is_bktr: bool = False
    base_id: int = 0
    pkg_title_id: int = 0
    pkg_version: int = 0
    fh: IO[bytes] | None = None
    src_path: Path | None = None


def _work_priority(w: _ConvertWork) -> int:
    """Process Base Program first (0) to extract base RomFS reader, then Control (1),

    then BKTR Updates (2) so they merge against base RomFS, then DLCs (3).
    """
    if not w.is_bktr and w.nca_type == _NTYPE_PROGRAM:
        return 0
    if w.nca_type == _NTYPE_CONTROL:
        return 1
    if w.is_bktr:
        return 2
    return 3


def convert(
    src: Path | str,
    out: Path | str,
    *,
    keys_path: Path | str | None = None,
    title_keys_path: Path | str | None = None,
    base: Path | str | None = None,
    updates: Sequence[Path | str] | None = None,
    dlcs: Sequence[Path | str] | None = None,
    merge_siblings: bool = False,
    threads: int = 0,
    level: int = 3,
    replace: bool = False,
    fast: bool = False,
    name: str | None = None,
    publisher: str | None = None,
    display_version: str | None = None,
    no_control: bool = False,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> list[PackInput]:
    """Directly convert Switch dump(s) into a consolidated .nup archive in a single pass."""
    src_p = Path(src)
    out_p = Path(out)

    source_files: list[Path] = []
    if src_p.is_dir():
        # Source is a directory: find all dump files in it
        try:
            out_p.resolve().relative_to(src_p.resolve())
            raise UnpackError(f"output file cannot be inside the source directory: {out_p}")
        except ValueError:
            pass
        for item in sorted(src_p.iterdir()):
            if item.is_file() and item.suffix.lower() in _DUMP_SUFFIXES:
                source_files.append(item)
        if not source_files:
            raise UnpackError(f"no Switch dump files found in directory: {src_p}")
    elif src_p.is_file():
        source_files.append(src_p)
    else:
        raise UnpackError(f"source path not found: {src_p}")

    if updates:
        for u in updates:
            up = Path(u)
            if not up.is_file():
                raise UnpackError(f"update dump not found: {up}")
            if up not in source_files:
                source_files.append(up)

    if dlcs:
        for d in dlcs:
            dp = Path(d)
            if not dp.is_file():
                raise UnpackError(f"DLC dump not found: {dp}")
            if dp not in source_files:
                source_files.append(dp)

    for sf in source_files:
        if sf.resolve() == out_p.resolve():
            raise UnpackError(f"output file cannot be one of the source files: {out_p}")

    keys_p = Path(keys_path) if keys_path else None
    tkeys_p = Path(title_keys_path) if title_keys_path else None
    base_p = Path(base) if base else None

    keyset = Keyset.load(keys_p, tkeys_p)
    prog = Progress(stage="scan")
    if progress:
        progress(prog)

    def check_cancel() -> None:
        if cancel is not None and cancel():
            raise CancelledError()

    check_cancel()

    open_handles: list[IO[bytes]] = []
    temp_files: list[Path] = []

    try:
        # If merge_siblings is requested and src is a single file, discover related files
        if merge_siblings and src_p.is_file():
            parent_dir = src_p.resolve().parent
            sibling_candidates = [
                p for p in parent_dir.iterdir()
                if p.is_file() and p.suffix.lower() in _DUMP_SUFFIXES and p.resolve() != src_p.resolve()
            ]
            for cand in sibling_candidates:
                if cand not in source_files:
                    source_files.append(cand)

        prog.stage = "meta"
        if progress:
            progress(prog)
        check_cancel()

        works: list[_ConvertWork] = []

        for cur_path in source_files:
            fh = _open_file(cur_path)
            open_handles.append(fh)
            file_size = os.path.getsize(cur_path)

            def read_at(off: int, n: int, f: IO[bytes] = fh, name: str = cur_path.name) -> bytes:
                return read_at_file(f, off, n, name)

            kind = _detect_kind(read_at, cur_path.name)
            if kind == "pfs0":
                entries = _list_pfs0(fh)
            elif kind == "xci":
                entries = _list_xci(fh, file_size)
            else:
                entries = [_Entry(cur_path.name, 0, file_size)]

            if kind == "nca":
                hdr = _peek_header(fh, 0, file_size, keyset, cur_path.name)
                nca_type = hdr[0x205]
                title_id = int.from_bytes(hdr[0x210:0x218], "little")
                keygen = _keygen(hdr)
                rights_raw = hdr[0x230:0x240]
                rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
                entry = entries[0]
                entry_read = _slice_reader(fh, entry)
                is_ncz_content = entry.name.lower().endswith(".ncz") or is_ncz(entry_read, 0, file_size)
                titlekey: bytes | None = None
                if rights_id is not None:
                    titlekey = _resolve_titlekey(
                        fh, entries, keyset, rights_id, keygen,
                        lambda cand: _probe_nca_titlekey(entry_read, file_size, keyset, cand, entry.name),
                    )
                if nca_type in (_NTYPE_PROGRAM, _NTYPE_DATA, _NTYPE_PUBLIC_DATA, _NTYPE_CONTROL):
                    works.append(_ConvertWork(
                        entry, nca_type, titlekey, is_ncz_content,
                        pkg_title_id=title_id, pkg_version=0,
                        fh=fh, src_path=cur_path,
                    ))
            else:
                meta_entries = [e for e in entries if e.name.lower().endswith((".cnmt.nca", ".cnmt.ncz"))]
                if not meta_entries:
                    for e in entries:
                        if not e.name.lower().endswith((".nca", ".ncz")):
                            continue
                        hdr = _peek_header(fh, e.offset, e.size, keyset, e.name)
                        if hdr[0x205] == _NTYPE_META:
                            meta_entries.append(e)

                for meta_entry in meta_entries:
                    cnmt, _meta_tk, _kg = _parse_meta_entry(fh, meta_entry, entries, keyset)
                    for c in cnmt.entries:
                        if c.content_type == ContentType.META:
                            continue
                        if c.content_type in (ContentType.MANUAL, ContentType.LEGAL):
                            continue
                        matched = next(
                            (e for e in entries if e.name.lower().startswith(c.content_id.lower())),
                            None,
                        )
                        if matched is None:
                            continue

                        hdr = _peek_header(fh, matched.offset, matched.size, keyset, matched.name)
                        nca_type = hdr[0x205]
                        if nca_type == _NTYPE_MANUAL:
                            continue

                        keygen = _keygen(hdr)
                        rights_raw = hdr[0x230:0x240]
                        rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
                        entry_read = _slice_reader(fh, matched)
                        is_decomp = matched.name.lower().endswith(".ncz") or is_ncz(entry_read, 0, matched.size)
                        titlekey = None
                        if rights_id is not None:
                            titlekey = _resolve_titlekey(
                                fh, entries, keyset, rights_id, keygen,
                                lambda cand: _probe_nca_titlekey(entry_read, matched.size, keyset, cand, matched.name),
                            )

                        if cnmt.meta_type == MetaType.PROGRAM:
                            works.append(_ConvertWork(
                                matched, nca_type, titlekey, is_decomp,
                                pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                fh=fh, src_path=cur_path,
                            ))
                        elif cnmt.meta_type == MetaType.PATCH:
                            works.append(_ConvertWork(
                                matched, nca_type, titlekey, is_decomp,
                                is_bktr=(nca_type == _NTYPE_PROGRAM),
                                base_id=cnmt.base_id,
                                pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                fh=fh, src_path=cur_path,
                            ))
                        elif cnmt.meta_type == MetaType.ADDON:
                            works.append(_ConvertWork(
                                matched, nca_type, titlekey, is_decomp,
                                pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                fh=fh, src_path=cur_path,
                            ))

        # Sort works: Base Program first, then Control, then Updates (BKTR), then DLCs
        works.sort(key=_work_priority)

        # Collect virtual packages and their virtual file lists
        base_files: list[tuple[str, Callable[[int, int], bytes], int]] = []
        update_files_by_version: dict[int, list[tuple[str, Callable[[int, int], bytes], int]]] = {}
        addon_files_by_tid: dict[int, list[tuple[str, Callable[[int, int], bytes], int]]] = {}

        base_pkg_info: dict[str, int | bytes | None] = {"title_id": 0, "version": 0, "npdm": None, "build_id": None}
        upd_pkg_info_by_version: dict[int, dict[str, int | bytes | None]] = {}
        active_base_romfs_readers: dict[int, SectionReader] = {}

        nacp_title: str | None = None
        nacp_pub: str | None = None
        nacp_ver: str | None = None
        icon_bytes: bytes | None = None

        for work in works:
            check_cancel()
            assert work.fh is not None
            entry_read = _slice_reader(work.fh, work.entry)
            is_ncz_content = work.is_ncz or is_ncz(entry_read, 0, work.entry.size)
            if is_ncz_content:
                temp_path = out_p.parent / f".tmp_{os.getpid()}_{work.entry.name}.nca"
                temp_files.append(temp_path)
                ncz_to_nca(entry_read, 0, temp_path, cancel=cancel)
                decomp_fh = _open_file(temp_path)
                open_handles.append(decomp_fh)
                dec_size = os.path.getsize(temp_path)

                def dec_read(off: int, n: int, f: IO[bytes] = decomp_fh, p: Path = temp_path) -> bytes:
                    return read_at_file(f, off, n, p.name)

                nca = Nca(dec_read, dec_size, keyset, titlekey=work.titlekey, label=temp_path.name)
            else:
                nca = Nca(entry_read, work.entry.size, keyset, titlekey=work.titlekey, label=work.entry.name)

            # ExeFS
            exefs_res = _find_exefs_section(nca)
            if exefs_res is not None:
                sec_exefs, pfiles = exefs_res
                r_exefs = nca.reader(sec_exefs)
                win = SliceReader(r_exefs.read_at, sec_exefs.pfs0_offset, sec_exefs.pfs0_size)
                if work.is_bktr:
                    cur_files = update_files_by_version.setdefault(work.pkg_version, [])
                    info_dict = upd_pkg_info_by_version.setdefault(
                        work.pkg_version, {"title_id": work.pkg_title_id, "version": work.pkg_version, "npdm": None, "build_id": None}
                    )
                else:
                    cur_files = base_files
                    info_dict = base_pkg_info
                    info_dict["title_id"] = work.pkg_title_id
                    info_dict["version"] = work.pkg_version

                for f in pfiles:
                    sub_read = SliceReader(win.read_at, f.offset, f.size).read_at
                    cur_files.append((f"exefs/{f.name}", sub_read, f.size))
                    if f.name == "main.npdm":
                        npdm_bytes = win.read_at(f.offset, f.size)
                        info_dict["npdm"] = npdm_bytes
                    elif f.name == "main" and f.size >= 0x60:
                        head = win.read_at(f.offset, 0x60)
                        if head[:4] == b"NSO0" or head[0x10:0x14] == b"NRO0":
                            info_dict["build_id"] = head[0x40:0x60]

            # RomFS
            sec_romfs = nca.romfs_section()
            if sec_romfs is not None and work.nca_type != _NTYPE_CONTROL:
                if sec_romfs.is_bktr:
                    # Update BKTR RomFS: must resolve base before parsing BKTR tables
                    base_reader_fn: SectionReader | None = active_base_romfs_readers.get(work.base_id)
                    if base_reader_fn is None:
                        # Fallback: resolve base from external file
                        assert work.src_path is not None
                        base_path = _resolve_base(work.src_path, base_p, work.base_id, keyset)
                        if base_path is not None:
                            sink_dummy = _ProgressSink(None, cancel)
                            base_handle = _get_base_romfs_reader(base_path, keyset, out_p.parent, sink_dummy)
                            open_handles.extend(base_handle.fhs)
                            if base_handle.temp_path:
                                temp_files.append(base_handle.temp_path)
                            base_reader_fn = base_handle.reader
                        else:
                            raise UnpackError(
                                f"update requires base game (title ID 0x{work.base_id:016X}) "
                                f"to merge BKTR RomFS, but base game was not found (use --base)"
                            )

                    cur_files = update_files_by_version.setdefault(work.pkg_version, [])
                    update_reader = nca.reader(sec_romfs)
                    tables = load_bktr(update_reader)
                    bktr_reader = BktrReader(update_reader, base_reader_fn, tables)
                    romfs = RomFs(bktr_reader.read_at, sec_romfs.ivfc_level5_offset)
                    for rf in romfs.files():
                        sub_read = SliceReader(bktr_reader.read_at, rf.offset, rf.size).read_at
                        cur_files.append((f"romfs/{rf.path}", sub_read, rf.size))
                elif work.nca_type in (_NTYPE_DATA, _NTYPE_PUBLIC_DATA) and (not base_files or work.pkg_title_id != base_pkg_info.get("title_id")):
                    # Addon (DLC)
                    r_romfs = nca.reader(sec_romfs)
                    romfs = RomFs(r_romfs.read_at, sec_romfs.ivfc_level5_offset)
                    target_list = addon_files_by_tid.setdefault(work.pkg_title_id, [])
                    for rf in romfs.files():
                        sub_read = SliceReader(r_romfs.read_at, rf.offset, rf.size).read_at
                        target_list.append((f"romfs/{rf.path}", sub_read, rf.size))
                else:
                    # Base RomFS
                    r_romfs = nca.reader(sec_romfs)
                    active_base_romfs_readers[work.pkg_title_id] = r_romfs
                    romfs = RomFs(r_romfs.read_at, sec_romfs.ivfc_level5_offset)
                    for rf in romfs.files():
                        sub_read = SliceReader(r_romfs.read_at, rf.offset, rf.size).read_at
                        base_files.append((f"romfs/{rf.path}", sub_read, rf.size))

            # Control NCA
            if work.nca_type == _NTYPE_CONTROL and not no_control:
                sec_ctrl = nca.romfs_section()
                if sec_ctrl is not None:
                    r_ctrl = nca.reader(sec_ctrl)
                    romfs = RomFs(r_ctrl.read_at, sec_ctrl.ivfc_level5_offset)
                    for rf in romfs.files():
                        if rf.path.endswith("control.nacp") or rf.path == "control.nacp":
                            try:
                                raw_nacp = r_ctrl.read_at(rf.offset, rf.size)
                                nacp_obj = parse_nacp(raw_nacp)
                                nacp_title = nacp_obj.title_name
                                nacp_pub = nacp_obj.publisher
                                nacp_ver = nacp_obj.display_version
                            except Exception:
                                pass
                        elif "icon_" in rf.path and icon_bytes is None:
                            try:
                                icon_bytes = r_ctrl.read_at(rf.offset, rf.size)
                            except Exception:
                                pass

        # Assemble packages and roots
        packages: list[PackInput] = []
        roots: list[DirObj] = []

        # 1. Base package
        if base_files:
            b_root = build_virtual_tree(base_files)
            roots.append(b_root)
            b_tid = int(base_pkg_info["title_id"] or 0)
            b_ver = int(base_pkg_info["version"] or 0)
            b_npdm = base_pkg_info["npdm"] if isinstance(base_pkg_info["npdm"], bytes) else None
            b_bid = base_pkg_info["build_id"] if isinstance(base_pkg_info["build_id"], bytes) else None
            packages.append(PackInput(
                kind=F.KIND_BASE,
                src=src_p.name,
                title_id=b_tid,
                version=b_ver,
                npdm=b_npdm,
                build_id=b_bid,
            ))

        # 2. Update package(s)
        for u_ver in sorted(update_files_by_version.keys()):
            u_files = update_files_by_version[u_ver]
            u_root = build_virtual_tree(u_files)
            roots.append(u_root)
            u_info = upd_pkg_info_by_version.get(u_ver, {})
            u_tid = int(u_info.get("title_id") or 0)
            raw_npdm = u_info.get("npdm")
            u_npdm: bytes | None = raw_npdm if isinstance(raw_npdm, bytes) else None
            raw_bid = u_info.get("build_id")
            u_bid: bytes | None = raw_bid if isinstance(raw_bid, bytes) else None
            packages.append(PackInput(
                kind=F.KIND_UPDATE,
                src=src_p.name,
                title_id=u_tid,
                version=u_ver,
                flags=F.PKG_FLAG_STANDALONE_UPDATE if not base_files else 0,
                npdm=u_npdm,
                build_id=u_bid,
            ))

        # 3. Addon (DLC) package(s)
        for a_tid in sorted(addon_files_by_tid.keys()):
            a_files = addon_files_by_tid[a_tid]
            a_root = build_virtual_tree(a_files)
            roots.append(a_root)
            packages.append(PackInput(
                kind=F.KIND_ADDON,
                src=src_p.name,
                title_id=a_tid,
                version=0,
            ))

        if not packages:
            raise UnpackError("no playable package contents found in dump")

        tree = Tree(artifacts=set())
        tree.assign(roots)

        # Build app metadata
        final_name = name or nacp_title
        final_pub = publisher or nacp_pub
        final_ver = display_version or nacp_ver

        meta_names: dict[str | None, str] | None = {None: final_name} if final_name else None
        meta_icons: dict[str | None, str] | None = None
        if icon_bytes is not None and not no_control:
            tmp_icon = out_p.parent / f".tmp_{os.getpid()}_icon.dat"
            temp_files.append(tmp_icon)
            tmp_icon.write_bytes(icon_bytes)
            meta_icons = {None: str(tmp_icon)}

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

        pack_virtual(
            str(out_p),
            packages,
            roots,
            tree,
            dump_label=src_p.name,
            level=level,
            replace=replace,
            display_version=final_ver,
            publisher=final_pub,
            names=meta_names,
            icons=meta_icons,
            progress=on_pack_progress,
            threads=threads,
        )

        if not fast:
            prog.stage = "verify"
            if progress:
                progress(prog)
            check_cancel()
            ok, problems = verify(str(out_p), deep=True)
            if not ok or problems:
                raise UnpackError(f"verification failed: {problems}")

        prog.stage = "done"
        prog.current = ""
        prog.done = prog.total
        prog.bytes_done = prog.bytes_total
        if progress:
            progress(prog)

        return packages

    finally:
        for h in open_handles:
            try:
                h.close()
            except OSError:
                pass
        for t in temp_files:
            if t.is_file():
                try:
                    t.unlink()
                except OSError:
                    pass
