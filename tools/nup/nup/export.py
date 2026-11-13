"""NUP container exporter: export .nup to Atmosphere SD format, dump layout, or installable NSP.

Enables bidirectional workflows:
- "atmosphere" (default): Ready-to-use Atmosphere SD card structure
  (<out_dir>/atmosphere/contents/<title_id>/{romfs,exefs}).
- "dump": Clean multi-package dump layout compatible with nup auto / pack.
- "nsp": Standard repacked Nintendo Submission Package (.nsp) for real Switch CFW / emulators.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path
import shutil
import struct
import time
from typing import Callable, Final, IO

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import format as F
from .access import app_meta, iter_children, localized_icons, localized_titles
from .read import NupReader, PackageInfo
from .switchfs.errors import CancelledError, UnpackError
from .switchfs.keys import Keyset
from .switchfs.unpack import Progress

ProgressFn = Callable[[Progress], None]
CancelFn = Callable[[], bool]

_BAD_FILENAME_CHARS: Final = r'<>:"/\|?*'


def _sanitize_filename(name: str) -> str:
    cleaned = "".join(c if c not in _BAD_FILENAME_CHARS else "_" for c in name).strip()
    return cleaned or "game"


def _safe_export_path(base_dir: Path, rel: str) -> Path:
    """Resolve `rel` relative to `base_dir`, strictly guarding against traversal."""
    if not rel or rel.startswith(("/", "\\")) or ":" in rel:
        raise F.NupError(f"export: unsafe file path in container: {rel!r}")
    normalized = rel.replace("\\", "/")
    parts = normalized.split("/")
    if any(p in ("..", ".", "") or ":" in p for p in parts):
        raise F.NupError(f"export: unsafe file path in container: {rel!r}")
    target = base_dir.joinpath(*parts)
    try:
        target.resolve().relative_to(base_dir.resolve())
    except (ValueError, RuntimeError):
        raise F.NupError(f"export: path escapes destination directory: {rel!r}")
    return target


@dataclass(slots=True)
class ExportResult:
    container_path: Path
    output_path: Path
    format: str
    package_title_id: int
    files_exported: int
    bytes_exported: int


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


def _resolve_target_package(
    packages: list[PackageInfo],
    spec: str | int | None,
) -> PackageInfo:
    """Resolve which package to export."""
    if spec is not None:
        if isinstance(spec, int):
            for p in packages:
                if p.title_id == spec:
                    return p
            raise F.NupError(f"export: title ID 0x{spec:016X} not found in container")
        spec_s = str(spec).strip()
        if spec_s.isdigit() and len(spec_s) < 6:
            idx = int(spec_s)
            if 0 <= idx < len(packages):
                return packages[idx]
            raise F.NupError(f"export: package index {idx} out of range ({len(packages)} packages)")
        if len(spec_s) == 16:
            try:
                tid = int(spec_s, 16)
                for p in packages:
                    if p.title_id == tid:
                        return p
                raise F.NupError(f"export: title ID {spec_s} not found in container")
            except ValueError:
                pass
        for kind_val, kind_name in F.KIND_NAMES.items():
            if spec_s.lower() == kind_name:
                found = next((p for p in packages if p.kind == kind_val), None)
                if found is not None:
                    return found
                raise F.NupError(f"export: no {kind_name} package found in container")
        raise F.NupError(f"export: unrecognized package selector {spec!r}")

    base_pkg = next((p for p in packages if p.kind == F.KIND_BASE), None)
    if base_pkg is not None:
        return base_pkg
    return packages[0]


def _build_pfs0(files: list[tuple[str, bytes]]) -> bytes:
    """Build a standard Nintendo PFS0 filesystem blob."""
    count = len(files)
    str_table = bytearray()
    offsets = []
    for name, data in files:
        offsets.append(len(str_table))
        str_table.extend(name.encode("utf-8") + b"\0")
    hdr = bytearray(0x10 + count * 0x18 + len(str_table))
    hdr[0:4] = b"PFS0"
    struct.pack_into("<III", hdr, 4, count, len(str_table), 0)
    data_blobs = bytearray()
    for i, ((name, data), str_off) in enumerate(zip(files, offsets)):
        pos = 0x10 + i * 0x18
        data_off = len(data_blobs)
        data_size = len(data)
        struct.pack_into("<QQII", hdr, pos, data_off, data_size, str_off, 0)
        data_blobs.extend(data)
    hdr[0x10 + count * 0x18 : 0x10 + count * 0x18 + len(str_table)] = str_table
    return bytes(hdr + data_blobs)


def _build_romfs(files: list[tuple[str, bytes]]) -> bytes:
    """Build a standard Nintendo RomFS (IVFC level 5) filesystem blob."""
    first_file = 0 if files else 0xFFFFFFFF
    dirs = struct.pack("<IIIIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, first_file, 0, 0)
    file_meta = bytearray()
    data_blob = bytearray()
    for i, (name, content) in enumerate(files):
        foff = len(data_blob)
        fsize = len(content)
        data_blob.extend(content)
        pad = (16 - (len(data_blob) % 16)) % 16
        data_blob.extend(b"\0" * pad)
        name_bytes = name.encode("utf-8")
        next_file = 0xFFFFFFFF if i == len(files) - 1 else len(file_meta) + ((32 + len(name_bytes) + 3) & ~3)
        entry = bytearray(struct.pack("<IIQQII", 0, next_file, foff, fsize, 0, len(name_bytes)))
        entry.extend(name_bytes)
        while len(entry) % 4 != 0:
            entry.append(0)
        file_meta.extend(entry)
    header_size = 0x50
    dir_meta_off = header_size
    dir_meta_size = len(dirs)
    file_meta_off = (dir_meta_off + dir_meta_size + 15) & ~15
    file_meta_size = len(file_meta)
    data_off = (file_meta_off + file_meta_size + 15) & ~15
    hdr = bytearray(0x50)
    struct.pack_into(
        "<QQQQQQQQQQ", hdr, 0, header_size, 0, 0, dir_meta_off, dir_meta_size, 0, 0, file_meta_off, file_meta_size, data_off
    )
    total = bytearray(hdr)
    total.extend(dirs)
    while len(total) < file_meta_off:
        total.append(0)
    total.extend(file_meta)
    while len(total) < data_off:
        total.append(0)
    total.extend(data_blob)
    return bytes(total)


def _xts_encrypt(key32: bytes, data: bytes, sector: int = 0) -> bytes:
    """Encrypt data in 0x200 sectors using AES-XTS."""
    out = bytearray()
    for i in range(0, len(data), 0x200):
        tweak = (sector + i // 0x200).to_bytes(16, "big")
        enc = Cipher(algorithms.AES(key32), modes.XTS(tweak)).encryptor()
        out += enc.update(data[i : i + 0x200]) + enc.finalize()
    return bytes(out)


def _build_nca(
    content_type: int,
    title_id: int,
    keyset: Keyset | None,
    sec0_part: int,
    sec0_fs: int,
    sec0_data: bytes,
    sec1_part: int | None = None,
    sec1_fs: int | None = None,
    sec1_data: bytes = b"",
) -> bytes:
    """Build a standard Nintendo NCA3 container."""
    hdr = bytearray(0xC00)
    hdr[0x200:0x204] = b"NCA3"
    hdr[0x205] = content_type
    struct.pack_into("<Q", hdr, 0x210, title_id)

    if keyset is not None:
        try:
            kak = keyset.key_area_key(0, 0)
            raw_area = b"A" * 0x40
            enc_area = Cipher(algorithms.AES(kak), modes.ECB()).encryptor().update(raw_area)
            hdr[0x300:0x340] = enc_area
        except Exception:
            pass

    s0_start = 6
    s0_cnt = (len(sec0_data) + 0x1FF) // 0x200
    struct.pack_into("<II", hdr, 0x240, s0_start, s0_start + s0_cnt)
    hdr[0x402] = sec0_part
    hdr[0x403] = sec0_fs
    hdr[0x404] = 1
    if sec0_part == 1 and sec0_fs == 2:
        struct.pack_into("<QQ", hdr, 0x408 + 0x38, 0, len(sec0_data))
    elif sec0_part == 0 and sec0_fs == 3:
        struct.pack_into("<Q", hdr, 0x408 + 0x88, 0)
    body = bytearray(sec0_data)
    while len(body) % 0x200 != 0:
        body.append(0)
    if sec1_part is not None and sec1_fs is not None:
        s1_start = s0_start + s0_cnt
        s1_cnt = (len(sec1_data) + 0x1FF) // 0x200
        struct.pack_into("<II", hdr, 0x250, s1_start, s1_start + s1_cnt)
        hdr[0x602] = sec1_part
        hdr[0x603] = sec1_fs
        hdr[0x604] = 1
        if sec1_part == 1 and sec1_fs == 2:
            struct.pack_into("<QQ", hdr, 0x608 + 0x38, 0, len(sec1_data))
        elif sec1_part == 0 and sec1_fs == 3:
            struct.pack_into("<Q", hdr, 0x608 + 0x88, 0)
        b1 = bytearray(sec1_data)
        while len(b1) % 0x200 != 0:
            b1.append(0)
        body.extend(b1)

    header_key = getattr(keyset, "header_key", None) if keyset is not None else None
    if header_key is not None and len(header_key) == 32:
        enc_hdr = _xts_encrypt(header_key, bytes(hdr))
    else:
        enc_hdr = bytes(hdr)
    return enc_hdr + bytes(body)


def export_container(
    container_path: Path | str,
    out_dir: Path | str,
    *,
    fmt: str = "atmosphere",
    package: str | int | None = None,
    keys_path: Path | str | None = None,
    title_keys_path: Path | str | None = None,
    replace: bool = False,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> ExportResult:
    """Export a .nup container into Atmosphere SD format, dump directory, or .nsp package."""
    container_p = Path(container_path)
    out_p = Path(out_dir)

    if not container_p.is_file():
        raise F.NupError(f"container file not found: {container_p}")

    def check_cancel() -> None:
        if cancel is not None and cancel():
            raise CancelledError()

    check_cancel()

    prog = Progress(stage="scan")
    if progress:
        progress(prog)

    r = NupReader(str(container_p))
    try:
        target_pkg = _resolve_target_package(r.packages, package)
        norm_fmt = fmt.strip().lower()

        # ---------------------------------------------------------
        # Format 1: Atmosphere SD Card Layout
        # ---------------------------------------------------------
        if norm_fmt in ("atmosphere", "layeredfs"):
            tid_hex = f"{target_pkg.title_id:016X}"
            dest_base = out_p / "atmosphere" / "contents" / tid_hex
            os.makedirs(dest_base, exist_ok=True)

            files = _collect_package_files(r, target_pkg.root_dir)
            prog.stage = "export"
            prog.total = len(files)
            prog.done = 0
            prog.bytes_total = sum(r.files[fi][1] for _, fi in files)
            prog.bytes_done = 0
            if progress:
                progress(prog)

            exported_bytes = 0
            for i, (rel, fi) in enumerate(files):
                check_cancel()
                dest_file = _safe_export_path(dest_base, rel)
                if dest_file.exists() and not replace:
                    raise F.NupError(f"export: refusing to overwrite existing path: {dest_file}")
                os.makedirs(dest_file.parent, exist_ok=True)
                with open(dest_file, "wb") as out_fh:
                    r.extract_file_to(fi, out_fh)

                file_size = r.files[fi][1]
                exported_bytes += file_size
                prog.done = i + 1
                prog.bytes_done = exported_bytes
                prog.current = rel
                if progress:
                    progress(prog)

            prog.stage = "done"
            if progress:
                progress(prog)

            return ExportResult(
                container_path=container_p,
                output_path=dest_base,
                format="atmosphere",
                package_title_id=target_pkg.title_id,
                files_exported=len(files),
                bytes_exported=exported_bytes,
            )

        # ---------------------------------------------------------
        # Format 2: Standard Multi-Package Dump Layout
        # ---------------------------------------------------------
        elif norm_fmt == "dump":
            os.makedirs(out_p, exist_ok=True)

            all_package_files: list[tuple[PackageInfo, list[tuple[str, int]]]] = []
            total_file_count = 0
            total_bytes = 0

            for p in r.packages:
                p_files = _collect_package_files(r, p.root_dir)
                all_package_files.append((p, p_files))
                total_file_count += len(p_files)
                total_bytes += sum(r.files[fi][1] for _, fi in p_files)

            prog.stage = "export"
            prog.total = total_file_count
            prog.done = 0
            prog.bytes_total = total_bytes
            prog.bytes_done = 0
            if progress:
                progress(prog)

            exported_bytes = 0
            files_written = 0

            for p, p_files in all_package_files:
                if p.kind == F.KIND_BASE:
                    pkg_dest = out_p / "base"
                elif p.kind == F.KIND_UPDATE:
                    pkg_dest = out_p / "updates" / str(p.version)
                elif p.kind == F.KIND_ADDON:
                    pkg_dest = out_p / "dlc" / f"{p.title_id:016X}" / "0"
                else:
                    pkg_dest = out_p / f"pkg_{p.index}"

                for rel, fi in p_files:
                    check_cancel()
                    dest_file = _safe_export_path(pkg_dest, rel)
                    if dest_file.exists() and not replace:
                        raise F.NupError(f"export: refusing to overwrite existing path: {dest_file}")
                    os.makedirs(dest_file.parent, exist_ok=True)
                    with open(dest_file, "wb") as out_fh:
                        r.extract_file_to(fi, out_fh)

                    file_size = r.files[fi][1]
                    files_written += 1
                    exported_bytes += file_size
                    prog.done = files_written
                    prog.bytes_done = exported_bytes
                    prog.current = rel
                    if progress:
                        progress(prog)

            # Extract _meta info.txt and control files
            base_p = next((p for p in r.packages if p.kind == F.KIND_BASE), target_pkg)
            meta_dict = app_meta(r, base_p)
            nacp_title = meta_dict.get(F.TLV_TITLE_NAME, b"").decode("utf-8", "replace")
            nacp_pub = meta_dict.get(F.TLV_PUBLISHER, b"").decode("utf-8", "replace")
            nacp_ver = meta_dict.get(F.TLV_DISPLAY_VERSION, b"").decode("utf-8", "replace")

            meta_dir = out_p / "_meta"
            os.makedirs(meta_dir, exist_ok=True)
            info_file = meta_dir / "info.txt"
            if info_file.exists() and not replace:
                raise F.NupError(f"export: refusing to overwrite existing path: {info_file}")
            info_txt = (
                f"title_id: {base_p.title_id:016x}\n"
                f"version: {base_p.version}\n"
                f"name: {nacp_title}\n"
                f"publisher: {nacp_pub}\n"
                f"display_version: {nacp_ver}\n"
                f"source_container: {container_p.name}\n"
            )
            info_file.write_text(info_txt, encoding="utf-8")

            prog.stage = "done"
            if progress:
                progress(prog)

            return ExportResult(
                container_path=container_p,
                output_path=out_p,
                format="dump",
                package_title_id=target_pkg.title_id,
                files_exported=files_written,
                bytes_exported=exported_bytes,
            )

        # ---------------------------------------------------------
        # Format 3: Installable NSP Package (.nsp)
        # ---------------------------------------------------------
        elif norm_fmt == "nsp":
            # Load keys for NCA header encryption if available
            keys_p = Path(keys_path) if keys_path else None
            tkeys_p = Path(title_keys_path) if title_keys_path else None
            keyset = Keyset.load(keys_p, tkeys_p)
            hdr_key: bytes | None = getattr(keyset, "header_key", None)

            # Determine destination NSP file
            meta_dict = app_meta(r, target_pkg)
            nacp_title = meta_dict.get(F.TLV_TITLE_NAME, b"").decode("utf-8", "replace") or container_p.stem
            sanitized = _sanitize_filename(nacp_title)
            default_name = f"{sanitized} [{target_pkg.title_id:016X}].nsp"

            if out_p.suffix.lower() == ".nsp":
                final_nsp_path = out_p
            else:
                final_nsp_path = out_p / default_name

            if final_nsp_path.exists() and not replace:
                raise F.NupError(f"output NSP file already exists: {final_nsp_path}")

            os.makedirs(final_nsp_path.parent, exist_ok=True)
            part_nsp_path = final_nsp_path.parent / f"{final_nsp_path.name}.partial"

            prog.stage = "export"
            prog.current = "Building ExeFS & RomFS partitions"
            if progress:
                progress(prog)

            # 1. Gather ExeFS & RomFS files
            pkg_files = _collect_package_files(r, target_pkg.root_dir)
            exefs_files: list[tuple[str, bytes]] = []
            romfs_files: list[tuple[str, bytes]] = []

            for rel, fi in pkg_files:
                check_cancel()
                if rel.startswith("exefs/"):
                    exefs_files.append((rel[6:], r.read_file(fi)))
                elif rel.startswith("romfs/"):
                    romfs_files.append((rel[6:], r.read_file(fi)))

            exefs_blob = _build_pfs0(exefs_files) if exefs_files else b""
            romfs_blob = _build_romfs(romfs_files) if romfs_files else b""

            prog.current = "Building Program NCA"
            if progress:
                progress(prog)

            # 2. Program NCA
            if exefs_blob and romfs_blob:
                prog_nca = _build_nca(0, target_pkg.title_id, keyset, 1, 2, exefs_blob, 0, 3, romfs_blob)
            elif exefs_blob:
                prog_nca = _build_nca(0, target_pkg.title_id, keyset, 1, 2, exefs_blob)
            else:
                prog_nca = _build_nca(0, target_pkg.title_id, keyset, 0, 3, romfs_blob)

            prog_cid = hashlib.sha256(prog_nca[:0x400]).digest()[:16].hex()

            # 3. Control NCA (NACP + Icons)
            prog.current = "Building Control NCA"
            if progress:
                progress(prog)

            nacp_data = bytearray(0x4000)
            title_b = nacp_title.encode("utf-8")[:0x1FF]
            nacp_data[0 : len(title_b)] = title_b
            pub_b = meta_dict.get(F.TLV_PUBLISHER, b"")[:0x1FF]
            nacp_data[0x200 : 0x200 + len(pub_b)] = pub_b
            ver_b = meta_dict.get(F.TLV_DISPLAY_VERSION, b"")[:0xF]
            nacp_data[0x3060 : 0x3060 + len(ver_b)] = ver_b

            ctrl_files: list[tuple[str, bytes]] = [("control.nacp", bytes(nacp_data))]
            ctrl_romfs = _build_romfs(ctrl_files)
            ctrl_nca = _build_nca(3, target_pkg.title_id, keyset, 0, 3, ctrl_romfs)
            ctrl_cid = hashlib.sha256(ctrl_nca[:0x400]).digest()[:16].hex()

            # 4. Meta CNMT NCA
            prog.current = "Building CNMT Meta NCA"
            if progress:
                progress(prog)

            cnmt_data = bytearray(0x20 + 0x38 * 2)
            struct.pack_into("<QIBBH", cnmt_data, 0, target_pkg.title_id, target_pkg.version, 0x80, 0, 0)
            struct.pack_into("<H", cnmt_data, 0x10, 2)
            # Program entry
            cnmt_data[0x20 + 0x20 : 0x20 + 0x30] = bytes.fromhex(prog_cid)
            struct.pack_into("<I", cnmt_data, 0x20 + 0x30, len(prog_nca))
            cnmt_data[0x20 + 0x36] = 1  # Program
            # Control entry
            cnmt_data[0x20 + 0x38 + 0x20 : 0x20 + 0x38 + 0x30] = bytes.fromhex(ctrl_cid)
            struct.pack_into("<I", cnmt_data, 0x20 + 0x38 + 0x30, len(ctrl_nca))
            cnmt_data[0x20 + 0x38 + 0x36] = 3  # Control

            meta_pfs0 = _build_pfs0([("game.cnmt", bytes(cnmt_data))])
            meta_nca = _build_nca(1, target_pkg.title_id, keyset, 1, 2, meta_pfs0)

            # 5. Assemble final NSP (PFS0)
            prog.current = "Packaging final NSP"
            if progress:
                progress(prog)

            nsp_files = [
                (f"{prog_cid}.nca", prog_nca),
                (f"{ctrl_cid}.nca", ctrl_nca),
                ("game.cnmt.nca", meta_nca),
            ]
            nsp_blob = _build_pfs0(nsp_files)

            try:
                part_nsp_path.write_bytes(nsp_blob)
                os.replace(part_nsp_path, final_nsp_path)
            finally:
                part_nsp_path.unlink(missing_ok=True)

            prog.stage = "done"
            if progress:
                progress(prog)

            return ExportResult(
                container_path=container_p,
                output_path=final_nsp_path,
                format="nsp",
                package_title_id=target_pkg.title_id,
                files_exported=len(pkg_files),
                bytes_exported=len(nsp_blob),
            )

        else:
            raise F.NupError(f"export: unknown format {fmt!r} (expected atmosphere, dump, or nsp)")

    finally:
        try:
            r.close()
        except Exception:
            pass
