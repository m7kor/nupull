"""Unpack driver: NSP/NSZ/XCI/XCZ/NCA -> base/updates/dlc dump layout.

Produces exactly what ``nup pack`` consumes (SPEC §3.1.3): ``base/`` and
``updates/<decimal version>/`` content dirs with ``exefs/`` + ``romfs/``,
``dlc/<16-hex title id>/<index>/`` for addons, and ``_meta/`` holding the
control NCA's ``control/`` files, ``control.nacp`` and an ``info.txt``.
Update program NCAs carry a BKTR (patch) RomFS: the merged virtual view
is extracted when the matching base content can be resolved.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
from dataclasses import dataclass, field
from typing import Callable, Final, IO

from . import crypto
from .bktr import BktrReader, load_bktr
from .cnmt import Cnmt, ContentType, MetaType, parse_cnmt
from .errors import CancelledError, UnpackError
from .hfs0 import Hfs0Entry, parse_hfs0
from .keys import Keyset
from .nacp import Nacp, parse_nacp
from .nca import CRYPT_BKTR, CRYPT_NONE, Nca, Section, SectionReader
from .ncz import is_ncz, ncz_to_nca
from .pfs0 import Pfs0Entry, parse_pfs0
from .reader import ReadAt, SliceReader, copy_stream, read_exact
from .romfs import RomFs
from .tik import parse_ticket
from .xci import Xci

# NCA header content types (hactool enum nca.h) - NOT the CNMT enum.
_NTYPE_PROGRAM: Final = 0
_NTYPE_META: Final = 1
_NTYPE_CONTROL: Final = 2
_NTYPE_MANUAL: Final = 3
_NTYPE_DATA: Final = 4
_NTYPE_PUBLIC_DATA: Final = 5

_PFS0: Final = b"PFS0"
_NCZ_SECTIONS: Final = b"NCZSECTN"
_CHUNK: Final = 0x100000
_DUMP_SUFFIXES: Final = (".nsp", ".nsz", ".xci", ".xcz", ".nca", ".ncz")

ProgressFn = Callable[["Progress"], None]
CancelFn = Callable[[], bool]


@dataclass(slots=True)
class Progress:
    """Snapshot handed to the progress callback after every update."""

    stage: str = "scan"        # scan | meta | extract | control | done
    current: str = ""          # file currently being written
    done: int = 0              # contents handled
    total: int = 0             # contents to handle
    bytes_done: int = 0
    bytes_total: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def warning(self) -> str:
        return self.warnings[-1] if self.warnings else ""


@dataclass(slots=True)
class _Entry:
    """One file inside the input container."""

    name: str
    offset: int   # absolute in the source file
    size: int


@dataclass(slots=True)
class _Work:
    """A content NCA selected for extraction."""

    entry: _Entry
    nca_type: int        # NCA header content type
    titlekey: bytes | None
    is_ncz: bool
    temp_path: Path | None = None
    dest_exefs: Path | None = None
    dest_romfs: Path | None = None
    dest_meta: Path | None = None
    is_bktr: bool = False
    base_id: int = 0
    pkg_title_id: int = 0
    pkg_version: int = 0


class _ProgressSink:
    """Owns the Progress instance; enforces cooperative cancellation."""

    __slots__ = ("p", "_cb", "_cancel")

    def __init__(self, cb: ProgressFn | None, cancel: CancelFn | None) -> None:
        self.p = Progress()
        self._cb = cb
        self._cancel = cancel

    def check(self) -> None:
        if self._cancel is not None and self._cancel():
            raise CancelledError()

    def emit(self) -> None:
        if self._cb is not None:
            self._cb(self.p)

    def stage(self, name: str) -> None:
        self.check()
        self.p.stage = name
        self.emit()

    def warn(self, msg: str) -> None:
        self.p.warnings.append(msg)
        self.emit()


# -- container detection ------------------------------------------------
def _detect_kind(read_at: ReadAt, name: str) -> str:
    """Classify the input: 'pfs0' (NSP/NSZ), 'xci' (XCI/XCZ) or 'nca'."""
    try:
        head = read_at(0, 4)
        if head == _PFS0:
            return "pfs0"
    except UnpackError:
        pass

    # XCI card header: HEAD magic at 0x100 or 0x1100 (two known layouts).
    try:
        probe = read_at(0x100, 4)
        if probe == b"HEAD":
            return "xci"
    except UnpackError:
        pass

    try:
        probe = read_at(0x1100, 4)
        if probe == b"HEAD":
            return "xci"
    except UnpackError:
        pass

    # Bare NCA/NCZ: NCA3 magic sits at +0x200 of the (XTS-encrypted)
    # header; NCZ stores the header raw, so try both.
    if name.lower().endswith((".nca", ".ncz")):
        return "nca"
    raise UnpackError(
        "unrecognized container (expected NSP/NSZ/XCI/XCZ/NCA magic)"
    )


def _open_file(path: Path) -> IO[bytes]:
    try:
        return open(path, "rb")
    except OSError as exc:
        raise UnpackError(f"cannot open {path}: {exc}") from exc


def _list_pfs0(fh: IO[bytes]) -> list[_Entry]:
    fh.seek(0)
    hdr = fh.read(0x10)
    if hdr[:4] != _PFS0:
        raise UnpackError(f"bad PFS0 magic {hdr[:4]!r}")
    count = int.from_bytes(hdr[4:8], "little")
    str_size = int.from_bytes(hdr[8:12], "little")
    if count > 0x10000:
        raise UnpackError(f"implausible NSP file count {count}")
    ent_blob = fh.read(count * 0x18)
    names = fh.read(str_size)
    data_base = 0x10 + count * 0x18 + str_size
    out: list[_Entry] = []
    for i in range(count):
        pos = i * 0x18
        off = int.from_bytes(ent_blob[pos:pos + 8], "little")
        size = int.from_bytes(ent_blob[pos + 8:pos + 16], "little")
        so = int.from_bytes(ent_blob[pos + 16:pos + 20], "little")
        if so >= str_size:
            raise UnpackError(f"NSP entry {i} name offset out of range")
        end = names.find(b"\0", so)
        if end < 0:
            end = str_size
        out.append(_Entry(names[so:end].decode("utf-8", "replace"),
                          data_base + off, size))
    return out


def _list_xci(fh: IO[bytes], size: int) -> list[_Entry]:
    fh.seek(0)

    def read_at(off: int, n: int) -> bytes:
        fh.seek(off)
        return fh.read(n)

    xci = Xci(Path("input"), read_at, size)
    entries: list[_Entry] = []
    for part in xci.partitions:
        # Only the secure partition holds NCAs; update/normal do not.
        if part.name not in ("secure", "update"):
            continue
        part_off = part.offset

        def read_part(o: int, n: int) -> bytes:
            return read_at(part_off + o, n)

        raw = parse_hfs0(read_part)
        for e in raw:
            entries.append(_Entry(e.name, part.offset + e.offset, e.size))
    if not entries:
        raise UnpackError("XCI has no NCA entries in secure/update partition")
    return entries


# -- keys / meta --------------------------------------------------------
def _peek_header(fh: IO[bytes], off: int, size: int, keyset: Keyset,
                 label: str) -> bytes:
    """XTS-decrypt the first 0xC00 bytes of an NCA at `off` (raw for NCZ)."""
    fh.seek(off)
    blob = fh.read(min(0xC00, size))
    if len(blob) < 0x400:
        raise UnpackError(f"{label}: NCA header truncated")
    if blob[0x200:0x204] in (b"NCA3", b"NCA2"):
        return blob  # NCZ stores the header raw
    return crypto.xts_decrypt(keyset.header_key, blob, 0)


def _titlekey_from_tik(fh: IO[bytes], entries: list[_Entry],
                       keyset: Keyset, rights_id: str,
                       keygen: int) -> bytes | None:
    """Decrypt the NSP's .tik with titlekek_<keygen>; None when absent."""
    for tik in entries:
        if not tik.name.lower().endswith(".tik"):
            continue
        blob = read_at_file(fh, tik.offset, tik.size, "ticket")
        ticket = parse_ticket(blob)
        if ticket.rights_id.lower() == rights_id.lower():
            try:
                kek = keyset.titlekek(keygen)
                return crypto.ecb_decrypt(kek, ticket.enc_titlekey)
            except UnpackError:
                pass
    return None


def read_at_file(fh: IO[bytes], off: int, size: int, what: str) -> bytes:
    fh.seek(off)
    blob = fh.read(size)
    if len(blob) != size:
        raise UnpackError(f"truncated {what} at offset 0x{off:x}")
    return blob


def _resolve_titlekey(fh: IO[bytes], entries: list[_Entry], keyset: Keyset,
                      rights_id: str | None, keygen: int,
                      probe: Callable[[bytes | None], bool]) -> bytes | None:
    """Title key for rights_id: NSP .tik first, title.keys fallback.

    `probe(candidate)` must validate the candidate against real section
    data (PFS0/IVFC magic); when nothing validates we hand back the
    hactool-convention value so the caller can fail on actual reads.
    """
    if rights_id is None:
        return None
    stored = keyset.titlekeys.get(rights_id)
    candidates: list[bytes] = []
    tik_key = _titlekey_from_tik(fh, entries, keyset, rights_id, keygen)
    if tik_key is not None:
        candidates.append(tik_key)
    if stored is not None:
        candidates.append(stored)
        try:
            dec = crypto.ecb_decrypt(keyset.titlekek(keygen), stored)
            if dec != stored:
                candidates.append(dec)
        except UnpackError:
            pass
    for cand in candidates:
        if probe(cand):
            return cand
    if tik_key is not None:
        return tik_key
    if stored is not None:
        return stored
    raise UnpackError(
        f"no titlekey for rights id {rights_id} "
        "(add a .tik-carrying NSP, or the entry in title.keys)")


def _parse_meta_entry(fh: IO[bytes], meta: _Entry, entries: list[_Entry],
                      keyset: Keyset) -> tuple[Cnmt, bytes | None, int]:
    is_ncz = meta.name.lower().endswith(".ncz")
    if is_ncz:
        raise UnpackError(
            "compressed meta NCA (.cnmt.ncz): unpack from a plain NSP/XCI")

    hdr = _peek_header(fh, meta.offset, meta.size, keyset, meta.name)
    if hdr[0x205] != _NTYPE_META:
        raise UnpackError(f"{meta.name}: expected a meta NCA")
    keygen = _keygen(hdr)
    rights_raw = hdr[0x230:0x240]
    rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None

    # Build a reader over the meta NCA to validate titlekey candidates.
    meta_read = _slice_reader(fh, meta)

    def probe(cand: bytes | None) -> bool:
        try:
            nca = Nca(meta_read, meta.size, keyset, titlekey=cand,
                      label=meta.name)
            sec = nca.sections[0]
            r = nca.reader(sec)
            if sec.is_pfs0:
                return r.read_at(sec.pfs0_offset, 4) == _PFS0
            return int.from_bytes(r.read_at(sec.ivfc_level5_offset, 8)[:8],
                                  "little") == 0x50
        except UnpackError:
            return False

    titlekey = _resolve_titlekey(fh, entries, keyset, rights_id, keygen,
                                 probe)
    nca = Nca(meta_read, meta.size, keyset, titlekey=titlekey,
              label=meta.name)
    if not nca.sections:
        raise UnpackError(f"{meta.name}: meta NCA has no sections")
    sec = nca.sections[0]
    if not sec.is_pfs0:
        raise UnpackError(f"{meta.name}: meta NCA section is not PFS0")
    r = nca.reader(sec)
    window = SliceReader(r.read_at, sec.pfs0_offset, sec.pfs0_size)
    files = parse_pfs0(window.read_at)
    cnmt_file = next((f for f in files if f.name.endswith(".cnmt")), None)
    if cnmt_file is None:
        if not files:
            raise UnpackError(f"{meta.name}: meta PFS0 is empty")
        cnmt_file = files[0]
    # Pfs0Entry offsets are window-relative already.
    blob = window.read_at(cnmt_file.offset, cnmt_file.size)
    return parse_cnmt(blob), titlekey, keygen


def _load_cnmt(fh: IO[bytes], entries: list[_Entry], keyset: Keyset
               ) -> tuple[Cnmt, bytes | None, int]:
    """Parse the package's CNMT.

    Returns (cnmt, titlekey used for the meta NCA, keygen). The titlekey
    is resolved by trial-probing the meta NCA's own PFS0 section.
    """
    meta = next((e for e in entries
                 if e.name.lower().endswith((".cnmt.nca", ".cnmt.ncz"))),
                None)
    if meta is None:
        # Fall back: the meta content type is 1; scan headers (rare).
        for e in entries:
            if not e.name.lower().endswith((".nca", ".ncz")):
                continue
            hdr = _peek_header(fh, e.offset, e.size, keyset, e.name)
            if hdr[0x205] == _NTYPE_META:
                meta = e
                break
    if meta is None:
        raise UnpackError("no meta (CNMT) NCA found in the package")
    return _parse_meta_entry(fh, meta, entries, keyset)


def _keygen(hdr: bytes) -> int:
    keygen = max(hdr[0x206], hdr[0x220])
    return keygen - 1 if keygen else 0


def _slice_reader(fh: IO[bytes], e: _Entry) -> ReadAt:
    def read_at(off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > e.size:
            raise UnpackError(
                f"{e.name}: read out of range 0x{off:x}+0x{n:x}")
        return read_at_file(fh, e.offset + off, n, e.name)
    return read_at


def _probe_nca_titlekey(read_at: ReadAt, size: int, keyset: Keyset,
                        cand: bytes | None, label: str) -> bool:
    try:
        nca = Nca(read_at, size, keyset, titlekey=cand, label=label)
        if not nca.sections:
            return True
        sec0 = nca.sections[0]
        r = nca.reader(sec0)
        if sec0.is_pfs0:
            return r.read_at(sec0.pfs0_offset, 4) == _PFS0
        if sec0.is_romfs or sec0.is_bktr:
            if sec0.is_bktr:
                return True
            head = r.read_at(sec0.ivfc_level5_offset, 8)
            return int.from_bytes(head[:8], "little") == 0x50
        return True
    except (UnpackError, ValueError):
        return False


def _find_exefs_section(nca: Nca) -> tuple[Section, list[Pfs0Entry]] | None:
    candidates: list[tuple[Section, list[Pfs0Entry]]] = []
    for s in nca.pfs0_sections():
        # Plaintext logo section check: ignore plaintext PFS0 at 0x4000
        if s.pfs0_offset == 0x4000:
            continue
        try:
            r = nca.reader(s)
            window = SliceReader(r.read_at, s.pfs0_offset, s.pfs0_size)
            files = parse_pfs0(window.read_at)
            candidates.append((s, files))
        except (UnpackError, ValueError):
            continue
    if not candidates:
        return None
    # 1. Look for section containing main.npdm
    for sec, files in candidates:
        if any(f.name == "main.npdm" for f in files):
            return sec, files
    # 2. Fall back to largest PFS0 section
    return max(candidates, key=lambda pair: pair[0].pfs0_size)


def _probe_base(cand: Path, target_base_id: int, keyset: Keyset) -> bool:
    try:
        with _open_file(cand) as fh:
            sz = os.path.getsize(cand)

            def probe_read(o: int, n: int) -> bytes:
                return read_at_file(fh, o, n, cand.name)

            kind = _detect_kind(probe_read, cand.name)
            if kind == "pfs0":
                entries = _list_pfs0(fh)
            elif kind == "xci":
                entries = _list_xci(fh, sz)
            else:
                return False
            cnmt, _, _ = _load_cnmt(fh, entries, keyset)
            return (cnmt.meta_type == MetaType.PROGRAM
                    and cnmt.title_id == target_base_id)
    except (UnpackError, OSError):
        return False


def _resolve_base(
    src: Path,
    base_arg: Path | None,
    target_base_id: int,
    keyset: Keyset,
) -> Path | None:
    if base_arg is not None:
        if base_arg.is_file():
            if _probe_base(base_arg, target_base_id, keyset):
                return base_arg
            return None
        if base_arg.is_dir():
            for p in base_arg.iterdir():
                if p.is_file() and p.suffix.lower() in _DUMP_SUFFIXES:
                    if _probe_base(p, target_base_id, keyset):
                        return p
            return None
    # Auto-discovery: scan src.resolve().parent and parent.parent
    src_res = src.resolve()
    scanned_dirs: list[Path] = [src_res.parent]
    if src_res.parent.parent != src_res.parent:
        scanned_dirs.append(src_res.parent.parent)
    for d in scanned_dirs:
        if not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                if (p.is_file() and p.resolve() != src_res
                        and p.suffix.lower() in _DUMP_SUFFIXES):
                    if _probe_base(p, target_base_id, keyset):
                        return p
        except OSError:
            continue
    return None


class _BaseHandle:
    __slots__ = ("fhs", "temp_path", "reader")

    def __init__(self, fhs: list[IO[bytes]], temp_path: Path | None,
                 reader: SectionReader) -> None:
        self.fhs = fhs
        self.temp_path = temp_path
        self.reader = reader

    def close(self) -> None:
        for fh in self.fhs:
            try:
                fh.close()
            except OSError:
                pass
        if self.temp_path and self.temp_path.is_file():
            try:
                self.temp_path.unlink()
            except OSError:
                pass


def _get_base_romfs_reader(
    base_path: Path,
    keyset: Keyset,
    out_dir: Path,
    sink: _ProgressSink,
) -> _BaseHandle:
    base_fh = _open_file(base_path)
    fhs: list[IO[bytes]] = [base_fh]
    temp_nca: Path | None = None
    try:
        def base_read(o: int, n: int) -> bytes:
            return read_at_file(base_fh, o, n, base_path.name)

        base_size = os.path.getsize(base_path)
        base_kind = _detect_kind(base_read, base_path.name)
        if base_kind == "pfs0":
            base_entries = _list_pfs0(base_fh)
        elif base_kind == "xci":
            base_entries = _list_xci(base_fh, base_size)
        else:
            raise UnpackError(f"unsupported base container: {base_path}")
        base_cnmt, _, _ = _load_cnmt(base_fh, base_entries, keyset)
        prog = next(
            (c for c in base_cnmt.entries if c.content_type == ContentType.PROGRAM),
            None,
        )
        if prog is None:
            raise UnpackError(f"{base_path}: no PROGRAM in CNMT")
        entry = next(
            (e for e in base_entries
             if e.name.lower().startswith(prog.content_id.lower())),
            None,
        )
        if entry is None:
            raise UnpackError(f"{base_path}: content {prog.content_id} not found")

        entry_read = _slice_reader(base_fh, entry)
        if is_ncz(entry_read, 0, entry.size) or entry.name.lower().endswith(".ncz"):
            temp_nca = out_dir / f".tmp_{os.getpid()}_{entry.name}.nca"
            ncz_to_nca(entry_read, 0, temp_nca, nca_size=entry.size, cancel=sink._cancel)
            decomp_fh = _open_file(temp_nca)
            fhs.append(decomp_fh)
            dec_size = os.path.getsize(temp_nca)

            def dec_read(off: int, n: int) -> bytes:
                return read_at_file(decomp_fh, off, n, temp_nca.name)

            hdr = _peek_header(decomp_fh, 0, dec_size, keyset, temp_nca.name)
            keygen = _keygen(hdr)
            rights_raw = hdr[0x230:0x240]
            rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
            titlekey = _resolve_titlekey(
                base_fh, base_entries, keyset, rights_id, keygen,
                lambda cand: _probe_nca_titlekey(dec_read, dec_size, keyset, cand, temp_nca.name),
            )
            nca = Nca(dec_read, dec_size, keyset, titlekey=titlekey, label=temp_nca.name)
        else:
            hdr = _peek_header(base_fh, entry.offset, entry.size, keyset, entry.name)
            keygen = _keygen(hdr)
            rights_raw = hdr[0x230:0x240]
            rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
            titlekey = _resolve_titlekey(
                base_fh, base_entries, keyset, rights_id, keygen,
                lambda cand: _probe_nca_titlekey(entry_read, entry.size, keyset, cand, entry.name),
            )
            nca = Nca(entry_read, entry.size, keyset, titlekey=titlekey, label=entry.name)

        sec = nca.romfs_section()
        if sec is None:
            raise UnpackError(f"{base_path}: base NCA has no RomFS section")
        return _BaseHandle(fhs, temp_nca, nca.reader(sec))
    except Exception:
        for fh in fhs:
            try:
                fh.close()
            except OSError:
                pass
        if temp_nca and temp_nca.is_file():
            try:
                temp_nca.unlink()
            except OSError:
                pass
        raise


_WIN_RESERVED: Final = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)


def _safe_resolve(dest: Path, rel: str) -> Path:
    """Resolve `rel` relative to `dest`, guarding strictly against traversal and Windows device names."""
    if not rel or rel.startswith(("/", "\\")) or ":" in rel or "\0" in rel:
        raise UnpackError(f"unsafe file path in container: {rel!r}")
    normalized = rel.replace("\\", "/")
    parts = normalized.split("/")
    for p in parts:
        if p in ("..", ".", "") or ":" in p or "\0" in p:
            raise UnpackError(f"unsafe file path in container: {rel!r}")
        if os.name == "nt":
            if p.split(".", 1)[0].upper() in _WIN_RESERVED or p != p.rstrip(" ."):
                raise UnpackError(f"unsafe Windows device name or trailing space/dot in path: {rel!r}")
    target = dest.joinpath(*parts)
    try:
        target.resolve().relative_to(dest.resolve())
    except (ValueError, RuntimeError):
        raise UnpackError(f"path escapes destination directory: {rel!r}")
    return target


def _extract_nca_content(
    nca: Nca,
    work: _Work,
    src: Path,
    out: Path,
    keyset: Keyset,
    base_arg: Path | None,
    sink: _ProgressSink,
) -> None:
    def on_chunk(n: int) -> None:
        sink.check()
        sink.p.bytes_done += n
        if sink.p.bytes_done > sink.p.bytes_total:
            sink.p.bytes_total = sink.p.bytes_done
        sink.emit()

    # 1. ExeFS
    if work.dest_exefs is not None:
        exefs_res = _find_exefs_section(nca)
        if exefs_res is not None:
            sec_exefs, pfiles = exefs_res
            r_exefs = nca.reader(sec_exefs)
            win = SliceReader(r_exefs.read_at, sec_exefs.pfs0_offset, sec_exefs.pfs0_size)
            for f in pfiles:
                sink.check()
                dp = _safe_resolve(work.dest_exefs, f.name)
                dp.parent.mkdir(parents=True, exist_ok=True)
                sink.p.current = str(dp.relative_to(out))
                sink.emit()
                with open(dp, "wb") as out_f:
                    copy_stream(win.read_at, f.offset, f.size, out_f.write, on_progress=on_chunk)

    # 2. RomFS
    if work.dest_romfs is not None:
        sec_romfs = nca.romfs_section()
        if sec_romfs is not None:
            if sec_romfs.is_bktr:
                base_path = _resolve_base(src, base_arg, work.base_id, keyset)
                if base_path is None:
                    sink.warn(
                        f"base package {work.base_id:016x} not found; skipping update RomFS merge"
                    )
                else:
                    base_handle = _get_base_romfs_reader(base_path, keyset, out, sink)
                    try:
                        update_reader = nca.reader(sec_romfs)
                        tables = load_bktr(update_reader)
                        bktr_reader = BktrReader(update_reader, base_handle.reader, tables)
                        romfs = RomFs(bktr_reader.read_at, sec_romfs.ivfc_level5_offset)
                        for rf in romfs.files():
                            sink.check()
                            dp = _safe_resolve(work.dest_romfs, rf.path)
                            dp.parent.mkdir(parents=True, exist_ok=True)
                            sink.p.current = str(dp.relative_to(out))
                            sink.emit()
                            with open(dp, "wb") as out_f:
                                copy_stream(bktr_reader.read_at, rf.offset, rf.size,
                                            out_f.write, on_progress=on_chunk)
                    finally:
                        base_handle.close()
            else:
                r_romfs = nca.reader(sec_romfs)
                romfs = RomFs(r_romfs.read_at, sec_romfs.ivfc_level5_offset)
                for rf in romfs.files():
                    sink.check()
                    dp = _safe_resolve(work.dest_romfs, rf.path)
                    dp.parent.mkdir(parents=True, exist_ok=True)
                    sink.p.current = str(dp.relative_to(out))
                    sink.emit()
                    with open(dp, "wb") as out_f:
                        copy_stream(r_romfs.read_at, rf.offset, rf.size,
                                    out_f.write, on_progress=on_chunk)

    # 3. Control / Meta
    if work.dest_meta is not None:
        sink.stage("control")
        sec_ctrl = nca.romfs_section()
        if sec_ctrl is not None:
            r_ctrl = nca.reader(sec_ctrl)
            romfs = RomFs(r_ctrl.read_at, sec_ctrl.ivfc_level5_offset)
            nacp_obj: Nacp | None = None
            for rf in romfs.files():
                sink.check()
                dp = _safe_resolve(work.dest_meta, rf.path)
                dp.parent.mkdir(parents=True, exist_ok=True)
                sink.p.current = str(dp.relative_to(out))
                sink.emit()
                with open(dp, "wb") as out_f:
                    copy_stream(r_ctrl.read_at, rf.offset, rf.size,
                                out_f.write, on_progress=on_chunk)
                if rf.path.endswith("control.nacp") or rf.path == "control.nacp":
                    try:
                        raw_nacp = r_ctrl.read_at(rf.offset, rf.size)
                        nacp_obj = parse_nacp(raw_nacp)
                    except Exception:
                        pass
            if nacp_obj is None:
                cand_nacp = work.dest_meta / "control.nacp"
                if cand_nacp.is_file():
                    try:
                        nacp_obj = parse_nacp(cand_nacp.read_bytes())
                    except Exception:
                        pass
            if nacp_obj is None:
                nacp_obj = Nacp("", "", "")
            info_path = work.dest_meta / "info.txt"
            info_body = (
                f"title_id: {work.pkg_title_id:016x}\n"
                f"version: {work.pkg_version}\n"
                f"name: {nacp_obj.title_name}\n"
                f"publisher: {nacp_obj.publisher}\n"
                f"display_version: {nacp_obj.display_version}\n"
                f"source: {src.name}\n"
            )
            info_path.write_text(info_body, encoding="utf-8")


def _extract_work(
    fh: IO[bytes],
    work: _Work,
    src: Path,
    out: Path,
    keyset: Keyset,
    base_arg: Path | None,
    sink: _ProgressSink,
) -> None:
    entry_read = _slice_reader(fh, work.entry)
    is_ncz_content = work.is_ncz or is_ncz(entry_read, 0, work.entry.size)
    if is_ncz_content:
        temp_path = out / f".tmp_{os.getpid()}_{work.entry.name}.nca"
        try:
            sink.check()
            ncz_to_nca(
                entry_read,
                0,
                temp_path,
                nca_size=work.entry.size,
                on_progress=lambda n: sink.check(),
                cancel=sink._cancel,
            )
            with _open_file(temp_path) as decomp_fh:
                dec_size = os.path.getsize(temp_path)

                def dec_read(off: int, n: int) -> bytes:
                    return read_at_file(decomp_fh, off, n, temp_path.name)

                nca = Nca(dec_read, dec_size, keyset, titlekey=work.titlekey,
                          label=temp_path.name)
                _extract_nca_content(nca, work, src, out, keyset, base_arg, sink)
        finally:
            if temp_path.is_file():
                try:
                    temp_path.unlink()
                except OSError:
                    pass
    else:
        nca = Nca(entry_read, work.entry.size, keyset, titlekey=work.titlekey,
                  label=work.entry.name)
        _extract_nca_content(nca, work, src, out, keyset, base_arg, sink)


def unpack(
    src: Path,
    out: Path,
    *,
    keys_path: Path | None = None,
    title_keys_path: Path | None = None,
    base: Path | None = None,
    no_control: bool = False,
    replace: bool = False,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> None:
    """Unpack an NSP/NSZ/XCI/XCZ/NCA into the standard dump directory layout."""
    if not src.is_file():
        raise UnpackError(f"source file not found: {src}")

    src_res = src.resolve()
    out_res = out.resolve()
    if src_res == out_res:
        raise UnpackError(f"output directory cannot be the source file: {out}")
    if src_res.is_relative_to(out_res):
        raise UnpackError(f"output directory {out} contains the source file {src}")
    if out.is_file():
        raise UnpackError(f"output path is an existing file: {out}")

    out_existed = out.exists()
    out_is_non_empty = out_existed and any(out.iterdir())
    if out_is_non_empty and not replace:
        raise UnpackError(
            f"refusing to overwrite non-empty output directory: {out} "
            f"(pass replace=True or --force)"
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    # Sweep stale partials and backups from prior crashed runs
    for p in out.parent.glob(f".{out.name}.partial_*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
    for p in out.parent.glob(f".{out.name}.old_*"):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)

    staging = out.parent / f".{out.name}.partial_{os.getpid()}"
    staging.mkdir(parents=True, exist_ok=True)

    try:
        keyset = Keyset.load(keys_path, title_keys_path)
        sink = _ProgressSink(progress, cancel)
        sink.stage("scan")

        with _open_file(src) as fh:
            file_size = os.path.getsize(src)

            def read_at(off: int, n: int) -> bytes:
                return read_at_file(fh, off, n, src.name)

            kind = _detect_kind(read_at, src.name)
            if kind == "pfs0":
                entries = _list_pfs0(fh)
            elif kind == "xci":
                entries = _list_xci(fh, file_size)
            else:
                entries = [_Entry(src.name, 0, file_size)]

            sink.stage("meta")
            works: list[_Work] = []

            if kind == "nca":
                hdr = _peek_header(fh, 0, file_size, keyset, src.name)
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
                if nca_type == _NTYPE_PROGRAM:
                    works.append(_Work(
                        entry, nca_type, titlekey, is_ncz_content,
                        dest_exefs=staging / "base" / "exefs",
                        dest_romfs=staging / "base" / "romfs",
                        pkg_title_id=title_id, pkg_version=0,
                    ))
                elif nca_type in (_NTYPE_DATA, _NTYPE_PUBLIC_DATA):
                    works.append(_Work(
                        entry, nca_type, titlekey, is_ncz_content,
                        dest_romfs=staging / "dlc" / f"{title_id:016x}" / "0" / "romfs",
                        pkg_title_id=title_id, pkg_version=0,
                    ))
                elif nca_type == _NTYPE_CONTROL:
                    if not no_control:
                        works.append(_Work(
                            entry, nca_type, titlekey, is_ncz_content,
                            dest_meta=staging / "_meta",
                            pkg_title_id=title_id, pkg_version=0,
                        ))
            else:
                # Find all meta entries
                meta_entries = [e for e in entries if e.name.lower().endswith((".cnmt.nca", ".cnmt.ncz"))]
                if not meta_entries:
                    for e in entries:
                        if not e.name.lower().endswith((".nca", ".ncz")):
                            continue
                        hdr = _peek_header(fh, e.offset, e.size, keyset, e.name)
                        if hdr[0x205] == _NTYPE_META:
                            meta_entries.append(e)
                if not meta_entries:
                    raise UnpackError("no meta (CNMT) NCA found in the package")

                for meta_entry in meta_entries:
                    cnmt, _meta_tk, _kg = _parse_meta_entry(fh, meta_entry, entries, keyset)
                    for c in cnmt.entries:
                        if c.content_type == ContentType.META:
                            continue
                        if c.content_type in (ContentType.MANUAL, ContentType.LEGAL):
                            continue
                        if c.content_type == ContentType.CONTROL and no_control:
                            continue
                        matched = next(
                            (e for e in entries if e.name.lower().startswith(c.content_id.lower())),
                            None,
                        )
                        if matched is None:
                            raise UnpackError(f"content {c.content_id} not found in container")

                        hdr = _peek_header(fh, matched.offset, matched.size, keyset, matched.name)
                        nca_type = hdr[0x205]
                        if nca_type == _NTYPE_MANUAL:
                            continue
                        if nca_type == _NTYPE_CONTROL and no_control:
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
                            if nca_type == _NTYPE_PROGRAM:
                                works.append(_Work(
                                    matched, nca_type, titlekey, is_decomp,
                                    dest_exefs=staging / "base" / "exefs",
                                    dest_romfs=staging / "base" / "romfs",
                                    pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                ))
                            elif nca_type == _NTYPE_CONTROL:
                                if not no_control:
                                    works.append(_Work(
                                        matched, nca_type, titlekey, is_decomp,
                                        dest_meta=staging / "_meta",
                                        pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                    ))
                            elif nca_type in (_NTYPE_DATA, _NTYPE_PUBLIC_DATA):
                                works.append(_Work(
                                    matched, nca_type, titlekey, is_decomp,
                                    dest_romfs=staging / "base" / "romfs",
                                    pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                ))
                        elif cnmt.meta_type == MetaType.PATCH:
                            if nca_type == _NTYPE_PROGRAM:
                                works.append(_Work(
                                    matched, nca_type, titlekey, is_decomp,
                                    dest_exefs=staging / "updates" / str(cnmt.version) / "exefs",
                                    dest_romfs=staging / "updates" / str(cnmt.version) / "romfs",
                                    is_bktr=True, base_id=cnmt.base_id,
                                    pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                ))
                            elif nca_type == _NTYPE_CONTROL:
                                if not no_control:
                                    works.append(_Work(
                                        matched, nca_type, titlekey, is_decomp,
                                        dest_meta=staging / "_meta",
                                        pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                    ))
                        elif cnmt.meta_type == MetaType.ADDON:
                            if nca_type in (_NTYPE_DATA, _NTYPE_PUBLIC_DATA, _NTYPE_PROGRAM):
                                idx_str = str(c.id_offset)
                                works.append(_Work(
                                    matched, nca_type, titlekey, is_decomp,
                                    dest_romfs=staging / "dlc" / f"{cnmt.title_id:016x}" / idx_str / "romfs",
                                    pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                ))
                            elif nca_type == _NTYPE_CONTROL:
                                if not no_control:
                                    works.append(_Work(
                                        matched, nca_type, titlekey, is_decomp,
                                        dest_meta=staging / "_meta",
                                        pkg_title_id=cnmt.title_id, pkg_version=cnmt.version,
                                    ))

            sink.stage("extract")
            sink.p.total = len(works)
            sink.p.bytes_total = sum(w.entry.size for w in works)
            sink.p.done = 0
            sink.p.bytes_done = 0
            sink.emit()

            try:
                free_space = shutil.disk_usage(staging).free
                if free_space < sink.p.bytes_total:
                    sink.warn(
                        f"low disk space on {out.parent}: "
                        f"{free_space // (1024 * 1024):,} MB free, "
                        f"{sink.p.bytes_total // (1024 * 1024):,} MB estimated required"
                    )
            except OSError:
                pass

            for w in works:
                sink.check()
                _extract_work(fh, w, src, staging, keyset, base, sink)
                sink.p.done += 1
                sink.emit()

            sink.stage("done")
            sink.p.current = ""
            if sink.p.bytes_done < sink.p.bytes_total:
                sink.p.bytes_done = sink.p.bytes_total
            sink.emit()

            # Atomic publish to out
            if out_is_non_empty and replace:
                backup = out.parent / f".{out.name}.old_{os.getpid()}"
                os.replace(out, backup)
                try:
                    os.replace(staging, out)
                except BaseException:
                    try:
                        os.replace(backup, out)
                    except OSError:
                        pass
                    raise
                shutil.rmtree(backup, ignore_errors=True)
            else:
                if out.is_dir():
                    try:
                        out.rmdir()
                    except OSError:
                        pass
                os.replace(staging, out)

    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
