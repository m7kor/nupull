"""Batch converter: discover, group, and convert multiple Switch game dumps into .nup containers.

Scans an input directory, inspects dump headers in milliseconds, groups Base games
with their matching Updates and DLCs, and converts each game group into a consolidated,
verified .nup container.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import time
from typing import Callable, Final, IO

from .convert import convert
from .discover import PackInput
from .switchfs.cnmt import MetaType
from .switchfs.errors import CancelledError, UnpackError
from .switchfs.keys import Keyset
from .switchfs.nacp import parse_nacp
from .switchfs.nca import Nca
from .switchfs.romfs import RomFs
from .switchfs.unpack import (
    Progress,
    _Entry,
    _detect_kind,
    _keygen,
    _list_pfs0,
    _list_xci,
    _open_file,
    _parse_meta_entry,
    _peek_header,
    _probe_nca_titlekey,
    _resolve_titlekey,
    _slice_reader,
    read_at_file,
    _NTYPE_META,
    _NTYPE_CONTROL,
    _DUMP_SUFFIXES,
)

ProgressFn = Callable[[Progress], None]
CancelFn = Callable[[], bool]

_BAD_FILENAME_CHARS: Final = r'<>:"/\|?*'


def _sanitize_filename(name: str) -> str:
    cleaned = "".join(c if c not in _BAD_FILENAME_CHARS else "_" for c in name).strip()
    return cleaned or "container"


@dataclass(slots=True)
class _GameGroup:
    title_id: int
    name: str = ""
    base_file: Path | None = None
    updates: list[Path] = field(default_factory=list)
    dlcs: list[Path] = field(default_factory=list)


@dataclass(slots=True)
class BatchResult:
    total_games: int = 0
    succeeded: int = 0
    failed: int = 0
    errors: dict[str, str] = field(default_factory=dict)
    containers: list[Path] = field(default_factory=list)


def _inspect_dump(
    path: Path,
    keyset: Keyset,
) -> tuple[int, int, int, str | None] | None:
    """Inspect a dump in milliseconds, returning (meta_type, title_id, base_id, app_name)."""
    try:
        fh = _open_file(path)
    except Exception:
        return None
    try:
        file_size = os.path.getsize(path)

        def read_at(off: int, n: int) -> bytes:
            return read_at_file(fh, off, n, path.name)

        kind = _detect_kind(read_at, path.name)
        if kind == "pfs0":
            entries = _list_pfs0(fh)
        elif kind == "xci":
            entries = _list_xci(fh, file_size)
        else:
            return None

        meta_entries = [e for e in entries if e.name.lower().endswith((".cnmt.nca", ".cnmt.ncz"))]
        if not meta_entries:
            for e in entries:
                if not e.name.lower().endswith((".nca", ".ncz")):
                    continue
                hdr = _peek_header(fh, e.offset, e.size, keyset, e.name)
                if hdr[0x205] == _NTYPE_META:
                    meta_entries.append(e)
        if not meta_entries:
            return None

        cnmt, _, _ = _parse_meta_entry(fh, meta_entries[0], entries, keyset)
        app_name: str | None = None

        # Optional: check if control NCA exists to read title name
        ctrl_entry = next(
            (e for e in entries if "control" in e.name.lower() and e.name.lower().endswith(".nca")),
            None,
        )
        if ctrl_entry:
            try:
                hdr = _peek_header(fh, ctrl_entry.offset, ctrl_entry.size, keyset, ctrl_entry.name)
                keygen = _keygen(hdr)
                rights_raw = hdr[0x230:0x240]
                rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
                entry_read = _slice_reader(fh, ctrl_entry)
                titlekey = None
                if rights_id is not None:
                    titlekey = _resolve_titlekey(
                        fh, entries, keyset, rights_id, keygen,
                        lambda cand: _probe_nca_titlekey(entry_read, ctrl_entry.size, keyset, cand, ctrl_entry.name),
                    )
                nca = Nca(entry_read, ctrl_entry.size, keyset, titlekey=titlekey, label=ctrl_entry.name)
                sec_ctrl = nca.romfs_section()
                if sec_ctrl is not None:
                    r_ctrl = nca.reader(sec_ctrl)
                    romfs = RomFs(r_ctrl.read_at, sec_ctrl.ivfc_level5_offset)
                    for rf in romfs.files():
                        if rf.path.endswith("control.nacp"):
                            raw_nacp = r_ctrl.read_at(rf.offset, rf.size)
                            nacp_obj = parse_nacp(raw_nacp)
                            app_name = nacp_obj.title_name
                            break
            except Exception:
                pass

        return cnmt.meta_type, cnmt.title_id, cnmt.base_id, app_name
    except Exception:
        return None
    finally:
        try:
            fh.close()
        except OSError:
            pass


def batch_convert(
    in_dir: Path | str,
    out_dir: Path | str,
    *,
    keys_path: Path | str | None = None,
    title_keys_path: Path | str | None = None,
    threads: int = -1,
    level: int = 19,
    replace: bool = False,
    fast: bool = False,
    no_control: bool = False,
    progress: ProgressFn | None = None,
    cancel: CancelFn | None = None,
) -> BatchResult:
    """Discover, group, and convert all Switch dumps in in_dir to out_dir."""
    in_p = Path(in_dir)
    out_p = Path(out_dir)

    if not in_p.is_dir():
        raise UnpackError(f"input directory not found: {in_p}")

    try:
        out_p.resolve().relative_to(in_p.resolve())
        raise UnpackError(f"output directory cannot be inside input directory: {out_p}")
    except ValueError:
        pass

    os.makedirs(out_p, exist_ok=True)

    def check_cancel() -> None:
        if cancel is not None and cancel():
            raise CancelledError()

    check_cancel()

    keys_p = Path(keys_path) if keys_path else None
    tkeys_p = Path(title_keys_path) if title_keys_path else None
    keyset = Keyset.load(keys_p, tkeys_p)

    prog = Progress(stage="scan")
    if progress:
        progress(prog)

    # 1. Discover all candidate dump files
    candidates: list[Path] = []
    for item in sorted(in_p.iterdir()):
        if item.is_file() and item.suffix.lower() in _DUMP_SUFFIXES:
            candidates.append(item)

    if not candidates:
        return BatchResult()

    prog.total = len(candidates)

    # 2. Inspect and group dumps
    groups: dict[int, _GameGroup] = {}
    standalone_files: list[Path] = []

    for i, cand in enumerate(candidates):
        check_cancel()
        prog.done = i
        prog.current = f"Inspecting {cand.name}"
        if progress:
            progress(prog)

        info = _inspect_dump(cand, keyset)
        if info is None:
            standalone_files.append(cand)
            continue

        meta_type, tid, base_id, name = info
        if meta_type == MetaType.PROGRAM:
            matched_gid = None
            for gid in list(groups.keys()):
                if gid == tid or (gid & ~0x1FFF) == (tid & ~0x1FFF):
                    matched_gid = gid
                    break
            if matched_gid is not None:
                grp = groups[matched_gid]
            else:
                grp = groups.setdefault(tid, _GameGroup(title_id=tid))
            grp.title_id = tid
            grp.base_file = cand
            if name and not grp.name:
                grp.name = name
        elif meta_type == MetaType.PATCH:
            target_id = base_id if base_id != 0 else (tid & ~0x1FFF)
            matched_gid = None
            for gid in list(groups.keys()):
                if gid == target_id or (gid & ~0x1FFF) == (target_id & ~0x1FFF):
                    matched_gid = gid
                    break
            if matched_gid is not None:
                grp = groups[matched_gid]
            else:
                grp = groups.setdefault(target_id, _GameGroup(title_id=target_id))
            grp.updates.append(cand)
        elif meta_type == MetaType.ADDON:
            target_id = base_id if base_id != 0 else (tid & ~0x1FFF)
            matched_gid = None
            for gid in list(groups.keys()):
                if gid == target_id or (gid & ~0x1FFF) == (target_id & ~0x1FFF) or (tid - 0x1000) == gid:
                    matched_gid = gid
                    break
            if matched_gid is not None:
                grp = groups[matched_gid]
            else:
                grp = groups.setdefault(target_id, _GameGroup(title_id=target_id))
            grp.dlcs.append(cand)
        else:
            standalone_files.append(cand)

    # 3. Assemble active game jobs
    active_groups: list[_GameGroup] = [
        g for g in groups.values()
        if g.base_file is not None or g.updates or g.dlcs
    ]

    result = BatchResult(total_games=len(active_groups))
    if not active_groups:
        return result

    prog.stage = "batch"
    prog.done = 0
    prog.total = len(active_groups)

    # 4. Convert each game group
    for i, grp in enumerate(active_groups):
        check_cancel()
        if grp.base_file is not None:
            primary = grp.base_file
            rem_updates = grp.updates
        elif grp.updates:
            primary = grp.updates[0]
            rem_updates = grp.updates[1:]
        elif grp.dlcs:
            primary = grp.dlcs[0]
            rem_updates = []
        else:
            continue

        label = grp.name or primary.stem
        prog.current = label
        prog.done = i
        if progress:
            progress(prog)

        if grp.name and grp.title_id:
            out_name = f"{grp.name} [{grp.title_id:016X}].nup"
        else:
            out_name = f"{primary.stem}.nup"

        out_file = out_p / _sanitize_filename(out_name)

        try:
            convert(
                primary,
                out_file,
                keys_path=keys_p,
                title_keys_path=tkeys_p,
                updates=rem_updates,
                dlcs=grp.dlcs,
                threads=threads,
                level=level,
                replace=replace,
                fast=fast,
                no_control=no_control,
                cancel=cancel,
            )
            result.succeeded += 1
            result.containers.append(out_file)
        except CancelledError:
            raise
        except Exception as exc:
            result.failed += 1
            result.errors[label] = str(exc)

    prog.stage = "done"
    prog.done = len(active_groups)
    prog.current = ""
    if progress:
        progress(prog)

    return result
