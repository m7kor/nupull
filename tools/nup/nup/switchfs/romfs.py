"""RomFS directory tree walking (metadata tables, IVFC data offset)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnpackError
from .reader import ReadAt, read_exact

_HEADER_SIZE: Final = 0x50
_EMPTY: Final = 0xFFFFFFFF
_MAX_ENTRIES: Final = 4_000_000


@dataclass(frozen=True, slots=True)
class RomFsFile:
    path: str   # relative, '/'-separated
    offset: int  # reader-relative data offset
    size: int


def _u32(blob: bytes, off: int) -> int:
    return int.from_bytes(blob[off:off + 4], "little")


def _u64(blob: bytes, off: int) -> int:
    return int.from_bytes(blob[off:off + 8], "little")


def _name(blob: bytes, off: int, size: int) -> str:
    return blob[off:off + size].decode("utf-8", "replace")


class RomFs:
    """Walks a RomFS given a reader positioned at the section level."""

    __slots__ = ("_read_at", "romfs_offset")

    def __init__(self, read_at: ReadAt, romfs_offset: int) -> None:
        self._read_at = read_at
        self.romfs_offset = romfs_offset

    def files(self) -> list[RomFsFile]:
        base = self.romfs_offset
        hdr = read_exact(self._read_at, base, _HEADER_SIZE, "RomFS header")
        header_size = _u64(hdr, 0)
        if header_size != _HEADER_SIZE:
            raise UnpackError(f"bad RomFS header size {header_size:#x}")
        dir_meta_off = _u64(hdr, 0x18)
        dir_meta_size = _u64(hdr, 0x20)
        file_meta_off = _u64(hdr, 0x38)
        file_meta_size = _u64(hdr, 0x40)
        data_off = _u64(hdr, 0x48)
        if dir_meta_size > 0x80000000 or file_meta_size > 0x80000000:
            raise UnpackError("implausible RomFS metadata size")
        dirs = read_exact(self._read_at, base + dir_meta_off, dir_meta_size,
                          "RomFS dir table")
        files_blob = read_exact(self._read_at, base + file_meta_off,
                                file_meta_size, "RomFS file table")

        out: list[RomFsFile] = []
        seen_dirs: set[int] = set()
        # (dir entry offset within dirs, path prefix)
        stack: list[tuple[int, str]] = [(0, "")]
        count = 0
        while stack:
            doff, prefix = stack.pop()
            if doff in seen_dirs:
                continue
            seen_dirs.add(doff)
            if doff + 24 > len(dirs):
                raise UnpackError("RomFS dir entry out of range")
            child = _u32(dirs, doff + 8)
            first_file = _u32(dirs, doff + 12)
            name_size = _u32(dirs, doff + 20)
            dname = _name(dirs, doff + 24, name_size)
            dpath = f"{prefix}{dname}/" if name_size else prefix
            # Files of this directory.
            foff = first_file
            visited_files: set[int] = set()
            while foff != _EMPTY:
                if foff in visited_files or foff + 32 > len(files_blob):
                    raise UnpackError("RomFS file chain corrupt")
                visited_files.add(foff)
                count += 1
                if count > _MAX_ENTRIES:
                    raise UnpackError("RomFS entry count overflow")
                fsibling = _u32(files_blob, foff + 4)
                foffset = _u64(files_blob, foff + 8)
                fsize = _u64(files_blob, foff + 16)
                fname_size = _u32(files_blob, foff + 28)
                fname = _name(files_blob, foff + 32, fname_size)
                out.append(RomFsFile(
                    path=dpath + fname,
                    offset=base + data_off + foffset,
                    size=fsize,
                ))
                foff = fsibling
            # Child directories (push in reverse so they pop in order).
            children: list[int] = []
            c = child
            seen_children: set[int] = set()
            while c != _EMPTY:
                if c in seen_children or c + 24 > len(dirs):
                    raise UnpackError("RomFS dir chain corrupt")
                seen_children.add(c)
                children.append(c)
                c = _u32(dirs, c + 4)
            for c in reversed(children):
                stack.append((c, dpath))
        return out
