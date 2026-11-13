"""PFS0 (package filesystem) parsing.

Header: magic 'PFS0', u32 file count, u32 string table size, u32
reserved; then count entries of {u64 offset, u64 size, u32 str_off,
u32 reserved} and the string table. Entry offsets are relative to the
end of the header region; returned offsets are reader-relative.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnpackError
from .reader import ReadAt, read_exact

MAGIC: Final = b"PFS0"
_ENTRY_SIZE: Final = 0x18
_HEADER_SIZE: Final = 0x10


@dataclass(frozen=True, slots=True)
class Pfs0Entry:
    name: str
    offset: int  # reader-relative
    size: int


def parse_pfs0(read_at: ReadAt) -> list[Pfs0Entry]:
    """Parse a PFS0 whose header sits at offset 0 of `read_at`."""
    hdr = read_exact(read_at, 0, _HEADER_SIZE, "PFS0 header")
    if hdr[:4] != MAGIC:
        raise UnpackError(f"bad PFS0 magic {hdr[:4]!r}")
    count, str_size, _reserved = (int.from_bytes(hdr[4:8], "little"),
                                  int.from_bytes(hdr[8:12], "little"),
                                  int.from_bytes(hdr[12:16], "little"))
    if count > 0x10000:
        raise UnpackError(f"implausible PFS0 file count {count}")
    if str_size > 0x4000000:
        raise UnpackError(f"implausible PFS0 string table size {str_size}")
    ent_blob = read_exact(read_at, _HEADER_SIZE, count * _ENTRY_SIZE,
                          "PFS0 entries")
    names = read_exact(read_at, _HEADER_SIZE + count * _ENTRY_SIZE, str_size,
                       "PFS0 string table")
    data_base = _HEADER_SIZE + count * _ENTRY_SIZE + str_size
    out: list[Pfs0Entry] = []
    for i in range(count):
        pos = i * _ENTRY_SIZE
        off = int.from_bytes(ent_blob[pos:pos + 8], "little")
        size = int.from_bytes(ent_blob[pos + 8:pos + 16], "little")
        str_off = int.from_bytes(ent_blob[pos + 16:pos + 20], "little")
        if str_off >= str_size:
            raise UnpackError(f"PFS0 entry {i} name offset out of range")
        end = names.find(b"\0", str_off)
        if end < 0:
            end = str_size
        name = names[str_off:end].decode("utf-8", "replace")
        out.append(Pfs0Entry(name, data_base + off, size))
    return out
