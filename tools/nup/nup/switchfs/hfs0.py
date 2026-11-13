"""HFS0 (hashed filesystem) parsing for XCI partitions.

Header mirrors PFS0; entries are {u64 offset, u64 size, u32 str_off,
u32 hashed_size, u64 reserved, u8[0x20] hash} with a 0x40 stride.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnpackError
from .reader import ReadAt, read_exact

MAGIC: Final = b"HFS0"
_ENTRY_SIZE: Final = 0x40
_HEADER_SIZE: Final = 0x10


@dataclass(frozen=True, slots=True)
class Hfs0Entry:
    name: str
    offset: int  # reader-relative (after the header region)
    size: int
    hashed_size: int


def parse_hfs0(read_at: ReadAt) -> list[Hfs0Entry]:
    """Parse an HFS0 whose header sits at offset 0 of `read_at`."""
    hdr = read_exact(read_at, 0, _HEADER_SIZE, "HFS0 header")
    if hdr[:4] != MAGIC:
        raise UnpackError(f"bad HFS0 magic {hdr[:4]!r}")
    count = int.from_bytes(hdr[4:8], "little")
    str_size = int.from_bytes(hdr[8:12], "little")
    if count > 0x10000:
        raise UnpackError(f"implausible HFS0 file count {count}")
    if str_size > 0x4000000:
        raise UnpackError(f"implausible HFS0 string table size {str_size}")
    ent_blob = read_exact(read_at, _HEADER_SIZE, count * _ENTRY_SIZE,
                          "HFS0 entries")
    names = read_exact(read_at, _HEADER_SIZE + count * _ENTRY_SIZE, str_size,
                       "HFS0 string table")
    data_base = _HEADER_SIZE + count * _ENTRY_SIZE + str_size
    out: list[Hfs0Entry] = []
    for i in range(count):
        pos = i * _ENTRY_SIZE
        off = int.from_bytes(ent_blob[pos:pos + 8], "little")
        size = int.from_bytes(ent_blob[pos + 8:pos + 16], "little")
        str_off = int.from_bytes(ent_blob[pos + 16:pos + 20], "little")
        hashed = int.from_bytes(ent_blob[pos + 20:pos + 24], "little")
        if str_off >= str_size:
            raise UnpackError(f"HFS0 entry {i} name offset out of range")
        end = names.find(b"\0", str_off)
        if end < 0:
            end = str_size
        name = names[str_off:end].decode("utf-8", "replace")
        out.append(Hfs0Entry(name, data_base + off, size, hashed))
    return out
