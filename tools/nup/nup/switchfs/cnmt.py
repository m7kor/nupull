"""CNMT (content meta) parsing.

Layout: u64 title id, u32 version, u8 type, u8 base-id flag,
u16 extended-header size, u16 content count, 6 bytes reserved,
0x10 bytes meta id, then `count` PackagedContentInfo entries of
0x38 bytes: hash[0x20], content id[0x10], size (6 bytes), content
type u8, id-offset u8.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

from .errors import UnpackError
from .reader import ReadAt, read_exact


class MetaType(IntEnum):
    PROGRAM = 0x80
    PATCH = 0x81
    ADDON = 0x82
    DELTA = 0x83


class ContentType(IntEnum):
    PROGRAM = 1
    META = 2
    CONTROL = 3
    MANUAL = 4
    LEGAL = 5
    DATA = 6
    PUBLIC_DATA = 7


@dataclass(frozen=True, slots=True)
class ContentEntry:
    content_id: str   # 32 lowercase hex chars
    size: int
    content_type: int  # ContentType
    id_offset: int


@dataclass(frozen=True, slots=True)
class Cnmt:
    title_id: int
    version: int
    meta_type: int      # MetaType
    ext_size: int
    base_id: int        # patch/addon target application id (0 otherwise)
    entries: tuple[ContentEntry, ...]


def parse_cnmt(blob: bytes) -> Cnmt:
    if len(blob) < 0x20:
        raise UnpackError("CNMT too small")
    title_id = int.from_bytes(blob[0:8], "little")
    version = int.from_bytes(blob[8:12], "little")
    meta_type = blob[0xC]
    ext_size = int.from_bytes(blob[0xE:0x10], "little")
    count = int.from_bytes(blob[0x10:0x12], "little")
    if 0x20 + ext_size > len(blob):
        raise UnpackError("CNMT extended header out of range")
    if count > 2048:
        raise UnpackError(f"implausible CNMT content count {count}")
    entries: list[ContentEntry] = []
    pos = 0x20 + ext_size
    for _ in range(count):
        if pos + 0x38 > len(blob):
            raise UnpackError("CNMT content entries truncated")
        content_id = blob[pos + 0x20:pos + 0x30].hex()
        size = int.from_bytes(blob[pos + 0x30:pos + 0x36], "little")
        entries.append(ContentEntry(content_id, size, blob[pos + 0x36],
                                    blob[pos + 0x37]))
        pos += 0x38
    # The extended header starts at absolute 0x20; patch and addon CNMTs store
    # the base application id as the first u64 of it.
    base_id = 0
    if meta_type in (MetaType.PATCH, MetaType.ADDON) and ext_size >= 8:
        base_id = int.from_bytes(blob[0x20:0x28], "little")
    return Cnmt(title_id, version, meta_type, ext_size, base_id,
                tuple(entries))


def parse_cnmt_at(read_at: ReadAt, off: int, size: int) -> Cnmt:
    return parse_cnmt(read_exact(read_at, off, size, "CNMT"))
