"""BKTR (patch) section tables and the virtual RomFS reader.

Layout inside a BKTR section: [0, reloc.offset) is the patched data
region, then the relocation table region, then the subsection table
region. The tables are plain-CTR readable; virtual reads map through
the relocation table (virtual -> patch/base) and use subsection
counters for CTR IVs on patched data.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnpackError
from .nca import Section, SectionReader

_BUCKET_HDR: Final = 0x10
_BLOCK_HDR: Final = 0x4000
_RELOC_BUCKET_SIZE: Final = 0x4000
_SUB_BUCKET_SIZE: Final = 0x4000
_RELOC_ENTRY: Final = 20   # u64 virt, u64 phys, u32 is_patch
_SUB_ENTRY: Final = 16     # u64 offset, u32 pad, u32 ctr_val
_MAX_RELOC_ENTRIES: Final = 818
_MAX_SUB_ENTRIES: Final = 1023
_SUPERBLOCK_RELOC: Final = 0xE0 + 0x18  # ivfc header + pad


@dataclass(frozen=True, slots=True)
class RelocEntry:
    virt: int
    phys: int
    is_patch: bool


@dataclass(frozen=True, slots=True)
class SubsecEntry:
    offset: int
    ctr: int


def _u32(blob: bytes, off: int) -> int:
    return int.from_bytes(blob[off:off + 4], "little")


def _u64(blob: bytes, off: int) -> int:
    return int.from_bytes(blob[off:off + 8], "little")


@dataclass(slots=True)
class BktrTables:
    relocs: list[RelocEntry]      # sorted by virt, sentinel-terminated
    subs: list[SubsecEntry]       # sorted by offset, sentinel-terminated
    total_size: int               # virtual size of the section

    def reloc_index(self, virt: int) -> int:
        """Index of the reloc entry covering `virt` (bisect right - 1)."""
        lo, hi = 0, len(self.relocs)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.relocs[mid].virt <= virt:
                lo = mid + 1
            else:
                hi = mid
        idx = lo - 1
        if idx < 0 or virt >= self.total_size:
            raise UnpackError(f"virtual offset 0x{virt:x} outside BKTR range")
        return idx

    def sub_index(self, phys: int) -> int:
        lo, hi = 0, len(self.subs)
        while lo < hi:
            mid = (lo + hi) // 2
            if self.subs[mid].offset <= phys:
                lo = mid + 1
            else:
                hi = mid
        idx = lo - 1
        if idx < 0:
            raise UnpackError(f"physical offset 0x{phys:x} outside BKTR range")
        return idx


def load_bktr(reader: SectionReader) -> BktrTables:
    """Parse and flatten the reloc/subsection tables of a BKTR section."""
    sec = reader.section
    sb = sec.fs_header[8:]
    if sb[_SUPERBLOCK_RELOC + 0x10:_SUPERBLOCK_RELOC + 0x14] != b"BKTR" or \
            sb[_SUPERBLOCK_RELOC + 0x30:_SUPERBLOCK_RELOC + 0x34] != b"BKTR":
        raise UnpackError("BKTR magic missing from section superblock")
    reloc_off = _u64(sb, _SUPERBLOCK_RELOC)
    reloc_size = _u64(sb, _SUPERBLOCK_RELOC + 8)
    sub_off = _u64(sb, _SUPERBLOCK_RELOC + 0x20)
    sub_size = _u64(sb, _SUPERBLOCK_RELOC + 0x28)
    if reloc_off + reloc_size != sub_off or sub_off + sub_size != sec.file_size:
        raise UnpackError("invalid BKTR table layout")

    reloc_blob = reader.read_at(reloc_off, reloc_size)
    sub_blob = reader.read_at(sub_off, sub_size)

    relocs, total = _parse_reloc(reloc_blob)
    subs = _parse_subsec(sub_blob, reloc_off, sec.section_ctr,
                         sec.file_size)
    tables = BktrTables(relocs, subs, total)
    # hactool sanity check: subsection table must cover the data region.
    if subs[0].offset != 0:
        raise UnpackError("BKTR subsection table does not start at 0")
    return tables


def _parse_reloc(blob: bytes) -> tuple[list[RelocEntry], int]:
    if len(blob) < 16:
        raise UnpackError("BKTR reloc table truncated")
    num_buckets = _u32(blob, 4)
    total = _u64(blob, 8)
    if not 0 < num_buckets <= 0x400:
        raise UnpackError(f"implausible BKTR reloc bucket count {num_buckets}")
    if 16 + num_buckets * 8 > len(blob):
        raise UnpackError("BKTR reloc bucket directory truncated")
    out: list[RelocEntry] = []
    for b in range(num_buckets):
        base = _BLOCK_HDR + b * _RELOC_BUCKET_SIZE
        if base + _BUCKET_HDR > len(blob):
            raise UnpackError("BKTR reloc bucket out of range")
        count = _u32(blob, base + 4)
        if count > _MAX_RELOC_ENTRIES:
            raise UnpackError(f"implausible BKTR reloc entry count {count}")
        for i in range(count):
            pos = base + _BUCKET_HDR + i * _RELOC_ENTRY
            if pos + _RELOC_ENTRY > len(blob):
                raise UnpackError("BKTR reloc entries truncated")
            virt = _u64(blob, pos)
            phys = _u64(blob, pos + 8)
            patch = _u32(blob, pos + 16)
            out.append(RelocEntry(virt, phys, patch != 0))
        if b + 1 < num_buckets:
            bucket_idx_pos = 16 + (b + 1) * 8
            if bucket_idx_pos + 8 > len(blob):
                raise UnpackError("BKTR reloc bucket index truncated")
            nxt = _u64(blob, bucket_idx_pos)
            out.append(RelocEntry(nxt, 0, False))
    out.append(RelocEntry(total, 0, False))
    return out, total


def _parse_subsec(blob: bytes, reloc_off: int, section_ctr: int,
                  section_size: int) -> list[SubsecEntry]:
    if len(blob) < 8:
        raise UnpackError("BKTR subsection table truncated")
    num_buckets = _u32(blob, 4)
    if not 0 < num_buckets <= 0x400:
        raise UnpackError(f"implausible BKTR subsection bucket count "
                          f"{num_buckets}")
    out: list[SubsecEntry] = []
    for b in range(num_buckets):
        base = _BLOCK_HDR + b * _SUB_BUCKET_SIZE
        if base + _BUCKET_HDR > len(blob):
            raise UnpackError("BKTR subsection bucket out of range")
        count = _u32(blob, base + 4)
        if count > _MAX_SUB_ENTRIES:
            raise UnpackError(f"implausible BKTR subsection count {count}")
        bucket_entries: list[SubsecEntry] = []
        for i in range(count):
            pos = base + _BUCKET_HDR + i * _SUB_ENTRY
            if pos + _SUB_ENTRY > len(blob):
                raise UnpackError("BKTR subsection entries truncated")
            offset = _u64(blob, pos)
            ctr = _u32(blob, pos + 8)
            bucket_entries.append(SubsecEntry(offset, ctr))
        out.extend(bucket_entries)
        if b + 1 < num_buckets:
            # hactool: next bucket's first entry bounds this bucket.
            nb = _BLOCK_HDR + (b + 1) * _SUB_BUCKET_SIZE
            if nb + _BUCKET_HDR + 12 > len(blob):
                raise UnpackError("BKTR next subsection bucket truncated")
            nxt_off = _u64(blob, nb + _BUCKET_HDR)
            nxt_ctr = _u32(blob, nb + _BUCKET_HDR + 8)
            out.append(SubsecEntry(nxt_off, nxt_ctr))
    out.append(SubsecEntry(reloc_off, section_ctr & 0xFFFFFFFF))
    out.append(SubsecEntry(section_size, 0))
    return out


class BktrReader:
    """Virtual (fully merged) reader over an update BKTR section.

    Patched pages come from the update NCA; the rest is read from the
    matching base NCA section at the same virtual offset.
    """

    __slots__ = ("_update", "_base", "tables")

    def __init__(self, update: SectionReader, base: SectionReader,
                 tables: BktrTables) -> None:
        self._update = update
        self._base = base
        self.tables = tables

    @property
    def size(self) -> int:
        return self.tables.total_size

    def read_at(self, off: int, size: int) -> bytes:
        if off < 0 or size < 0 or off + size > self.tables.total_size:
            raise UnpackError(
                f"BKTR read out of range: off=0x{off:x} size=0x{size:x}")
        out = bytearray()
        pos = 0
        while pos < size:
            virt = off + pos
            idx = self.tables.reloc_index(virt)
            entry = self.tables.relocs[idx]
            nxt = self.tables.relocs[idx + 1].virt
            span = min(nxt, off + size) - virt
            if span <= 0:
                raise UnpackError(
                    f"BKTR relocation table not progressing at 0x{virt:x}")
            delta = virt - entry.virt
            if entry.is_patch:
                phys = entry.phys + delta
                # Do not cross a subsection boundary (CTR IV changes).
                sidx = self.tables.sub_index(phys)
                sub_next = self.tables.subs[sidx + 1].offset
                take = min(span, sub_next - phys)
                if take <= 0:
                    raise UnpackError(
                        f"BKTR subsection table not progressing at phys 0x{phys:x}")
                ctr_val = self.tables.subs[sidx].ctr
                out += self._update.read_physical(phys, take, ctr_val)
            else:
                take = span
                out += self._base.read_at(entry.phys + delta, take)
            pos += take
        return bytes(out)
