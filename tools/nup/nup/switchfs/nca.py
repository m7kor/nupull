"""NCA3/NCA2 container: header, key derivation, encrypted sections."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from . import crypto
from .errors import UnpackError
from .keys import Keyset
from .reader import ReadAt, read_exact

_HEADER_READ: Final = 0xC00
_SECTOR: Final = 0x200
_FS_HEADER_OFF: Final = 0x400
_FS_HEADER_SIZE: Final = 0x200
_SECTION_ENTRY: Final = 0x10
_CHUNK: Final = 0x100000

CRYPT_NONE: Final = 1
CRYPT_XTS: Final = 2
CRYPT_CTR: Final = 3
CRYPT_BKTR: Final = 4


@dataclass(frozen=True, slots=True)
class Section:
    """One NCA section (present entries only)."""

    index: int
    file_offset: int   # absolute within the NCA
    file_size: int
    crypt: int         # fs header crypt type (1..4)
    part: int          # fs header partition type (0 = romfs, 1 = pfs0)
    fs_type: int       # fs header fs type (2 = pfs0, 3 = romfs)
    fs_header: bytes   # 0x200 bytes
    section_ctr: int   # u64 LE at fs header + 0x140

    @property
    def superblock(self) -> bytes:
        return self.fs_header[8:]

    @property
    def crypt_name(self) -> str:
        return {CRYPT_NONE: "none", CRYPT_XTS: "xts", CRYPT_CTR: "ctr",
                CRYPT_BKTR: "bktr"}.get(self.crypt, "unknown")

    @property
    def is_pfs0(self) -> bool:
        return self.fs_type == 2 and self.part == 1

    @property
    def is_romfs(self) -> bool:
        return self.fs_type == 3 and self.part == 0

    @property
    def pfs0_offset(self) -> int:
        return int.from_bytes(self.superblock[0x38:0x40], "little")

    @property
    def pfs0_size(self) -> int:
        return int.from_bytes(self.superblock[0x40:0x48], "little")

    @property
    def ivfc_level5_offset(self) -> int:
        """logical_offset of IVFC level 5 (the RomFS data)."""
        return int.from_bytes(self.superblock[0x88:0x90], "little")

    @property
    def is_bktr(self) -> bool:
        return self.crypt == CRYPT_BKTR


class SectionReader:
    """Decrypting reader over one section (section-relative offsets)."""

    __slots__ = ("_nca_read", "_key", "_xts_key", "section")

    def __init__(self, nca_read: ReadAt, section: Section, ctr_key: bytes,
                 xts_key: bytes | None) -> None:
        self._nca_read = nca_read
        self.section = section
        self._key = ctr_key
        self._xts_key = xts_key

    @property
    def size(self) -> int:
        return self.section.file_size

    def read_at(self, off: int, size: int) -> bytes:
        if off < 0 or size < 0 or off + size > self.section.file_size:
            raise UnpackError(
                f"section {self.section.index} read out of range: "
                f"off=0x{off:x} size=0x{size:x}")
        if size == 0:
            return b""
        crypt = self.section.crypt
        if crypt == CRYPT_NONE:
            return self._nca_read(self.section.file_offset + off, size)
        if crypt == CRYPT_XTS:
            return self._read_xts(off, size)
        # CTR and (pre-virtual) BKTR physical reads share the plain CTR path;
        # BktrReader wraps BKTR sections for virtual reads.
        return self._read_ctr(off, size)

    def read_physical(self, off: int, size: int, ctr_val: int) -> bytes:
        """BKTR physical read within this section (CTR with ctr_val).

        The caller must keep the range inside one subsection; this method
        additionally clamps to a single 0x10-aligned CTR window per call
        only through chunking, never crossing ctr_val changes.
        """
        sec = self.section
        if sec.crypt != CRYPT_BKTR and sec.crypt != CRYPT_CTR:
            raise UnpackError("physical read on non-BKTR section")
        if off < 0 or size < 0 or off + size > sec.file_size:
            raise UnpackError("BKTR physical read out of range")
        out = bytearray()
        pos = 0
        while pos < size:
            abs_off = sec.file_offset + off + pos
            a = abs_off & ~0xF
            skip = abs_off - a
            n = min(_CHUNK + skip, sec.file_offset + off + size - a)
            if sec.crypt == CRYPT_BKTR:
                iv = crypto.bktr_iv(sec.section_ctr, ctr_val, a)
            else:
                iv = crypto.ctr_iv(sec.section_ctr, a)
            block = crypto.ctr_decrypt(self._key, iv,
                                       self._nca_read(a, n))
            take = min(size - pos, n - skip)
            out += block[skip:skip + take]
            pos += take
        return bytes(out)

    def _read_ctr(self, off: int, size: int) -> bytes:
        sec = self.section
        out = bytearray()
        pos = 0
        while pos < size:
            abs_off = sec.file_offset + off + pos
            a = abs_off & ~0xF
            skip = abs_off - a
            n = min(_CHUNK + skip, sec.file_offset + off + size - a)
            iv = crypto.ctr_iv(sec.section_ctr, a)
            block = crypto.ctr_decrypt(self._key, iv, self._nca_read(a, n))
            take = min(size - pos, n - skip)
            out += block[skip:skip + take]
            pos += take
        return bytes(out)

    def _read_xts(self, off: int, size: int) -> bytes:
        if self._xts_key is None:
            raise UnpackError("XTS section but no XTS key available")
        sec = self.section
        out = bytearray()
        pos = 0
        while pos < size:
            abs_off = sec.file_offset + off + pos
            a = abs_off & ~(_SECTOR - 1)
            skip = abs_off - a
            n = min(_CHUNK + skip, sec.file_offset + off + size - a)
            n -= n % _SECTOR
            if n == 0:
                n = _SECTOR
            sector = a // _SECTOR
            block = crypto.xts_decrypt(self._xts_key, self._nca_read(a, n),
                                       sector)
            take = min(size - pos, n - skip)
            out += block[skip:skip + take]
            pos += take
        return bytes(out)


class Nca:
    """Parsed NCA header with section access."""

    __slots__ = ("read_at", "size", "keyset", "content_type", "keygen",
                 "kaek_ind", "title_id", "rights_id", "label",
                 "sections", "_ctr_key", "_xts_key")

    def __init__(self, read_at: ReadAt, size: int, keyset: Keyset,
                 *, titlekey: bytes | None = None,
                 label: str = "") -> None:
        self.read_at = read_at
        self.size = size
        self.keyset = keyset
        self.label = label or "nca"
        hdr = crypto.xts_decrypt(keyset.header_key,
                                 read_exact(read_at, 0, _HEADER_READ,
                                            f"{self.label} header"),
                                 0)
        magic = hdr[0x200:0x204]
        if magic == b"NCA0":
            raise UnpackError(f"{self.label}: NCA0 (beta) is not supported")
        if magic not in (b"NCA3", b"NCA2"):
            raise UnpackError(f"{self.label}: bad NCA magic {magic!r}")
        self.content_type = hdr[0x205]
        crypto_type = hdr[0x206]
        crypto_type2 = hdr[0x220]
        self.kaek_ind = hdr[0x207]
        self.title_id = int.from_bytes(hdr[0x210:0x218], "little")
        rights_raw = hdr[0x230:0x240]
        self.rights_id = rights_raw.hex() if rights_raw != b"\0" * 16 else None
        keygen = max(crypto_type, crypto_type2)
        if keygen:
            keygen -= 1
        self.keygen = keygen

        # Sections.
        self.sections: list[Section] = []
        for i in range(4):
            pos = 0x240 + i * _SECTION_ENTRY
            media_start = int.from_bytes(hdr[pos:pos + 4], "little")
            media_end = int.from_bytes(hdr[pos + 4:pos + 8], "little")
            if not media_start:
                continue
            if media_end <= media_start:
                raise UnpackError(
                    f"{self.label}: section {i} invalid bounds "
                    f"start={media_start} end={media_end}")
            fss = _FS_HEADER_OFF + i * _FS_HEADER_SIZE
            fs_header = hdr[fss:fss + _FS_HEADER_SIZE]
            self.sections.append(Section(
                index=i,
                file_offset=media_start * _SECTOR,
                file_size=(media_end - media_start) * _SECTOR,
                crypt=fs_header[4],
                part=fs_header[2],
                fs_type=fs_header[3],
                fs_header=fs_header,
                section_ctr=int.from_bytes(fs_header[0x140:0x148],
                                           "little"),
            ))
        if not self.sections:
            raise UnpackError(f"{self.label}: no sections")

        # Keys.
        area = self._decrypt_key_area(hdr)
        if self.rights_id is not None:
            self._ctr_key = self._resolve_titlekey(titlekey)
            self._xts_key = area[0:32] if area is not None else None
        else:
            if area is None:
                raise UnpackError(f"{self.label}: empty key area")
            self._xts_key = area[0:32]
            self._ctr_key = area[32:48]

    # -- keys -----------------------------------------------------------
    def _decrypt_key_area(self, hdr: bytes) -> bytes | None:
        blob = hdr[0x300:0x340]
        if blob == b"\0" * 0x40:
            return None
        kak = self.keyset.key_area_key(self.keygen, self.kaek_ind)
        return crypto.ecb_decrypt(kak, blob)

    def _resolve_titlekey(self, given: bytes | None) -> bytes:
        rid = self.rights_id
        assert rid is not None
        if given is not None:
            return given
        stored = self.keyset.titlekeys.get(rid)
        if stored is None:
            raise UnpackError(
                f"{self.label}: no titlekey for rights id {rid} "
                "(add it to title.keys or unpack the containing NSP)")
        candidates = [stored]
        try:
            dec = crypto.ecb_decrypt(self.keyset.titlekek(self.keygen), stored)
            if dec != stored:
                candidates.append(dec)
        except UnpackError:
            pass
        if len(candidates) == 1:
            return candidates[0]
        for cand in candidates:
            if self._titlekey_looks_right(cand):
                return cand
        # Neither validates structurally: hactool convention (decrypt).
        return candidates[-1]

    def _titlekey_looks_right(self, cand: bytes) -> bool:
        """Check that `cand` decrypts section 0 into a PFS0/RomFS structure."""
        try:
            sec0 = self.sections[0]
        except IndexError:
            return True
        reader = SectionReader(self.read_at, sec0, cand, None)
        try:
            if sec0.is_pfs0:
                return reader.read_at(sec0.pfs0_offset, 4) == b"PFS0"
            if sec0.is_romfs or sec0.is_bktr:
                off = sec0.ivfc_level5_offset
                head = reader.read_at(off, 8) if not sec0.is_bktr else None
                if head is None:
                    return True  # BKTR needs virtual reads; skip validation
                return int.from_bytes(head[:8], "little") == 0x50
        except UnpackError:
            return False
        return True

    # -- accessors ------------------------------------------------------
    def reader(self, section: Section) -> SectionReader:
        return SectionReader(self.read_at, section, self._ctr_key,
                             self._xts_key)

    @property
    def ctr_key(self) -> bytes:
        return self._ctr_key

    def pfs0_sections(self) -> list[Section]:
        return [s for s in self.sections if s.is_pfs0]

    def romfs_section(self) -> Section | None:
        for s in self.sections:
            if s.is_romfs or s.is_bktr:
                return s
        return None
