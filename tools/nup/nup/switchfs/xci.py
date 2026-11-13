"""XCI gamecard image: CardHeader, root HFS0, secure partition."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final

from .errors import UnpackError
from .hfs0 import Hfs0Entry, parse_hfs0
from .reader import ReadAt

_MAGIC_OFF_A: Final = 0x100     # header struct at file 0 (hactool layout)
_MAGIC_OFF_B: Final = 0x1100    # CardHeader at 0x1000 (switchbrew layout)
_MAGIC: Final = b"HEAD"


@dataclass(frozen=True, slots=True)
class XciPartition:
    name: str
    offset: int  # absolute in file
    size: int


def _detect_header(read_at: ReadAt) -> tuple[int, int, int]:
    """Return (header_base, hfs0_offset, hfs0_header_size)."""
    for base in (0, 0x1000):
        blob = read_at(base, 0x200)
        if blob[0x100:0x104] == _MAGIC:
            hfs0_offset = int.from_bytes(blob[0x130:0x138], "little")
            hfs0_size = int.from_bytes(blob[0x138:0x140], "little")
            if 0 < hfs0_offset < (1 << 48) and hfs0_size >= 0x10:
                return base, hfs0_offset, hfs0_size
    raise UnpackError("XCI header (HEAD) not found")


class Xci:
    """Parsed XCI root/secure partition structure."""

    __slots__ = ("path", "read_at", "size", "hfs0_offset", "secure",
                 "partitions")

    def __init__(self, path: Path, read_at: ReadAt, size: int) -> None:
        self.path = path
        self.read_at = read_at
        self.size = size
        _base, hfs0_offset, hfs0_size = _detect_header(read_at)
        self.hfs0_offset = hfs0_offset
        root = parse_hfs0(lambda o, n: read_at(hfs0_offset + o, n))
        self.partitions = [
            XciPartition(e.name, hfs0_offset + e.offset, e.size)
            for e in root
        ]
        secure = next((p for p in self.partitions if p.name == "secure"),
                      None)
        if secure is None:
            raise UnpackError("XCI has no secure partition")
        self.secure = secure

    def secure_entries(self) -> list[Hfs0Entry]:
        """Entries of the secure partition HFS0 (offsets absolute)."""
        sec = self.secure
        return parse_hfs0(lambda o, n: self.read_at(sec.offset + o, n))
