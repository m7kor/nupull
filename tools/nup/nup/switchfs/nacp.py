"""NACP (application control property) parsing.

Total size 0x4000: 16 language records of 0x300 bytes (name[0x200],
publisher[0x100]), display version (0x10 bytes) at 0x3060.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

NACP_SIZE: Final = 0x4000
_LANG_COUNT: Final = 16
_LANG_STRIDE: Final = 0x300
_VERSION_OFF: Final = 0x3060
_VERSION_LEN: Final = 0x10


@dataclass(frozen=True, slots=True)
class Nacp:
    title_name: str
    publisher: str
    display_version: str


def _text(raw: bytes) -> str:
    end = raw.find(b"\0")
    if end >= 0:
        raw = raw[:end]
    return raw.decode("utf-8", "replace")


def parse_nacp(blob: bytes) -> Nacp:
    """Parse an NACP blob; falls back across language slots for the name."""
    if len(blob) < _VERSION_OFF + _VERSION_LEN:
        blob = blob + b"\0" * (_VERSION_OFF + _VERSION_LEN - len(blob))
    name = ""
    publisher = ""
    for i in range(_LANG_COUNT):
        base = i * _LANG_STRIDE
        cand = _text(blob[base:base + 0x200])
        if cand and not name:
            name = cand
            publisher = _text(blob[base + 0x200:base + _LANG_STRIDE])
        if name and i == 0:
            break
    version = _text(blob[_VERSION_OFF:_VERSION_OFF + _VERSION_LEN])
    return Nacp(name, publisher, version)
