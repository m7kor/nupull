"""Ticket (.tik) parsing for title keys.

Ticket layout (0x2C0 bytes): RSA signature 0x100 + 0x40 padding-ish
region, issuer ASCII at 0x140, AES-128-ECB titlekey at 0x180,
rights id at 0x2A0. The titlekey stored there is encrypted with
titlekek_<keygen>.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnpackError

TIK_SIZE: Final = 0x2C0
_TITLEKEY_OFF: Final = 0x180
_RIGHTS_OFF: Final = 0x2A0


@dataclass(frozen=True, slots=True)
class Ticket:
    rights_id: str  # 32 lowercase hex chars
    enc_titlekey: bytes  # 16 bytes, encrypted with titlekek_<keygen>


def parse_ticket(blob: bytes) -> Ticket:
    if len(blob) < TIK_SIZE:
        raise UnpackError(f"ticket too small ({len(blob)} bytes)")
    rights = blob[_RIGHTS_OFF:_RIGHTS_OFF + 0x10]
    enc = blob[_TITLEKEY_OFF:_TITLEKEY_OFF + 0x10]
    if rights == b"\0" * 0x10 or enc == b"\0" * 0x10:
        raise UnpackError("ticket has empty rights id or titlekey")
    return Ticket(rights.hex(), enc)
