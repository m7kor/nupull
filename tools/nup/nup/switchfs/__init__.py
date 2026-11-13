"""Switch filesystem dump unpacking: NSP/NSZ/XCI/XCZ/NCA -> standard dump layout."""

from __future__ import annotations

from .errors import CancelledError, UnpackError
from .unpack import Progress, unpack

__all__ = [
    "CancelledError",
    "Progress",
    "UnpackError",
    "unpack",
]
