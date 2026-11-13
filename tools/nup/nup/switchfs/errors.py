"""Errors raised by the switchfs (NSP/NSZ/XCI/XCZ/NCA) unpacker."""

from __future__ import annotations


class UnpackError(Exception):
    """A user-facing unpack failure (bad input, missing keys, corrupt data)."""


class CancelledError(Exception):
    """Raised when the cooperative cancel callback requests a stop."""
