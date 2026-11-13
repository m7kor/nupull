"""Byte-reader helpers shared by container and NCA section parsers."""

from __future__ import annotations

from typing import Callable, Final

from .errors import UnpackError

# (offset, size) -> exactly `size` bytes or an error.
ReadAt = Callable[[int, int], bytes]

_CHUNK: Final = 0x100000


def read_exact(read_at: ReadAt, off: int, size: int, what: str) -> bytes:
    """Read `size` bytes or raise UnpackError naming the failing structure."""
    try:
        data = read_at(off, size)
    except (OSError, ValueError) as exc:
        raise UnpackError(f"failed reading {what}: {exc}") from exc
    if len(data) != size:
        raise UnpackError(f"truncated {what} at offset 0x{off:x}")
    return data


class SliceReader:
    """A size-limited window over an underlying ReadAt (both offsets absolute)."""

    __slots__ = ("_base", "_read_at", "size")

    def __init__(self, read_at: ReadAt, base: int, size: int) -> None:
        self._read_at = read_at
        self._base = base
        self.size = size

    def read_at(self, off: int, size: int) -> bytes:
        if off < 0 or size < 0 or off + size > self.size:
            raise UnpackError(
                f"read out of range: off=0x{off:x} size=0x{size:x} "
                f"window=0x{self.size:x}")
        return self._read_at(self._base + off, size)


def copy_stream(
    read_at: ReadAt,
    src_off: int,
    size: int,
    write: Callable[[bytes], object],
    *,
    on_progress: Callable[[int], None] | None = None,
    chunk: int = _CHUNK,
) -> None:
    """Copy `size` bytes from read_at into write(), reporting bytes moved."""
    pos = 0
    while pos < size:
        n = min(chunk, size - pos)
        data = read_at(src_off + pos, n)
        if len(data) != n:
            raise UnpackError(f"short read at offset 0x{src_off + pos:x}")
        write(data)
        pos += n
        if on_progress is not None:
            on_progress(n)
