"""NCZ (compressed NCA, as stored in NSZ/XCZ) -> temporary plain .nca.

Format: 0x4000 raw NCA header, then b"NCZSECTN", a section count, and
per-section {offset, size, crypto_type, pad} i64s plus key[16] and
counter[16]. The body is either a solid zstd stream or an NCZBLOCK
series of independent frames. After decompression the CTR/BKTR
sections are re-encrypted in place so the result is a normal NCA.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Callable, Final, IO, cast

import zstandard

from . import crypto
from .errors import CancelledError, UnpackError
from .reader import ReadAt

_HEADER: Final = 0x4000
_MAGIC: Final = b"NCZSECTN"
_BLOCK_MAGIC: Final = b"NCZBLOCK"
_CHUNK: Final = 0x100000


class _RangeReader(io.RawIOBase):
    """Minimal read() adapter over a ReadAt window for zstandard."""

    __slots__ = ("_read_at", "_pos", "_end")

    def __init__(self, read_at: ReadAt, pos: int, end: int) -> None:
        self._read_at = read_at
        self._pos = pos
        self._end = end

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            size = self._end - self._pos
        size = min(size, self._end - self._pos)
        if size <= 0:
            return b""
        data = self._read_at(self._pos, size)
        self._pos += len(data)
        return data


def is_ncz(read_at: ReadAt, nca_off: int, nca_size: int) -> bool:
    """True when the NCA-shaped region is actually NCZ-compressed."""
    if nca_size < _HEADER + 8:
        return False
    try:
        return read_at(nca_off + _HEADER, 8) == _MAGIC
    except (OSError, ValueError, UnpackError):
        return False


def ncz_to_nca(
    read_at: ReadAt,
    nca_off: int,
    dest: Path,
    *,
    on_progress: Callable[[int], None] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> int:
    """Convert an NCZ region to a plain NCA file at `dest`.

    Returns the decompressed NCA size.
    """
    def check() -> None:
        if cancel is not None and cancel():
            raise CancelledError()

    header = read_at(nca_off, _HEADER)
    if len(header) != _HEADER:
        raise UnpackError("NCZ header truncated")
    pos = _HEADER
    magic = read_at(nca_off + pos, 8)
    if magic != _MAGIC:
        raise UnpackError(f"bad NCZ magic {magic!r}")
    pos += 8
    count_raw = read_at(nca_off + pos, 8)
    if len(count_raw) != 8:
        raise UnpackError("NCZ section count truncated")
    count = int.from_bytes(count_raw, "little", signed=True)
    pos += 8
    if not 0 < count <= 64:
        raise UnpackError(f"implausible NCZ section count {count}")
    sections: list[tuple[int, int, int, bytes, bytes]] = []
    for _ in range(count):
        blob = read_at(nca_off + pos, 56)
        if len(blob) != 56:
            raise UnpackError("NCZ section table truncated")
        s_offset = int.from_bytes(blob[0:8], "little", signed=True)
        s_size = int.from_bytes(blob[8:16], "little", signed=True)
        s_crypto = int.from_bytes(blob[16:24], "little", signed=True)
        if s_offset < 0 or s_size < 0:
            raise UnpackError(f"negative NCZ section bounds (offset={s_offset}, size={s_size})")
        sections.append((s_offset, s_size, s_crypto, blob[24:40],
                         blob[40:56]))
        pos += 56

    # Validate section boundaries and non-overlapping ranges
    sorted_sections = sorted((s_offset, s_size, s_crypto, k, c) for s_offset, s_size, s_crypto, k, c in sections)
    for i in range(len(sorted_sections)):
        s_off, s_sz = sorted_sections[i][0], sorted_sections[i][1]
        if s_off + s_sz > (128 << 30):
            raise UnpackError(f"implausible NCZ section range [{s_off}:{s_off + s_sz}]")
        if i + 1 < len(sorted_sections):
            next_off = sorted_sections[i + 1][0]
            if s_off + s_sz > next_off:
                raise UnpackError(
                    f"overlapping NCZ sections: [{s_off}:{s_off + s_sz}] overlaps with next at {next_off}"
                )

    body_off = nca_off + pos
    body_magic = read_at(body_off, 8)
    body_start = pos + (8 if body_magic == _BLOCK_MAGIC else 0)

    written = 0
    try:
        with open(dest, "wb") as out:
            out.write(header)
            written = _HEADER
            try:
                if body_magic == _BLOCK_MAGIC:
                    written += _decompress_blocks(
                        read_at, nca_off + body_start, out,
                        on_progress=on_progress, check=check)
                else:
                    written += _decompress_solid(
                        read_at, nca_off + body_start,
                        on_progress=on_progress, check=check, out=out)
            except zstandard.ZstdError as exc:
                raise UnpackError(f"NCZ zstd decode failed: {exc}") from exc
            # Re-encrypt CTR/BKTR sections in place.
            for s_offset, s_size, s_crypto, key, counter in sections:
                if s_crypto not in (3, 4):
                    continue
                start = max(s_offset, _HEADER)
                end = min(s_offset + s_size, written)
                if end <= start:
                    continue
                _encrypt_range(dest, start, end, key, counter,
                               on_progress=on_progress, check=check)
    except BaseException:
        if dest.is_file():
            dest.unlink(missing_ok=True)
        raise
    return written


def _decompress_solid(
    read_at: ReadAt,
    body_off: int,
    *,
    out: io.BufferedWriter,
    on_progress: Callable[[int], None] | None,
    check: Callable[[], None],
    max_size: int = 128 << 30,
) -> int:
    src = _RangeReader(read_at, body_off, body_off + (1 << 62))
    dctx = zstandard.ZstdDecompressor()
    reader = dctx.stream_reader(cast(IO[bytes], src))
    total = 0
    try:
        while True:
            check()
            data = reader.read(_CHUNK)
            if not data:
                break
            out.write(data)
            total += len(data)
            if total > max_size:
                raise UnpackError(f"solid NCZ stream exceeds maximum allowed size ({total} > {max_size})")
            if on_progress is not None:
                on_progress(len(data))
    finally:
        reader.close()  # type: ignore[no-untyped-call]
    return total


def _decompress_blocks(
    read_at: ReadAt,
    body_off: int,
    out: io.BufferedWriter,
    *,
    on_progress: Callable[[int], None] | None,
    check: Callable[[], None],
) -> int:
    meta = read_at(body_off, 4 + 4 + 8)
    if len(meta) != 16:
        raise UnpackError("NCZBLOCK header truncated")
    # version, type, unused, block_size_exp
    block_size_exp = meta[3]
    block_count = int.from_bytes(meta[4:8], "little", signed=True)
    decompressed_size = int.from_bytes(meta[8:16], "little", signed=True)
    if not 0 < block_count <= 1 << 24 or not 0 <= block_size_exp <= 26:
        raise UnpackError("implausible NCZBLOCK header")
    if decompressed_size < 0 or decompressed_size > (128 << 30):
        raise UnpackError(f"implausible NCZBLOCK decompressed size {decompressed_size}")
    block_size = 1 << block_size_exp
    min_expected = (block_count - 1) * block_size + 1
    max_expected = block_count * block_size
    if not (min_expected <= decompressed_size <= max_expected):
        raise UnpackError(
            f"NCZBLOCK block_count {block_count} (block_size {block_size}) "
            f"inconsistent with decompressed_size {decompressed_size}"
        )
    sizes_blob = read_at(body_off + 16, block_count * 4)
    if len(sizes_blob) != block_count * 4:
        raise UnpackError("NCZBLOCK size table truncated")
    sizes = [int.from_bytes(sizes_blob[i * 4:i * 4 + 4], "little",
                            signed=True)
             for i in range(block_count)]
    src_pos = body_off + 16 + block_count * 4
    remaining = decompressed_size
    dctx = zstandard.ZstdDecompressor()
    for bs in sizes:
        check()
        if bs < 0 or bs > block_size * 2 + 4096:
            raise UnpackError(f"implausible NCZBLOCK block size {bs}")
        out_size = min(block_size, remaining)
        if out_size > (64 << 20):
            raise UnpackError(f"excessive NCZBLOCK frame size {out_size}")
        comp = read_at(src_pos, bs)
        if len(comp) != bs:
            raise UnpackError("NCZBLOCK data truncated")
        src_pos += bs
        if bs < out_size:
            dobj = dctx.decompressobj()
            data = dobj.decompress(comp) + dobj.flush()
            if len(data) != out_size:
                raise UnpackError(
                    f"NCZBLOCK frame size mismatch ({len(data)} != "
                    f"{out_size})")
        else:
            data = comp
        out.write(data)
        remaining -= out_size
        if on_progress is not None:
            on_progress(len(data))
    if remaining != 0:
        raise UnpackError("NCZBLOCK stream shorter than declared size")
    return decompressed_size


def _encrypt_range(
    path: Path,
    start: int,
    end: int,
    key: bytes,
    counter: bytes,
    *,
    on_progress: Callable[[int], None] | None,
    check: Callable[[], None],
) -> None:
    """CTR re-encrypt [start, end) in place: IV = counter[0:8] ++ BE(abs>>4)."""
    with open(path, "r+b") as f:
        pos = start & ~0xF
        while pos < end:
            check()
            n = min(_CHUNK, end - pos)
            f.seek(pos)
            data = f.read(n)
            if len(data) != n:
                raise UnpackError("NCA re-encrypt short read")
            iv = counter[:8] + (pos >> 4).to_bytes(8, "big")
            out = crypto.ctr_decrypt(key, iv, data)
            f.seek(pos)
            f.write(out)
            pos += n
            if on_progress is not None:
                on_progress(n)
