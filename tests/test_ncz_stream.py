"""Targeted unit tests for NCZ streaming decompression and _RangeReader bounds."""
import io
import unittest
from pathlib import Path

import zstandard

from nup.switchfs.errors import UnpackError
from nup.switchfs.ncz import _RangeReader, _decompress_solid, ncz_to_nca


class TestNczStream(unittest.TestCase):
    def test_range_reader_empty_range(self) -> None:
        dummy_data = b"HELLO_WORLD_12345"
        rr = _RangeReader(lambda off, n: dummy_data[off : off + n], 0, 0)
        self.assertTrue(rr.readable())
        self.assertEqual(rr.read(10), b"")
        self.assertEqual(rr.read(0), b"")
        self.assertEqual(rr.read(-1), b"")

    def test_range_reader_exact_and_after_eof(self) -> None:
        dummy_data = b"0123456789ABCDEF"  # 16 bytes
        rr = _RangeReader(lambda off, n: dummy_data[off : off + n], 0, 16)
        chunk1 = rr.read(10)
        self.assertEqual(chunk1, b"0123456789")
        chunk2 = rr.read(10)
        self.assertEqual(chunk2, b"ABCDEF")
        # Reading after EOF must return empty bytes
        self.assertEqual(rr.read(10), b"")
        self.assertEqual(rr.read(1), b"")
        self.assertEqual(rr.read(), b"")

    def test_range_reader_bounded_slice_probe(self) -> None:
        # Simulate a slice reader that raises UnpackError when reading past boundary 25
        data = b"ABCDEFGHIJKLMNOPQRSTUVWXY"  # 25 bytes
        total_len = len(data)

        def mock_slice_reader(off: int, n: int) -> bytes:
            if off + n > total_len:
                raise UnpackError(f"entry.nca: read out of range 0x{off:x}+0x{n:x}")
            return data[off : off + n]

        # Pass an unknown end (e.g. 1000) so rr requests up to size
        rr = _RangeReader(mock_slice_reader, 0, 1000)
        # Read 10 bytes: within range
        self.assertEqual(rr.read(10), b"ABCDEFGHIJ")
        # Now request 50 bytes: exceeds total_len (only 15 left). Mock slice will raise out-of-range
        # _RangeReader should binary probe and return the remaining 15 bytes
        remaining = rr.read(50)
        self.assertEqual(remaining, b"KLMNOPQRSTUVWXY")
        # Next read must be clean EOF
        self.assertEqual(rr.read(50), b"")

    def test_decompress_solid_small_bounded_stream(self) -> None:
        payload = b"SUPER_SECRET_PAYLOAD_STRING_" * 40
        cctx = zstandard.ZstdCompressor(level=3)
        comp = cctx.compress(payload)

        # Slice that strictly rejects reading past len(comp)
        def strictly_bounded_read(off: int, n: int) -> bytes:
            if off + n > len(comp):
                raise UnpackError("strictly bounded read out of range")
            return comp[off : off + n]

        out_buf = io.BytesIO()
        decomp_size = _decompress_solid(
            strictly_bounded_read,
            0,
            body_end=len(comp),
            out=out_buf,  # type: ignore[arg-type]
            on_progress=None,
            check=lambda: None,
        )
        self.assertEqual(decomp_size, len(payload))
        self.assertEqual(out_buf.getvalue(), payload)


if __name__ == "__main__":
    unittest.main()
