"""Performance and memory benchmark for NUP bounded streaming extraction."""
import hashlib
import io
import mmap
import os
import tempfile
import time
import psutil
import zstandard

from nup import format as F
from nup.read import BoundedMmapReader, NupReader


def run_benchmark():
    proc = psutil.Process()
    print("=== NUPULL PHASE II PERFORMANCE & MEMORY STREAMING BENCHMARK ===")
    
    # 1. Generate realistic test payloads
    payload_mb = 64
    raw_bytes = os.urandom(1024 * 1024) * payload_mb
    raw_sha = hashlib.sha256(raw_bytes).hexdigest()
    
    # Compress with zstandard
    cctx = zstandard.ZstdCompressor(level=3)
    comp_bytes = cctx.compress(raw_bytes)
    
    raw_size_mb = len(raw_bytes) / (1024 * 1024)
    comp_size_mb = len(comp_bytes) / (1024 * 1024)
    ratio = len(raw_bytes) / len(comp_bytes)
    print(f"Input uncompressed size: {raw_size_mb:.2f} MiB")
    print(f"Compressed zstd size:    {comp_size_mb:.2f} MiB")
    print(f"Compression ratio:       {ratio:.2f}x")
    
    # Write compressed payload to disk to mmap
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(comp_bytes)
        tf_path = tf.name
        
    try:
        # Measure BoundedMmapReader streaming
        rss_start = proc.memory_info().rss
        t0 = time.perf_counter()
        
        with open(tf_path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            bmr = BoundedMmapReader(mm, 0, len(comp_bytes), chunk_size=65536)
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(bmr)
            
            # Stream to null sink calculating SHA-256
            hasher = hashlib.sha256()
            total_out = 0
            while True:
                chunk = reader.read(1024 * 1024)
                if not chunk:
                    break
                total_out += len(chunk)
                hasher.update(chunk)
                
            reader.close()
            rss_peak = proc.memory_info().rss
            mm.close()
            
        t1 = time.perf_counter()
        elapsed = t1 - t0
        throughput = raw_size_mb / elapsed if elapsed > 0 else 0
        computed_sha = hasher.hexdigest()
        rss_delta_mb = (rss_peak - rss_start) / (1024 * 1024)
        
        print(f"Extraction elapsed time: {elapsed:.3f} s")
        print(f"Decompression throughput: {throughput:.2f} MiB/s")
        print(f"Process RSS delta:       {rss_delta_mb:.2f} MiB")
        print(f"Hash verification:       {'PASSED (byte-for-byte)' if computed_sha == raw_sha else 'FAILED'}")
        print("==================================================================")
        return {
            "raw_mb": raw_size_mb,
            "comp_mb": comp_size_mb,
            "ratio": ratio,
            "elapsed": elapsed,
            "throughput": throughput,
            "rss_delta": rss_delta_mb,
            "hash_match": computed_sha == raw_sha
        }
    finally:
        os.unlink(tf_path)


if __name__ == "__main__":
    run_benchmark()
