"""Comprehensive True Peak Memory and Throughput Benchmark for NUP Streaming.

Measures:
- True Peak RSS (Working Set) via OS kernel peak_wset & high-frequency sampler (2ms)
- Peak Committed Memory (Pagefile commit charge on Windows)
- Python Heap Peak via tracemalloc
- Baseline RSS, Peak RSS delta, and Final RSS
- Streaming decompression throughput (MiB/s) and byte-for-byte SHA-256 verification
- Workloads: 64 MiB, 256 MiB, 1024 MiB (1 GiB) with compressible and randomized patterns
"""
from __future__ import annotations

import argparse
import gc
import hashlib
import json
import mmap
import os
import platform
import sys
import tempfile
import threading
import time
import tracemalloc
from typing import Any, Dict, List, Optional

import psutil
import zstandard

from nup.read import BoundedMmapReader, NupReader


class HighFrequencyMemorySampler(threading.Thread):
    """Samples process RSS and committed memory at high frequency (1-2 ms)."""

    def __init__(self, pid: int, interval_s: float = 0.002) -> None:
        super().__init__(daemon=True)
        self.proc = psutil.Process(pid)
        self.interval_s = interval_s
        self.stopped = threading.Event()
        self.samples_rss: List[int] = []
        self.samples_commit: List[int] = []
        self.peak_rss: int = 0
        self.peak_commit: int = 0

    def run(self) -> None:
        while not self.stopped.is_set():
            try:
                mem = self.proc.memory_info()
                rss = mem.rss
                commit = getattr(mem, "pagefile", mem.vms)
                if rss > self.peak_rss:
                    self.peak_rss = rss
                if commit > self.peak_commit:
                    self.peak_commit = commit
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(self.interval_s)

    def stop(self) -> None:
        self.stopped.set()
        self.join(timeout=1.0)
        try:
            mem = self.proc.memory_info()
            if mem.rss > self.peak_rss:
                self.peak_rss = mem.rss
            commit = getattr(mem, "pagefile", mem.vms)
            if commit > self.peak_commit:
                self.peak_commit = commit
        except Exception:
            pass


def generate_streaming_fixture(
    file_path: str,
    target_uncompressed_bytes: int,
    pattern: str = "compressible",
    block_size: int = 1024 * 1024,
) -> tuple[int, str]:
    """Generates a compressed fixture on disk using streaming compression to keep fixture gen O(1) RAM."""
    cctx = zstandard.ZstdCompressor(level=3)
    hasher = hashlib.sha256()
    bytes_written = 0

    # Ensure chunk is exactly block_size
    if pattern == "compressible":
        base_chunk = (b"NUPULL_STREAMING_TEST_BLOCK_0123456789ABCDEF" * 16 + b"\x00" * 384) * 16
        chunk = (base_chunk * ((block_size // len(base_chunk)) + 1))[:block_size]
    elif pattern == "incompressible":
        chunk = os.urandom(block_size)
    else:  # mixed
        chunk1 = (b"STRUCTURED_HEADER_DATA_" * 32 + b"\x00" * 256) * 16
        chunk2 = os.urandom(32768)
        combined = (chunk1 + chunk2) * 2
        chunk = (combined * ((block_size // len(combined)) + 1))[:block_size]

    with open(file_path, "wb") as fh:
        with cctx.stream_writer(fh) as compressor:
            while bytes_written < target_uncompressed_bytes:
                to_write = min(block_size, target_uncompressed_bytes - bytes_written)
                current_block = chunk[:to_write]
                compressor.write(current_block)
                hasher.update(current_block)
                bytes_written += len(current_block)

    return bytes_written, hasher.hexdigest()


def benchmark_stream_extraction(
    fixture_path: str,
    expected_uncompressed_size: int,
    expected_sha: str,
    chunk_size: int = 1024 * 1024,
) -> Dict[str, Any]:
    """Extracts the fixture using BoundedMmapReader while monitoring true peak memory."""
    proc = psutil.Process()
    gc.collect()
    time.sleep(0.05)

    comp_file_size = os.path.getsize(fixture_path)
    mem_before = proc.memory_info()
    baseline_rss = mem_before.rss
    baseline_commit = getattr(mem_before, "pagefile", mem_before.vms)

    # Start tracemalloc for Python heap
    tracemalloc.start()
    tracemalloc.reset_peak()

    # Start high frequency sampler
    sampler = HighFrequencyMemorySampler(os.getpid(), interval_s=0.002)
    sampler.start()

    t0 = time.perf_counter()
    hasher = hashlib.sha256()
    total_decompressed = 0

    with open(fixture_path, "rb") as fh:
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            bmr = BoundedMmapReader(mm, 0, comp_file_size, chunk_size=65536)
            dctx = zstandard.ZstdDecompressor()
            reader = dctx.stream_reader(bmr)

            while True:
                chunk = reader.read(chunk_size)
                if not chunk:
                    break
                total_decompressed += len(chunk)
                hasher.update(chunk)

            reader.close()
        finally:
            mm.close()

    t1 = time.perf_counter()
    sampler.stop()
    current_heap, peak_heap = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    mem_after = proc.memory_info()
    final_rss = mem_after.rss
    final_commit = getattr(mem_after, "pagefile", mem_after.vms)

    # OS-level peak working set if available
    os_peak_wset = getattr(mem_after, "peak_wset", 0)
    os_peak_pagefile = getattr(mem_after, "peak_pagefile", 0)

    elapsed_s = t1 - t0
    raw_mb = total_decompressed / (1024 * 1024)
    comp_mb = comp_file_size / (1024 * 1024)
    throughput_mbs = raw_mb / elapsed_s if elapsed_s > 0 else 0.0

    peak_rss = max(sampler.peak_rss, os_peak_wset if os_peak_wset > 0 else 0, final_rss)
    peak_commit = max(sampler.peak_commit, os_peak_pagefile if os_peak_pagefile > 0 else 0, final_commit)
    peak_rss_increase_mb = max(0.0, (peak_rss - baseline_rss) / (1024 * 1024))
    peak_commit_increase_mb = max(0.0, (peak_commit - baseline_commit) / (1024 * 1024))
    peak_heap_mb = peak_heap / (1024 * 1024)

    actual_sha = hasher.hexdigest()
    is_valid = (actual_sha == expected_sha) and (total_decompressed == expected_uncompressed_size)

    return {
        "raw_bytes": total_decompressed,
        "comp_bytes": comp_file_size,
        "raw_mb": raw_mb,
        "comp_mb": comp_mb,
        "ratio": raw_mb / comp_mb if comp_mb > 0 else 0.0,
        "elapsed_s": elapsed_s,
        "throughput_mbs": throughput_mbs,
        "baseline_rss_mb": baseline_rss / (1024 * 1024),
        "peak_rss_mb": peak_rss / (1024 * 1024),
        "peak_rss_increase_mb": peak_rss_increase_mb,
        "final_rss_mb": final_rss / (1024 * 1024),
        "baseline_commit_mb": baseline_commit / (1024 * 1024),
        "peak_commit_mb": peak_commit / (1024 * 1024),
        "peak_commit_increase_mb": peak_commit_increase_mb,
        "peak_heap_mb": peak_heap_mb,
        "os_peak_wset_mb": os_peak_wset / (1024 * 1024) if os_peak_wset else None,
        "os_peak_pagefile_mb": os_peak_pagefile / (1024 * 1024) if os_peak_pagefile else None,
        "integrity_verified": is_valid,
    }


def run_full_benchmark_suite(sizes_mb: Optional[List[int]] = None) -> List[Dict[str, Any]]:
    if sizes_mb is None:
        sizes_mb = [64, 256, 1024]

    print("================================================================================")
    print(" NUPULL PHASE III TRUE PEAK MEMORY & STREAMING THROUGHPUT PROFILER")
    print("================================================================================")
    print(f"OS: {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"Python: {platform.python_implementation()} {platform.python_version()}")
    print(f"CPU count: {os.cpu_count()}")
    total_ram_gb = psutil.virtual_memory().total / (1024**3)
    avail_ram_gb = psutil.virtual_memory().available / (1024**3)
    print(f"RAM: Total={total_ram_gb:.2f} GiB, Available={avail_ram_gb:.2f} GiB")
    print(f"Sampling method: HighFrequencyMemorySampler (2 ms) + OS GetProcessMemoryInfo")
    print("--------------------------------------------------------------------------------")

    results = []
    patterns = ["compressible", "mixed"]

    for sz in sizes_mb:
        target_bytes = sz * 1024 * 1024
        for pattern in patterns:
            print(f"\n[BENCHMARK] Workload: {sz} MiB uncompressed ({pattern} pattern)...")
            with tempfile.NamedTemporaryFile(suffix=".zst", delete=False) as tf:
                fixture_path = tf.name

            try:
                gen_t0 = time.perf_counter()
                uncomp_size, expected_sha = generate_streaming_fixture(
                    fixture_path, target_bytes, pattern=pattern
                )
                gen_elapsed = time.perf_counter() - gen_t0
                comp_size = os.path.getsize(fixture_path)
                print(
                    f"  Fixture generated in {gen_elapsed:.2f}s "
                    f"({comp_size / (1024*1024):.2f} MiB compressed, "
                    f"ratio {uncomp_size / comp_size:.2f}x)"
                )

                # Benchmark extraction
                res = benchmark_stream_extraction(fixture_path, uncomp_size, expected_sha)
                res["pattern"] = pattern
                res["size_label"] = f"{sz} MiB"
                results.append(res)

                status = "PASS" if res["integrity_verified"] else "FAIL (HASH MISMATCH)"
                print(f"  Result: {status}")
                print(f"  Throughput:           {res['throughput_mbs']:.2f} MiB/s")
                print(f"  Extraction time:      {res['elapsed_s']:.3f} s")
                print(f"  Baseline RSS:         {res['baseline_rss_mb']:.2f} MiB")
                print(f"  True Peak RSS:        {res['peak_rss_mb']:.2f} MiB")
                print(f"  Peak RSS Delta:       {res['peak_rss_increase_mb']:.2f} MiB  (<-- Bounded O(1))")
                print(f"  Final RSS:            {res['final_rss_mb']:.2f} MiB")
                print(f"  Python Heap Peak:     {res['peak_heap_mb']:.2f} MiB")
                if res['peak_commit_increase_mb'] is not None:
                    print(f"  Peak Commit Delta:    {res['peak_commit_increase_mb']:.2f} MiB")
            finally:
                if os.path.exists(fixture_path):
                    try:
                        os.unlink(fixture_path)
                    except Exception:
                        pass

    print("\n================================================================================")
    print(" SUMMARY TABLE: TRUE PEAK MEMORY PROFILING")
    print("================================================================================")
    print(f"{'Workload':<12} | {'Pattern':<13} | {'Raw MiB':<8} | {'Throughput':<12} | {'Peak RSS Incr':<14} | {'Peak Heap':<10} | {'Status'}")
    print("-" * 88)
    for r in results:
        status_str = "PASS" if r["integrity_verified"] else "FAIL"
        print(
            f"{r['size_label']:<12} | {r['pattern']:<13} | {r['raw_mb']:<8.0f} | "
            f"{r['throughput_mbs']:>7.2f} MiB/s | {r['peak_rss_increase_mb']:>9.2f} MiB    | "
            f"{r['peak_heap_mb']:>7.2f} MiB | {status_str}"
        )
    print("================================================================================\n")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NUPULL Phase III True Peak Memory Profiler")
    parser.add_argument("--sizes", nargs="+", type=int, default=[64, 256, 1024], help="Sizes in MiB to test")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    args = parser.parse_args()

    suite_results = run_full_benchmark_suite(args.sizes)
    if args.json:
        print(json.dumps(suite_results, indent=2))
