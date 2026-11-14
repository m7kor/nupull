"""Controlled process memory benchmark for Streaming NSP Exporter."""
import gc
import hashlib
import os
import shutil
from pathlib import Path
import tempfile
import time
import tracemalloc

import psutil

from nup import format as F
from nup.export import export_container
from nup.pack import pack
from nup.switchfs.keys import Keyset


def benchmark_nsp_export(workload_mb: int = 100) -> dict:
    work_dir = Path(tempfile.mkdtemp(prefix="nup_bench_exp_"))
    try:
        keys_file = work_dir / "test.keys"
        keys_file.write_text(
            f"header_key = {bytes(range(32)).hex()}\n"
            f"key_area_key_application_00 = {bytes(range(16, 32)).hex()}\n"
        )
        os.environ["NUP_KEYS"] = str(keys_file)

        # 1. Create a synthetic dump with mixed compressible and random data
        dump_dir = work_dir / "dump"
        (dump_dir / "exefs").mkdir(parents=True, exist_ok=True)
        (dump_dir / "romfs").mkdir(parents=True, exist_ok=True)
        (dump_dir / "exefs" / "main").write_bytes(b"NSO0" + b"\0" * 0x3C + b"\x11" * 0x20)
        (dump_dir / "exefs" / "main.npdm").write_bytes(b"ACI0" + b"\0" * 0x0C + (0x0100999900000000).to_bytes(8, "little") + b"\0" * 0x28)

        # Populate romfs with workload_mb of data
        chunk_pattern = os.urandom(64 * 1024) + (b"COMPRESSIBLE_BLOCK_" * 1024)  # 128 KB
        file_size = workload_mb * 1024 * 1024
        with open(dump_dir / "romfs" / "game_asset.dat", "wb") as fh:
            written = 0
            while written < file_size:
                to_write = min(len(chunk_pattern), file_size - written)
                fh.write(chunk_pattern[:to_write])
                written += to_write

        # 2. Pack to NUP
        nup_path = work_dir / "game.nup"
        pack(nup_path, dump_dir, level=1)

        # 3. Clean up RAM and measure baseline
        gc.collect()
        gc.collect()
        proc = psutil.Process(os.getpid())
        base_rss = proc.memory_info().rss
        tracemalloc.start()

        # Monitor peak memory in a high-frequency sampling thread
        peak_rss = base_rss
        stop_sampling = False

        def sampler():
            nonlocal peak_rss
            while not stop_sampling:
                try:
                    r = proc.memory_info().rss
                    if r > peak_rss:
                        peak_rss = r
                except Exception:
                    break
                time.sleep(0.002)

        import threading
        t = threading.Thread(target=sampler, daemon=True)
        t.start()

        t0 = time.perf_counter()
        exp_dir = work_dir / "exported_nsp"
        res = export_container(nup_path, exp_dir, fmt="nsp", keys_path=keys_file)
        elapsed = time.perf_counter() - t0

        stop_sampling = True
        t.join(timeout=1.0)
        curr_rss = proc.memory_info().rss
        if curr_rss > peak_rss:
            peak_rss = curr_rss

        heap_current, heap_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        exported_nsps = list(exp_dir.glob("*.nsp"))
        has_nsp = len(exported_nsps) > 0 and exported_nsps[0].stat().st_size > 0

        rss_delta_mb = (peak_rss - base_rss) / (1024 * 1024)
        heap_peak_mb = heap_peak / (1024 * 1024)

        return {
            "workload_mb": workload_mb,
            "elapsed_s": elapsed,
            "throughput_mbs": workload_mb / elapsed if elapsed > 0 else 0,
            "base_rss_mb": base_rss / (1024 * 1024),
            "peak_rss_mb": peak_rss / (1024 * 1024),
            "rss_delta_mb": rss_delta_mb,
            "heap_peak_mb": heap_peak_mb,
            "valid_nsp": has_nsp,
        }
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    print("================================================================================")
    print(" STREAMING NSP EXPORTER MEMORY & PERFORMANCE BENCHMARK")
    print("================================================================================")
    for size in [50, 150]:
        res = benchmark_nsp_export(size)
        print(f"Workload: {res['workload_mb']:>3} MiB | Time: {res['elapsed_s']:>5.2f}s | Speed: {res['throughput_mbs']:>6.1f} MiB/s | "
              f"Base RSS: {res['base_rss_mb']:>5.1f} MiB | Peak RSS: {res['peak_rss_mb']:>5.1f} MiB | "
              f"RSS Delta: {res['rss_delta_mb']:>5.2f} MiB | Heap Peak: {res['heap_peak_mb']:>4.2f} MiB | Valid: {res['valid_nsp']}")
    print("================================================================================")
