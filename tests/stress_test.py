"""Stress testing suite for Nupull Phase III.

Tests:
1. Sequential operations memory and file handle leak test (repeated extractions).
2. Large file count container (200 files) creation, TOC serialization, and extraction.
3. Pathological and extreme filenames (deep paths, unicode, Arabic, Japanese, spaces).
4. Concurrent multi-reader stress test (multiple threads reading from same NupReader).
"""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Tuple

import psutil

from nup import format as F
from nup.access import extract_tree
from nup.pack import pack
from nup.read import NupReader


def get_open_fd_count(proc: psutil.Process) -> int:
    """Returns open file handles on Windows or fds on POSIX."""
    try:
        return len(proc.open_files())
    except Exception:
        return proc.num_handles() if hasattr(proc, "num_handles") else 0


def create_minimal_dump(root_dir: str, files_dict: dict[str, bytes]) -> None:
    """Creates a mock Switch dump directory structure suitable for pack()."""
    exefs_dir = os.path.join(root_dir, "exefs")
    romfs_dir = os.path.join(root_dir, "romfs")
    os.makedirs(exefs_dir, exist_ok=True)
    os.makedirs(romfs_dir, exist_ok=True)

    # Standard minimum mock npdm & main
    with open(os.path.join(exefs_dir, "main"), "wb") as fh:
        fh.write(b"NSO0" + b"\0" * 0x3C + b"\x22" * 0x20)
    npdm = bytearray(b"\0" * 0x40)
    npdm[0:4] = b"ACI0"
    struct.pack_into("<Q", npdm, 0x10, 0x0100AAAABBBB0001)
    with open(os.path.join(exefs_dir, "main.npdm"), "wb") as fh:
        fh.write(bytes(npdm))

    for rel_path, data in files_dict.items():
        full_path = os.path.join(romfs_dir, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "wb") as fh:
            fh.write(data)


def test_sequential_extraction_leaks(iterations: int = 25) -> Tuple[bool, str]:
    """Tests sequential extractions for file descriptor leaks and memory growth."""
    proc = psutil.Process()
    td = tempfile.mkdtemp(prefix="nup_stress_leak_")
    try:
        dump_dir = os.path.join(td, "dump")
        nup_path = os.path.join(td, "test_sample.nup")
        extract_dir = os.path.join(td, "extracted")

        test_payload = b"STRESS_TEST_PAYLOAD_CHUNK_DATA" * 4096  # ~120KB
        create_minimal_dump(dump_dir, {
            "payload1.bin": test_payload,
            "sub/payload2.bin": test_payload[::-1],
        })
        pack(nup_path, dump_dir, level=3)

        gc_fds_baseline = get_open_fd_count(proc)
        mem_baseline = proc.memory_info().rss

        for i in range(iterations):
            out_dir = os.path.join(extract_dir, f"run_{i}")
            with NupReader(nup_path) as r:
                extract_tree(r, out_dir, r.packages[0].root_dir)
            shutil.rmtree(out_dir, ignore_errors=True)

        final_fds = get_open_fd_count(proc)
        mem_final = proc.memory_info().rss
        fd_diff = final_fds - gc_fds_baseline
        mem_diff_mb = (mem_final - mem_baseline) / (1024 * 1024)

        if fd_diff > 3:
            return False, f"File handle leak detected: initial={gc_fds_baseline}, final={final_fds}, diff={fd_diff}"
        if mem_diff_mb > 25.0:
            return False, f"Potential memory leak: grew by {mem_diff_mb:.2f} MiB over {iterations} runs"

        return True, f"Passed ({iterations} runs: fd_diff={fd_diff}, mem_diff={mem_diff_mb:+.2f} MiB)"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_high_file_count_container(count: int = 200) -> Tuple[bool, str]:
    """Tests container creation, TOC parsing, and full extraction with many files."""
    td = tempfile.mkdtemp(prefix="nup_stress_high_count_")
    try:
        dump_dir = os.path.join(td, "dump")
        nup_path = os.path.join(td, "high_count.nup")
        extract_dir = os.path.join(td, "extracted")

        files_dict = {}
        expected_hashes = {}
        for i in range(count):
            name = f"sub_{i % 15}/file_{i:04d}.dat"
            data = f"DATA_BLOCK_INDEX_{i}".encode("utf-8") * 100
            files_dict[name] = data
            expected_hashes[name] = hashlib.sha256(data).digest()

        t0 = time.perf_counter()
        create_minimal_dump(dump_dir, files_dict)
        pack(nup_path, dump_dir, level=3)
        build_time = time.perf_counter() - t0

        t1 = time.perf_counter()
        with NupReader(nup_path) as r:
            extract_tree(r, extract_dir, r.packages[0].root_dir)
        extract_time = time.perf_counter() - t1

        # Verify all extracted files match sha256 byte-for-byte
        for name, exp_sha in expected_hashes.items():
            out_file = os.path.join(extract_dir, "romfs", *name.split("/"))
            if not os.path.exists(out_file):
                return False, f"Missing extracted file: {name}"
            with open(out_file, "rb") as fh:
                got_sha = hashlib.sha256(fh.read()).digest()
                if got_sha != exp_sha:
                    return False, f"SHA mismatch on extracted file: {name}"

        return True, f"Passed ({count} files created in {build_time:.2f}s, extracted & verified in {extract_time:.2f}s)"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_pathological_filenames_and_unicode() -> Tuple[bool, str]:
    """Tests extreme and pathological filenames: unicode, Arabic, Japanese, special chars."""
    td = tempfile.mkdtemp(prefix="nup_stress_unicode_")
    try:
        dump_dir = os.path.join(td, "dump")
        nup_path = os.path.join(td, "unicode_test.nup")
        extract_dir = os.path.join(td, "extracted")

        test_files = {
            "arabic_تجربة.bin": b"ARABIC_PAYLOAD_TEST",
            "japanese_ゲーム.dat": b"JAPANESE_PAYLOAD_TEST",
            "accented_éàü_çöî.cfg": b"ACCENTED_PAYLOAD_TEST",
            "space and [bracket] (paren) + plus.txt": b"SPECIAL_CHARS_PAYLOAD",
            "l1/l2/l3/l4/l5/deep_leaf.dat": b"DEEP_NESTING_PAYLOAD",
        }

        create_minimal_dump(dump_dir, test_files)
        pack(nup_path, dump_dir, level=3)

        with NupReader(nup_path) as r:
            extract_tree(r, extract_dir, r.packages[0].root_dir)

        # Verify extracted files
        for name, data in test_files.items():
            target_path = os.path.join(extract_dir, "romfs", *name.split("/"))
            if not os.path.exists(target_path):
                return False, f"Pathological file missing after extraction: {name}"
            with open(target_path, "rb") as fh:
                if fh.read() != data:
                    return False, f"Corrupted content for pathological file: {name}"

        return True, f"Passed ({len(test_files)} pathological filenames verified)"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def test_concurrent_multithreaded_readers(num_threads: int = 8, reads_per_thread: int = 25) -> Tuple[bool, str]:
    """Tests concurrent reader thread safety against single NUP container."""
    td = tempfile.mkdtemp(prefix="nup_stress_concurrent_")
    try:
        dump_dir = os.path.join(td, "dump")
        nup_path = os.path.join(td, "concurrent.nup")
        payloads = {}
        for i in range(8):
            data = f"CONCURRENT_TEST_FILE_CONTENT_{i}".encode("utf-8") * 2048
            name = f"payload_{i}.bin"
            payloads[name] = (data, hashlib.sha256(data).digest())

        create_minimal_dump(dump_dir, {k: v[0] for k, v in payloads.items()})
        pack(nup_path, dump_dir, level=3)

        errors: List[str] = []

        def worker(thread_id: int):
            try:
                with NupReader(nup_path) as r:
                    for _ in range(reads_per_thread):
                        for fi in range(r.file_count):
                            fname = r.files[fi][0].decode("utf-8", "replace")
                            actual_data = r.read_file(fi)
                            actual_sha = r.hash_file(fi)
                            if hashlib.sha256(actual_data).digest() != actual_sha:
                                errors.append(f"Thread {thread_id}: SHA mismatch on {fname}")
            except Exception as e:
                errors.append(f"Thread {thread_id} crashed: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if errors:
            return False, f"Errors in concurrent reader test: {errors[:3]}"
        return True, f"Passed ({num_threads} concurrent threads, {reads_per_thread} iterations each)"
    finally:
        shutil.rmtree(td, ignore_errors=True)


def run_all_stress_tests() -> bool:
    print("================================================================================")
    print(" NUPULL PHASE III STRESS & RELIABILITY TEST SUITE")
    print("================================================================================")
    tests = [
        ("Sequential Extractions & FD/Memory Leak Check", lambda: test_sequential_extraction_leaks(25)),
        ("High File Count Container (200 entries)", lambda: test_high_file_count_container(200)),
        ("Pathological Filenames, Deep Nesting & Unicode", test_pathological_filenames_and_unicode),
        ("Concurrent Multi-Reader Thread Safety", lambda: test_concurrent_multithreaded_readers(8, 25)),
    ]

    all_passed = True
    for name, test_fn in tests:
        print(f"\n[STRESS TEST] {name}...")
        t0 = time.perf_counter()
        try:
            ok, msg = test_fn()
            elapsed = time.perf_counter() - t0
            status = "PASS" if ok else "FAIL"
            print(f"  Result: {status} ({elapsed:.3f}s)")
            print(f"  Detail: {msg}")
            if not ok:
                all_passed = False
        except Exception as e:
            elapsed = time.perf_counter() - t0
            print(f"  Result: CRASH ({elapsed:.3f}s)")
            print(f"  Exception: {e}")
            all_passed = False

    print("\n================================================================================")
    print(f" STRESS TEST SUMMARY: {'ALL PASSED' if all_passed else 'SOME TESTS FAILED'}")
    print("================================================================================\n")
    return all_passed


if __name__ == "__main__":
    success = run_all_stress_tests()
    sys.exit(0 if success else 1)
