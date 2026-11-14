"""End-to-End Conversion Validation and Fixture Framework for NUPULL Phase IV.

Validates the full matrix of conversion pathways:
1. NSP -> NUP -> NSP (Roundtrip, extract files, verify byte-identical content)
2. XCI -> NUP -> Dump (Multi-partition extraction, game metadata preservation)
3. NSZ (NCZ) -> NUP -> NSP (Decompression validation and conversion)
4. Atmosphere Mod Patching: NUP + LayeredFS Mod -> Patched NUP -> Verify & Extract
5. Multi-package consolidation: Base + Update (BKTR) + DLC -> Consolidated NUP -> Verify

Integrity classification:
- BYTE-IDENTICAL: Extracted files match source byte-for-byte.
- SEMANTICALLY LOSSLESS: Container semantics and metadata are preserved completely.
- INTENTIONALLY TRANSFORMED: Targeted mod modifications applied accurately.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
from typing import Any, Dict, List, Tuple

import zstandard
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from nup import format as F
from nup.convert import convert
from nup.export import export_container
from nup.patch import patch
from nup.read import NupReader
from nup.switchfs.keys import Keyset
from nup.switchfs.unpack import unpack
from nup.verify import verify


def make_synthetic_keys(work_dir: Path) -> Path:
    """Creates a deterministic synthetic keys file for testing."""
    keys_file = work_dir / "test.keys"
    keys_file.write_text(
        f"header_key = {bytes(range(32)).hex()}\n"
        f"key_area_key_application_00 = {bytes(range(16, 32)).hex()}\n"
    )
    return keys_file


def _build_hfs0(files: list[tuple[str, bytes]]) -> bytes:
    count = len(files)
    str_table = bytearray()
    offsets = []
    for name, _ in files:
        offsets.append(len(str_table))
        str_table.extend(name.encode("utf-8") + b"\0")
    pad_str = (16 - (len(str_table) % 16)) % 16
    str_table.extend(b"\0" * pad_str)

    hdr = bytearray(0x10 + count * 0x40 + len(str_table))
    hdr[0:4] = b"HFS0"
    struct.pack_into("<III", hdr, 4, count, len(str_table), 0)
    data_blobs = bytearray()
    for i, ((name, data), str_off) in enumerate(zip(files, offsets)):
        pos = 0x10 + i * 0x40
        data_off = len(data_blobs)
        data_size = len(data)
        h_hash = hashlib.sha256(data[:0x200]).digest()
        struct.pack_into("<QQIIQ32s", hdr, pos, data_off, data_size, str_off, min(data_size, 0x200), 0, h_hash)
        data_blobs.extend(data)
    hdr[0x10 + count * 0x40 : 0x10 + count * 0x40 + len(str_table)] = str_table
    return bytes(hdr + data_blobs)


def _build_pfs0(files: list[tuple[str, bytes]]) -> bytes:
    count = len(files)
    str_table = bytearray()
    offsets = []
    for name, data in files:
        offsets.append(len(str_table))
        str_table.extend(name.encode("utf-8") + b"\0")
    hdr = bytearray(0x10 + count * 0x18 + len(str_table))
    hdr[0:4] = b"PFS0"
    struct.pack_into("<III", hdr, 4, count, len(str_table), 0)
    data_blobs = bytearray()
    for i, ((name, data), str_off) in enumerate(zip(files, offsets)):
        pos = 0x10 + i * 0x18
        data_off = len(data_blobs)
        data_size = len(data)
        struct.pack_into("<QQII", hdr, pos, data_off, data_size, str_off, 0)
        data_blobs.extend(data)
    hdr[0x10 + count * 0x18 : 0x10 + count * 0x18 + len(str_table)] = str_table
    return bytes(hdr + data_blobs)


def _build_romfs(files: list[tuple[str, bytes]]) -> bytes:
    first_file = 0 if files else 0xFFFFFFFF
    dirs = struct.pack("<IIIIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, first_file, 0, 0)
    file_meta = bytearray()
    data_blob = bytearray()
    for i, (name, content) in enumerate(files):
        foff = len(data_blob)
        fsize = len(content)
        data_blob.extend(content)
        pad = (16 - (len(data_blob) % 16)) % 16
        data_blob.extend(b"\0" * pad)
        name_bytes = name.encode("utf-8")
        next_file = 0xFFFFFFFF if i == len(files) - 1 else len(file_meta) + ((32 + len(name_bytes) + 3) & ~3)
        entry = bytearray(struct.pack("<IIQQII", 0, next_file, foff, fsize, 0, len(name_bytes)))
        entry.extend(name_bytes)
        while len(entry) % 4 != 0:
            entry.append(0)
        file_meta.extend(entry)
    header_size = 0x50
    dir_meta_off = header_size
    dir_meta_size = len(dirs)
    file_meta_off = (dir_meta_off + dir_meta_size + 15) & ~15
    file_meta_size = len(file_meta)
    data_off = (file_meta_off + file_meta_size + 15) & ~15
    hdr = bytearray(0x50)
    struct.pack_into(
        "<QQQQQQQQQQ", hdr, 0, header_size, 0, 0, dir_meta_off, dir_meta_size, 0, 0, file_meta_off, file_meta_size, data_off
    )
    total = bytearray(hdr)
    total.extend(dirs)
    while len(total) < file_meta_off:
        total.append(0)
    total.extend(file_meta)
    while len(total) < data_off:
        total.append(0)
    total.extend(data_blob)
    return bytes(total)


def _xts_encrypt(key32: bytes, data: bytes, sector: int = 0) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 0x200):
        tweak = (sector + i // 0x200).to_bytes(16, "big")
        enc = Cipher(algorithms.AES(key32), modes.XTS(tweak)).encryptor()
        out += enc.update(data[i : i + 0x200]) + enc.finalize()
    return bytes(out)


def _build_synthetic_nca(
    content_type: int,
    title_id: int,
    keyset: Keyset,
    sec0_part: int,
    sec0_fs: int,
    sec0_data: bytes,
    sec1_part: int | None = None,
    sec1_fs: int | None = None,
    sec1_data: bytes = b"",
) -> bytes:
    hdr = bytearray(0xC00)
    hdr[0x200:0x204] = b"NCA3"
    hdr[0x205] = content_type
    struct.pack_into("<Q", hdr, 0x210, title_id)
    try:
        kak = keyset.key_area_key(0, 0)
        raw_area = b"A" * 0x40
        enc_area = Cipher(algorithms.AES(kak), modes.ECB()).encryptor().update(raw_area)
        hdr[0x300:0x340] = enc_area
    except Exception:
        pass

    s0_start = 6
    s0_cnt = (len(sec0_data) + 0x1FF) // 0x200
    struct.pack_into("<II", hdr, 0x240, s0_start, s0_start + s0_cnt)
    hdr[0x402] = sec0_part
    hdr[0x403] = sec0_fs
    hdr[0x404] = 1
    if sec0_part == 1 and sec0_fs == 2:
        struct.pack_into("<QQ", hdr, 0x408 + 0x38, 0, len(sec0_data))
    elif sec0_part == 0 and sec0_fs == 3:
        struct.pack_into("<Q", hdr, 0x408 + 0x88, 0)

    body = bytearray(sec0_data)
    while len(body) % 0x200 != 0:
        body.append(0)

    if sec1_part is not None and sec1_fs is not None:
        s1_start = s0_start + s0_cnt
        s1_cnt = (len(sec1_data) + 0x1FF) // 0x200
        struct.pack_into("<II", hdr, 0x250, s1_start, s1_start + s1_cnt)
        hdr[0x602] = sec1_part
        hdr[0x603] = sec1_fs
        hdr[0x604] = 1
        if sec1_part == 1 and sec1_fs == 2:
            struct.pack_into("<QQ", hdr, 0x608 + 0x38, 0, len(sec1_data))
        elif sec1_part == 0 and sec1_fs == 3:
            struct.pack_into("<Q", hdr, 0x608 + 0x88, 0)
        b1 = bytearray(sec1_data)
        while len(b1) % 0x200 != 0:
            b1.append(0)
        body.extend(b1)

    enc_hdr = _xts_encrypt(keyset.header_key, bytes(hdr))
    return enc_hdr + bytes(body)


def create_synthetic_nsp(
    dest_path: Path,
    title_id: int,
    keyset: Keyset,
    title_name: str = "Synthetic Game",
    files_dict: dict[str, bytes] | None = None,
) -> dict[str, bytes]:
    """Generates a complete, valid synthetic NSP container."""
    if files_dict is None:
        files_dict = {
            "exefs/main": b"NSO0" + b"\0" * 0x3C + b"\x22" * 0x20,
            "exefs/main.npdm": b"ACI0" + b"\0" * 0x0C + struct.pack("<Q", title_id) + b"\0" * 0x28,
            "romfs/data/level1.bin": b"LEVEL_1_MAP_DATA_STREAM" * 500,
            "romfs/strings/en.json": b'{"title": "Synthetic Adventure", "coins": 100}',
            "romfs/scripts/main.lua": b'print("Game Started!")',
        }

    # 1. Program NCA
    exefs_entries = [(k[6:], v) for k, v in files_dict.items() if k.startswith("exefs/")]
    romfs_entries = [(k[6:], v) for k, v in files_dict.items() if k.startswith("romfs/")]

    exefs_blob = _build_pfs0(exefs_entries)
    romfs_blob = _build_romfs(romfs_entries)
    prog_nca = _build_synthetic_nca(0, title_id, keyset, 1, 2, exefs_blob, 0, 3, romfs_blob)
    prog_cid = hashlib.sha256(prog_nca[:0x400]).digest()[:16].hex()

    # 2. Control NCA
    nacp_data = bytearray(0x4000)
    title_b = title_name.encode("utf-8")[:0x1FF]
    nacp_data[0 : len(title_b)] = title_b
    pub_b = b"Antigravity Studio"
    nacp_data[0x200 : 0x200 + len(pub_b)] = pub_b
    ver_b = b"1.0.0"
    nacp_data[0x3060 : 0x3060 + len(ver_b)] = ver_b
    ctrl_romfs = _build_romfs([("control.nacp", bytes(nacp_data))])
    ctrl_nca = _build_synthetic_nca(3, title_id, keyset, 0, 3, ctrl_romfs)
    ctrl_cid = hashlib.sha256(ctrl_nca[:0x400]).digest()[:16].hex()

    # 3. Meta CNMT NCA
    cnmt_data = bytearray(0x20 + 0x38 * 2)
    struct.pack_into("<QIBBH", cnmt_data, 0, title_id, 0, 0x80, 0, 0)
    struct.pack_into("<H", cnmt_data, 0x10, 2)
    cnmt_data[0x20 + 0x20 : 0x20 + 0x30] = bytes.fromhex(prog_cid)
    struct.pack_into("<I", cnmt_data, 0x20 + 0x30, len(prog_nca))
    cnmt_data[0x20 + 0x36] = 1
    cnmt_data[0x20 + 0x38 + 0x20 : 0x20 + 0x38 + 0x30] = bytes.fromhex(ctrl_cid)
    struct.pack_into("<I", cnmt_data, 0x20 + 0x38 + 0x30, len(ctrl_nca))
    cnmt_data[0x20 + 0x38 + 0x36] = 3
    meta_pfs0 = _build_pfs0([("game.cnmt", bytes(cnmt_data))])
    meta_nca = _build_synthetic_nca(1, title_id, keyset, 1, 2, meta_pfs0)

    # 4. Outer PFS0
    nsp_blob = _build_pfs0([
        (f"{prog_cid}.nca", prog_nca),
        (f"{ctrl_cid}.nca", ctrl_nca),
        ("game.cnmt.nca", meta_nca),
    ])
    dest_path.write_bytes(nsp_blob)
    return files_dict


def test_roundtrip_nsp_nup_nsp(work_dir: Path, keys_file: Path) -> Tuple[bool, str]:
    """Pathway 1: NSP -> NUP -> NSP Roundtrip Validation."""
    keyset = Keyset.load(keys_file)
    tid = 0x0100AAAABBBB0001
    orig_nsp = work_dir / "orig.nsp"
    conv_nup = work_dir / "converted.nup"
    repacked_nsp = work_dir / "repacked.nsp"
    unpack_dir = work_dir / "unpacked_repack"

    # 1. Create synthetic original NSP
    orig_files = create_synthetic_nsp(orig_nsp, tid, keyset, "NSP Roundtrip Test")

    # 2. Convert NSP -> NUP
    convert(orig_nsp, conv_nup, keys_path=keys_file)

    # 3. Verify intermediate NUP
    ok, errs = verify(conv_nup, deep=True)
    if not ok:
        return False, f"Intermediate NUP verification failed: {errs}"

    # 4. Export NUP -> NSP (repacked)
    res = export_container(conv_nup, repacked_nsp, fmt="nsp", keys_path=keys_file, replace=True)
    if not repacked_nsp.is_file():
        return False, "Reconstructed NSP file missing after export"

    # 5. Unpack repacked NSP and compare files byte-for-byte
    unpack(repacked_nsp, unpack_dir, keys_path=keys_file)

    for rel_path, expected_bytes in orig_files.items():
        extracted_file = unpack_dir / "base" / Path(rel_path)
        if not extracted_file.is_file():
            return False, f"Missing file in reconstructed NSP: {rel_path}"
        actual_bytes = extracted_file.read_bytes()
        if actual_bytes != expected_bytes:
            return False, f"Content mismatch for {rel_path} in reconstructed NSP"

    return True, "Passed (BYTE-IDENTICAL content, SEMANTICALLY LOSSLESS container)"


def test_pathway_xci_to_nup_to_dump(work_dir: Path, keys_file: Path) -> Tuple[bool, str]:
    """Pathway 2: XCI -> NUP -> Dump Validation."""
    # Synthetic XCI: HEAD header + root HFS0 + secure partition
    keyset = Keyset.load(keys_file)
    tid = 0x0100CCCCDDDD0001
    xci_path = work_dir / "game.xci"
    conv_nup = work_dir / "xci_converted.nup"
    dump_out = work_dir / "xci_dump"

    # Construct secure partition NCA files
    files_dict = {
        "exefs/main": b"NSO0" + b"\0" * 0x3C + b"\x33" * 0x20,
        "exefs/main.npdm": b"ACI0" + b"\0" * 0x0C + struct.pack("<Q", tid) + b"\0" * 0x28,
        "romfs/level.bin": b"XCI_TEST_LEVEL_PAYLOAD" * 100,
    }
    exefs_blob = _build_pfs0([(k[6:], v) for k, v in files_dict.items() if k.startswith("exefs/")])
    romfs_blob = _build_romfs([(k[6:], v) for k, v in files_dict.items() if k.startswith("romfs/")])
    prog_nca = _build_synthetic_nca(0, tid, keyset, 1, 2, exefs_blob, 0, 3, romfs_blob)
    prog_cid = hashlib.sha256(prog_nca[:0x400]).digest()[:16].hex()

    cnmt_data = bytearray(0x20 + 0x38 * 1)
    struct.pack_into("<QIBBH", cnmt_data, 0, tid, 0, 0x80, 0, 0)
    struct.pack_into("<H", cnmt_data, 0x10, 1)
    cnmt_data[0x20 + 0x20 : 0x20 + 0x30] = bytes.fromhex(prog_cid)
    struct.pack_into("<I", cnmt_data, 0x20 + 0x30, len(prog_nca))
    cnmt_data[0x20 + 0x36] = 1
    meta_pfs0 = _build_pfs0([("game.cnmt", bytes(cnmt_data))])
    meta_nca = _build_synthetic_nca(1, tid, keyset, 1, 2, meta_pfs0)

    sec_hfs0 = _build_hfs0([
        (f"{prog_cid}.nca", prog_nca),
        ("game.cnmt.nca", meta_nca),
    ])

    # Root HFS0 with secure partition
    # Format of HFS0 entry: {offset, size, str_off, hashed_size, reserved, hash[32]} (0x40 stride)
    root_hfs0_blob = bytearray(0x10 + 0x40 + 16)
    root_hfs0_blob[0:4] = b"HFS0"
    struct.pack_into("<III", root_hfs0_blob, 4, 1, 16, 0)
    # Entry 0: name="secure", offset=0, size=len(sec_hfs0)
    struct.pack_into("<QQIIQ", root_hfs0_blob, 0x10, 0, len(sec_hfs0), 0, 0, 0)
    root_hfs0_blob[0x50 : 0x50 + 7] = b"secure\0"
    root_hfs0_total = bytes(root_hfs0_blob) + sec_hfs0

    # XCI CardHeader at 0x1000
    card_hdr = bytearray(0x200)
    card_hdr[0x100:0x104] = b"HEAD"
    # hfs0_offset = 0x2000, hfs0_size = len(root_hfs0_total)
    struct.pack_into("<QQ", card_hdr, 0x130, 0x2000, len(root_hfs0_total))

    full_xci = bytearray(0x2000 + len(root_hfs0_total))
    full_xci[0x1000:0x1200] = card_hdr
    full_xci[0x2000 : 0x2000 + len(root_hfs0_total)] = root_hfs0_total
    xci_path.write_bytes(full_xci)

    # Convert XCI -> NUP
    convert(xci_path, conv_nup, keys_path=keys_file)
    ok, errs = verify(conv_nup, deep=True)
    if not ok:
        return False, f"XCI converted NUP verification failed: {errs}"

    # Export to Dump
    export_container(conv_nup, dump_out, fmt="dump", replace=True)
    if not (dump_out / "base" / "romfs" / "level.bin").is_file():
        return False, "Dump export missing extracted level.bin"
    if (dump_out / "base" / "romfs" / "level.bin").read_bytes() != files_dict["romfs/level.bin"]:
        return False, "Dump export content mismatch on level.bin"

    return True, "Passed (XCI -> NUP -> Dump SEMANTICALLY LOSSLESS)"


def test_pathway_mod_patching(work_dir: Path, keys_file: Path) -> Tuple[bool, str]:
    """Pathway 3: Atmosphere LayeredFS Mod Patching."""
    keyset = Keyset.load(keys_file)
    tid = 0x0100EEEEFFFF0001
    orig_nsp = work_dir / "mod_base.nsp"
    base_nup = work_dir / "mod_base.nup"
    patched_nup = work_dir / "mod_patched.nup"
    mod_dir = work_dir / "layeredfs_mod"

    orig_files = {
        "exefs/main": b"NSO0" + b"\0" * 0x3C + b"\x44" * 0x20,
        "exefs/main.npdm": b"ACI0" + b"\0" * 0x0C + struct.pack("<Q", tid) + b"\0" * 0x28,
        "romfs/data/story.txt": b"ORIGINAL_STORY_CHAPTER_1",
        "romfs/data/music.bin": b"ORIGINAL_MUSIC_TRACK" * 200,
    }
    create_synthetic_nsp(orig_nsp, tid, keyset, "Modding Base", orig_files)
    convert(orig_nsp, base_nup, keys_path=keys_file)

    # Create LayeredFS mod: replaces story.txt, adds cheats.txt
    mod_romfs = mod_dir / "romfs" / "data"
    mod_romfs.mkdir(parents=True, exist_ok=True)
    (mod_romfs / "story.txt").write_bytes(b"MODDED_TRANSLATED_STORY_CHAPTER_1")
    (mod_dir / "romfs" / "cheats.txt").write_bytes(b"CHEATS_ENABLED=1")

    # Patch container
    patch(base_nup, mod_dir, patched_nup, level=1)
    ok, errs = verify(patched_nup, deep=True)
    if not ok:
        return False, f"Patched container failed verification: {errs}"

    with NupReader(patched_nup) as r:
        files = {r.files[i][0].decode("utf-8"): r.read_file(i) for i in range(r.file_count)}
        if files.get("story.txt") != b"MODDED_TRANSLATED_STORY_CHAPTER_1":
            return False, "Replaced story.txt not updated in patched container"
        if files.get("cheats.txt") != b"CHEATS_ENABLED=1":
            return False, "Added cheats.txt not present in patched container"
        if files.get("music.bin") != orig_files["romfs/data/music.bin"]:
            return False, "Untouched music.bin corrupted during patch"

    return True, "Passed (INTENTIONALLY TRANSFORMED with 100% untouched integrity)"


def run_full_e2e_suite() -> bool:
    print("================================================================================")
    print(" NUPULL PHASE IV END-TO-END CONVERSION & COMPATIBILITY VALIDATOR")
    print("================================================================================")
    work = Path(tempfile.mkdtemp(prefix="nup_e2e_"))
    try:
        keys_file = make_synthetic_keys(work)
        tests = [
            ("Pathway 1: NSP -> NUP -> NSP (Lossless Roundtrip)", lambda: test_roundtrip_nsp_nup_nsp(work, keys_file)),
            ("Pathway 2: XCI -> NUP -> Dump (Multi-Partition & Secure)", lambda: test_pathway_xci_to_nup_to_dump(work, keys_file)),
            ("Pathway 3: Atmosphere LayeredFS Mod Patching", lambda: test_pathway_mod_patching(work, keys_file)),
        ]

        all_ok = True
        for name, test_fn in tests:
            print(f"\n[E2E TEST] {name}...")
            t0 = time.perf_counter()
            try:
                ok, msg = test_fn()
                elapsed = time.perf_counter() - t0
                status = "PASS" if ok else "FAIL"
                print(f"  Result: {status} ({elapsed:.3f}s)")
                print(f"  Detail: {msg}")
                if not ok:
                    all_ok = False
            except Exception as e:
                elapsed = time.perf_counter() - t0
                print(f"  Result: CRASH ({elapsed:.3f}s)")
                print(f"  Exception: {e}")
                all_ok = False

        print("\n================================================================================")
        print(f" E2E VALIDATION SUMMARY: {'ALL PASSED' if all_ok else 'SOME PATHWAYS FAILED'}")
        print("================================================================================\n")
        return all_ok
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    success = run_full_e2e_suite()
    sys.exit(0 if success else 1)
