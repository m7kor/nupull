"""Regression suite: attacks must fail cleanly, legit roundtrip must pass."""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile

from nup import format as F
from nup import meta as M
from nup.access import app_meta, extract_tree
from nup.batch import batch_convert, BatchResult
from nup.convert import convert
from nup.export import export_container, ExportResult
from nup.pack import pack
from nup.patch import patch, PatchResult
from nup.read import NupReader
from nup.verify import verify
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from nup.switchfs import unpack, CancelledError, UnpackError
from nup.switchfs.keys import Keyset

PY = sys.executable
fails = []


def check(cond, label, detail=""):
    tag = "PASS" if cond else "FAIL"
    if not cond:
        fails.append(label)
    print(f"[{tag}] {label}" + (f"  ({detail})" if detail else ""))


def cli(args):
    p = subprocess.run([PY, "-m", "nup.cli", *args],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr)


work = tempfile.mkdtemp(prefix="nup_reg_")
print("work:", work)


def patch_pool(data, old, new):
    toc_off = struct.unpack_from("<Q", data, 8)[0]
    pool_off = toc_off + struct.unpack_from("<Q", data, toc_off + 24)[0]
    pool_size = struct.unpack_from("<Q", data, toc_off + 32)[0]
    pool = bytes(data[pool_off:pool_off + pool_size])
    assert pool.count(old) == 1
    idx = pool.index(old)
    data[pool_off + idx:pool_off + idx + len(new)] = new


def rehash_toc(data):
    toc_off = struct.unpack_from("<Q", data, 8)[0]
    toc_size = struct.unpack_from("<Q", data, 16)[0]
    data[24:56] = hashlib.sha256(bytes(data[toc_off:toc_off + toc_size])).digest()


# ---------- build a legit dump ----------
evil = b"..\\..\\pwned.txt"
safe = b"a" * len(evil)
dump = os.path.join(work, "dump")
os.makedirs(os.path.join(dump, "exefs"))
os.makedirs(os.path.join(dump, "romfs", "sub"))
open(os.path.join(dump, "exefs", "main"), "wb").write(b"NSO0" + b"\0" * 0x3C + b"\x22" * 0x20)
npdm = bytearray(b"\0" * 0x40)
npdm[0:4] = b"ACI0"
struct.pack_into("<Q", npdm, 0x10, 0x0100AAAABBBB0001)
open(os.path.join(dump, "exefs", "main.npdm"), "wb").write(bytes(npdm))
open(os.path.join(dump, "romfs", safe.decode()), "wb").write(b"PWNED-VIA-EXTRACT")
open(os.path.join(dump, "romfs", "sub", "normal.bin"), "wb").write(b"normal content \xd8\xb1\xd8\xa7\xd9\x85")

nup1 = os.path.join(work, "game.nup")
pack(nup1, dump, level=3)

# ---------- B1: legit roundtrip ----------
rc, out = cli(["info", nup1])
check(rc == 0 and "0100AAAABBBB0001" in out, "info works + title id parsed", out[:120])
rc, out = cli(["verify", nup1])
check(rc == 0 and "verify: OK" in out, "verify deep OK on legit file")
rc, out = cli(["list", nup1])
check(rc == 0 and out.count("\n") >= 3, "list works")

dest = os.path.join(work, "out")
with NupReader(nup1) as r:
    n = extract_tree(r, dest, r.packages[0].root_dir)
check(n == 4, "extract legit count", f"n={n}")
check(open(os.path.join(dest, "romfs", safe.decode()), "rb").read() == b"PWNED-VIA-EXTRACT",
      "extracted bytes identical")

# ---------- B2: edit metadata ----------
rc, out = cli(["edit", nup1, "--name", "Audit Game", "--publisher", "QA"])
check(rc == 0 and "updated" in out, "edit works", out[:120])
rc, out = cli(["info", nup1])
check("Audit Game" in out and "QA" in out, "edited metadata visible")
rc, out = cli(["verify", nup1])
check(rc == 0, "verify still OK after edit")

# ---------- A1: path traversal name ----------
data = bytearray(open(nup1, "rb").read())
patch_pool(data, safe, evil)
rehash_toc(data)
evil_nup = os.path.join(work, "evil.nup")
open(evil_nup, "wb").write(bytes(data))

try:
    with NupReader(evil_nup) as r:
        extract_tree(r, os.path.join(work, "out_evil"), r.packages[0].root_dir)
    check(False, "traversal container rejected at open")
except F.NupError as e:
    check("unsafe" in str(e), "traversal container rejected: NupError", str(e)[:80])
check(not os.path.exists(os.path.join(work, "pwned.txt")), "no file escaped destination")

rc, out = cli(["verify", evil_nup])
check(rc == 1 and "unsafe" in out, "verify reports unsafe name (exit 1)", out[:120])
rc, out = cli(["info", evil_nup])
check(rc == 2 and "nup: error:" in out and "Traceback" not in out,
      "info on evil: clean exit 2, no traceback", out[:120])
rc, out = cli(["extract", evil_nup, os.path.join(work, "out_evil2")])
check(rc == 2 and "Traceback" not in out, "extract on evil: clean exit 2")

# ---------- A2: out-of-range child id ----------
data = bytearray(open(nup1, "rb").read())
toc_off = struct.unpack_from("<Q", data, 8)[0]
pkg_c = struct.unpack_from("<I", data, toc_off + 4)[0]
dir_c = struct.unpack_from("<Q", data, toc_off + 8)[0]
file_c = struct.unpack_from("<Q", data, toc_off + 16)[0]
children_at = toc_off + 48 + pkg_c * F.PKG_SIZE + dir_c * F.DIR_SIZE + file_c * F.FILE_SIZE
struct.pack_into("<I", data, children_at, 0xFFFFFF00)
rehash_toc(data)
badcid_nup = os.path.join(work, "badcid.nup")
open(badcid_nup, "wb").write(bytes(data))
try:
    with NupReader(badcid_nup):
        pass
    check(False, "bad child id rejected at open")
except F.NupError as e:
    check("out of range" in str(e), "bad child id rejected: NupError", str(e)[:80])
rc, out = cli(["verify", badcid_nup])
check(rc == 1 and "Traceback" not in out, "verify on bad cid: clean problem report")

# ---------- A3: malformed localized TLV ----------
for payload in (b"\x05en", b"\x03en\xff\xff\xff\xff", b"\x02en\x01", b"\x00abc\x00\x00\x00\x00"):
    try:
        M.decode_localized(payload)
        check(False, f"decode_localized rejects {payload!r}")
    except F.NupError as e:
        check(True, f"decode_localized NupError {payload!r}", str(e)[:60])
    except Exception as e:
        check(False, f"decode_localized clean error {payload!r}", f"{type(e).__name__}: {e}")

# ---------- A4: cycle in tree ----------
# make root's first child point at root itself (dir 0)
data = bytearray(open(nup1, "rb").read())
struct.pack_into("<I", data, children_at, 0)  # child slot -> dir 0 (root)
rehash_toc(data)
cycle_nup = os.path.join(work, "cycle.nup")
open(cycle_nup, "wb").write(bytes(data))
try:
    with NupReader(cycle_nup) as r:
        extract_tree(r, os.path.join(work, "out_cycle"), r.packages[0].root_dir)
    check(False, "cycle rejected during extract")
except F.NupError as e:
    # root-as-child is stopped by its unnamed-component rule; deeper loops by
    # the visited-set guard - either way it must be a clean NupError, no loop
    check("more than once" in str(e) or "unsafe file name" in str(e),
          "cycle rejected: NupError", str(e)[:80])
rc, out = cli(["extract", cycle_nup, os.path.join(work, "out_cycle2")])
check(rc == 2 and "Traceback" not in out, "cycle via CLI: clean exit 2")

# ---------- A4b: cycle between two named dirs (hits the visited-set guard) ----------
# dirs: 0=root 1=exefs 2=romfs 3=romfs/sub ; romfs's first child slot -> romfs
data = bytearray(open(nup1, "rb").read())
struct.pack_into("<I", data, children_at + 4 * 4, 2)
rehash_toc(data)
loop_nup = os.path.join(work, "loop.nup")
open(loop_nup, "wb").write(bytes(data))
try:
    with NupReader(loop_nup) as r:
        extract_tree(r, os.path.join(work, "out_loop"), r.packages[0].root_dir)
    check(False, "named-dir cycle rejected")
except F.NupError as e:
    check("more than once" in str(e), "named-dir cycle: visited-set guard", str(e)[:80])

# ---------- A5: title id validation ----------
rc, out = cli(["pack", dump, os.path.join(work, "x.nup"), "--title-id", "1234567890ABCDEF1"])
check(rc != 0 and "1-16 hex" in out and "Traceback" not in out, "bad --title-id rejected cleanly")
rc, out = cli(["pack", dump, os.path.join(work, "y.nup"), "--title-id", "-1"])
check(rc != 0 and "1-16 hex" in out, "negative --title-id rejected")

# ---------- A6: failed pack leaves no partial file ----------
outp = os.path.join(work, "huge.nup")
os.makedirs(os.path.join(work, "fakeupd", "999999999999"), exist_ok=True)
open(os.path.join(work, "fakeupd", "999999999999", "f"), "wb").write(b"x")
# pack a bundle whose update version overflows u32 -> SystemExit before write
bundle = os.path.join(work, "bundle")
os.makedirs(bundle, exist_ok=True)
shutil.copytree(os.path.join(dump), os.path.join(bundle, "base"), dirs_exist_ok=True)
shutil.copytree(os.path.join(work, "fakeupd"), os.path.join(bundle, "updates"), dirs_exist_ok=True)
rc, out = cli(["pack", bundle, outp])
check(rc != 0 and "u32" in out and "Traceback" not in out,
      "overflow update version: clean error", out[:120])
check(not os.path.exists(outp), "no partial output left after failed pack")

# ---------- R1: crash mid-pack leaves nothing at the final path ----------
crash_out = os.path.join(work, "crash.nup")


def _boom(done, total, fnode):
    if done >= 1:
        raise RuntimeError("injected mid-pack crash")


raised = False
try:
    pack(crash_out, dump, level=3, progress=_boom)
except RuntimeError:
    raised = True
check(raised, "mid-pack crash propagates to the caller")
check(not os.path.exists(crash_out), "crash mid-pack: no file at final path")
check(not os.path.exists(crash_out + ".partial"),
      "crash mid-pack: no .partial left behind")

# ---------- R2: stale .partial from a hard-killed run is swept ----------
swept = os.path.join(work, "swept.nup")
open(swept + ".partial", "wb").write(b"stale junk from a hard kill")
pack(swept, dump, level=3)
check(not os.path.exists(swept + ".partial"), "stale .partial swept on next pack")
rc, out = cli(["verify", swept])
check(rc == 0, "container built over a stale partial verifies OK", out[:120])

# ---------- R3: Ctrl+C (KeyboardInterrupt) cleans up and propagates ----------
def _ctrlc(done, total, fnode):
    if done >= 1:
        raise KeyboardInterrupt


int_out = os.path.join(work, "interrupted.nup")
interrupted = False
try:
    pack(int_out, dump, level=3, progress=_ctrlc)
except KeyboardInterrupt:
    interrupted = True
check(interrupted, "KeyboardInterrupt propagates (CLI exits cleanly, code 130)")
check(not os.path.exists(int_out) and not os.path.exists(int_out + ".partial"),
      "Ctrl+C: no output and no partial left")

# ---------- R4: replace=True - old output survives a failed rebuild ----------
swap = os.path.join(work, "swap.nup")
pack(swap, dump, level=3)                       # good version 1
size_v1 = os.path.getsize(swap)


def _boom2(done, total, fnode):
    if done >= 1:
        raise RuntimeError("boom before the swap")


raised = False
try:
    pack(swap, dump, level=3, replace=True, progress=_boom2)
except RuntimeError:
    raised = True
check(raised and os.path.getsize(swap) == size_v1,
      "failed replace keeps the previous good output intact")
# now really replace: add a source file so the new container differs
open(os.path.join(dump, "romfs", "extra.bin"), "wb").write(b"extra " * 100)
pack(swap, dump, level=3, replace=True)
check(os.path.getsize(swap) != size_v1,
      "successful replace swaps in the new container")
check(not os.path.exists(swap + ".partial"), "no .partial after replace")
rc, out = cli(["verify", swap])
check(rc == 0, "replaced container verifies OK", out[:120])
# refusal without replace=True still protects the file
rc, out = cli(["pack", dump, swap])
check(rc != 0 and "refusing to overwrite" in out and "Traceback" not in out,
      "pack without replace still refuses to overwrite", out[:120])

# ---------- R5: verify on a missing/unreadable file reports, no raise ----------
ok, problems = verify(os.path.join(work, "does_not_exist.nup"))
check(not ok and problems and problems[0].startswith("open:"),
      "verify missing file -> (False, ['open: ...'])", str(problems[:1]))
rc, out = cli(["verify", os.path.join(work, "nope.nup")])
check(rc != 0 and "open:" in out and "Traceback" not in out,
      "CLI verify missing: clean failure, no traceback", out[:120])

# ---------- R6: nup unpack CLI error reporting ----------
rc, out = cli(["unpack", os.path.join(work, "missing.nsp"), os.path.join(work, "out_missing")])
check(rc == 1 and "source file not found" in out and "Traceback" not in out,
      "unpack missing file: clean failure (exit 1)", out[:120])

corrupt_nsp = os.path.join(work, "corrupt.nsp")
open(corrupt_nsp, "wb").write(b"X" * 0x1200)
rc, out = cli(["unpack", corrupt_nsp, os.path.join(work, "out_corrupt")])
check(rc == 1 and "unrecognized container" in out and "Traceback" not in out,
      "unpack invalid file: clean failure (exit 1)", out[:120])

# ---------- R7: cooperative cancellation ----------
keyset = Keyset.load()
cancelled_caught = False
try:
    unpack(Path(corrupt_nsp), Path(work) / "out_cancel", cancel=lambda: True)
except CancelledError:
    cancelled_caught = True
except Exception:
    pass
check(cancelled_caught, "unpack cooperative cancellation raises CancelledError")

# ---------- R8: synthetic NSP unpack (Base + Control + Meta) ----------
kak = keyset.key_area_key(0, 0)
key_area_enc = Cipher(algorithms.AES(kak), modes.ECB()).encryptor().update(b"K" * 0x40)

def xts_enc(key32, data, sector=0):
    out = bytearray()
    for i in range(0, len(data), 0x200):
        tweak = (sector + i // 0x200).to_bytes(16, "big")
        enc = Cipher(algorithms.AES(key32), modes.XTS(tweak)).encryptor()
        out += enc.update(data[i : i + 0x200]) + enc.finalize()
    return bytes(out)

def build_pfs0(files):
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
    hdr[0x10 + count * 0x18: 0x10 + count * 0x18 + len(str_table)] = str_table
    return bytes(hdr + data_blobs)

def build_romfs(files):
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
    struct.pack_into("<QQQQQQQQQQ", hdr, 0, header_size, 0, 0, dir_meta_off, dir_meta_size, 0, 0, file_meta_off, file_meta_size, data_off)
    total = bytearray(hdr)
    total.extend(dirs)
    while len(total) < file_meta_off:
        total.append(0)
    total.extend(file_meta)
    while len(total) < data_off:
        total.append(0)
    total.extend(data_blob)
    return bytes(total)

def build_nca(content_type, title_id, sec0_part, sec0_fs, sec0_data, sec1_part=None, sec1_fs=None, sec1_data=b""):
    hdr = bytearray(0xC00)
    hdr[0x200:0x204] = b"NCA3"
    hdr[0x205] = content_type
    struct.pack_into("<Q", hdr, 0x210, title_id)
    hdr[0x300:0x340] = key_area_enc
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
    if sec1_part is not None:
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
    enc_hdr = xts_enc(keyset.header_key, bytes(hdr))
    return enc_hdr + bytes(body)

def build_hfs0(files):
    count = len(files)
    str_table = bytearray()
    offsets = []
    for name, data in files:
        offsets.append(len(str_table))
        str_table.extend(name.encode("utf-8") + b"\0")
    hdr = bytearray(0x10 + count * 0x40 + len(str_table))
    hdr[0:4] = b"HFS0"
    struct.pack_into("<III", hdr, 4, count, len(str_table), 0)
    data_blobs = bytearray()
    for i, ((name, data), str_off) in enumerate(zip(files, offsets)):
        pos = 0x10 + i * 0x40
        data_off = len(data_blobs)
        data_size = len(data)
        struct.pack_into("<QQIIQ", hdr, pos, data_off, data_size, str_off, 0, 0)
        data_blobs.extend(data)
    hdr[0x10 + count * 0x40: 0x10 + count * 0x40 + len(str_table)] = str_table
    return bytes(hdr + data_blobs)

# Program NCA
synth_tid = 0x0100AABBCCDDEE00
synth_npdm = bytearray(b"\0" * 0x40)
synth_npdm[0:4] = b"ACI0"
struct.pack_into("<Q", synth_npdm, 0x10, synth_tid)
exefs_bytes = build_pfs0([("main", b"NSO0" + b"\0" * 0x5C), ("main.npdm", bytes(synth_npdm))])
romfs_bytes = build_romfs([("game_data.bin", b"synthetic romfs payload 12345")])
prog_nca_bytes = build_nca(0, synth_tid, 1, 2, exefs_bytes, 0, 3, romfs_bytes)
prog_cid = "11" * 16

# Control NCA
nacp_data = bytearray(0x4000)
nacp_data[0:0x20] = b"Synthetic Game\0"
nacp_data[0x200:0x220] = b"Antigravity\0"
nacp_data[0x3060:0x3068] = b"1.2.3\0"
ctrl_romfs_bytes = build_romfs([("control.nacp", bytes(nacp_data)), ("icon_AmericanEnglish.dat", b"fakeicon" * 8)])
ctrl_nca_bytes = build_nca(2, synth_tid, 0, 3, ctrl_romfs_bytes)
ctrl_cid = "22" * 16

# Meta CNMT NCA
cnmt_data = bytearray(0x20 + 2 * 0x38)
struct.pack_into("<QIBBH", cnmt_data, 0, synth_tid, 0, 0x80, 0, 0)
struct.pack_into("<H", cnmt_data, 0x10, 2)
cnmt_data[0x20 + 0x20:0x20 + 0x30] = bytes.fromhex(prog_cid)
struct.pack_into("<I", cnmt_data, 0x20 + 0x30, len(prog_nca_bytes))
cnmt_data[0x20 + 0x36] = 1
cnmt_data[0x58 + 0x20:0x58 + 0x30] = bytes.fromhex(ctrl_cid)
struct.pack_into("<I", cnmt_data, 0x58 + 0x30, len(ctrl_nca_bytes))
cnmt_data[0x58 + 0x36] = 3

meta_pfs0_bytes = build_pfs0([("game.cnmt", bytes(cnmt_data))])
meta_nca_bytes = build_nca(1, synth_tid, 1, 2, meta_pfs0_bytes)

synth_nsp_bytes = build_pfs0([
    (f"{prog_cid}.nca", prog_nca_bytes),
    (f"{ctrl_cid}.nca", ctrl_nca_bytes),
    ("game.cnmt.nca", meta_nca_bytes),
])
synth_nsp_path = os.path.join(work, "synth.nsp")
open(synth_nsp_path, "wb").write(synth_nsp_bytes)

synth_out = os.path.join(work, "synth_unpacked")
unpack(Path(synth_nsp_path), Path(synth_out))
check(os.path.isfile(os.path.join(synth_out, "base", "exefs", "main.npdm"))
      and os.path.isfile(os.path.join(synth_out, "base", "romfs", "game_data.bin"))
      and os.path.isfile(os.path.join(synth_out, "_meta", "control.nacp"))
      and os.path.isfile(os.path.join(synth_out, "_meta", "info.txt")),
      "synthetic NSP unpack: base exefs/romfs + _meta files present")

info_content = open(os.path.join(synth_out, "_meta", "info.txt"), "r", encoding="utf-8").read()
check("title_id: 0100aabbccddee00" in info_content
      and "name: Synthetic Game" in info_content
      and "publisher: Antigravity" in info_content
      and "display_version: 1.2.3" in info_content,
      "synthetic NSP unpack: info.txt correctly parsed from NACP")

# ---------- R9: --no-control skips _meta ----------
synth_no_ctrl_out = os.path.join(work, "synth_no_ctrl")
unpack(Path(synth_nsp_path), Path(synth_no_ctrl_out), no_control=True)
check(os.path.isdir(os.path.join(synth_no_ctrl_out, "base", "exefs"))
      and not os.path.exists(os.path.join(synth_no_ctrl_out, "_meta")),
      "--no-control: skips _meta directory entirely")

# ---------- R10: unpacked output packs cleanly into .nup ----------
synth_nup = os.path.join(work, "synth.nup")
pkgs = pack(synth_nup, synth_out)
check(len(pkgs) == 1 and pkgs[0].title_id == synth_tid,
      "pack succeeds on unpacked dump directory")
ok, probs = verify(synth_nup, deep=True)
check(ok and not probs, "container packed from unpack output verifies deep OK")

# ---------- R11: synthetic XCI container unpack ----------
sec_hfs0_bytes = build_hfs0([
    (f"{prog_cid}.nca", prog_nca_bytes),
    (f"{ctrl_cid}.nca", ctrl_nca_bytes),
    ("game.cnmt.nca", meta_nca_bytes),
])
root_hfs0_bytes = build_hfs0([("secure", sec_hfs0_bytes)])
xci_card_hdr = bytearray(0x200)
xci_card_hdr[0x100:0x104] = b"HEAD"
struct.pack_into("<QQ", xci_card_hdr, 0x130, 0x200, len(root_hfs0_bytes))
synth_xci_bytes = bytes(xci_card_hdr) + root_hfs0_bytes
synth_xci_path = os.path.join(work, "synth.xci")
open(synth_xci_path, "wb").write(synth_xci_bytes)

synth_xci_out = os.path.join(work, "synth_xci_unpacked")
unpack(Path(synth_xci_path), Path(synth_xci_out), no_control=True)
check(os.path.isfile(os.path.join(synth_xci_out, "base", "exefs", "main.npdm")),
      "synthetic XCI unpack: extracts base exefs from secure partition")

# ---------- R12: real FF7 update BKTR merge test (if available) ----------
ff7_dir = Path(r"C:\Users\KH\Downloads\Compressed\FINAL FANTASY RESONANCE [0100606026F12000][v0][Base]")
ff7_upd = ff7_dir / "FINAL FANTASY RESONANCE [0100606026F12800][v65536][1.0.1][UPD].nsp"
ff7_base = ff7_dir / "FINAL FANTASY RESONANCE [0100606026F12000][v0][Base].nsp"
if ff7_upd.is_file() and ff7_base.is_file():
    d_test_dir = Path(tempfile.mkdtemp(prefix="nup_reg_d_", dir="D:\\"))
    try:
        unpack(ff7_upd, d_test_dir)
        upd_romfs_files = list((d_test_dir / "updates" / "65536" / "romfs").rglob("*"))
        upd_romfs_files = [f for f in upd_romfs_files if f.is_file()]
        check(len(upd_romfs_files) == 14,
              "real FF7 update BKTR merge: auto-finds base and extracts 14 files",
              f"count={len(upd_romfs_files)}")
        check((d_test_dir / "updates" / "65536" / "exefs" / "main.npdm").is_file(),
              "real FF7 update: exefs main.npdm present")
        info_path = d_test_dir / "_meta" / "info.txt"
        check(info_path.is_file() and "FINAL FANTASY RESONANCE" in info_path.read_text(encoding="utf-8"),
              "real FF7 update: _meta/info.txt title parsed")
    finally:
        shutil.rmtree(d_test_dir, ignore_errors=True)

# ---------- R13: unpack robustness guards ----------
# 1. Refuse overwrite without --force
existing_nonempty = os.path.join(work, "existing_nonempty")
os.makedirs(existing_nonempty, exist_ok=True)
open(os.path.join(existing_nonempty, "precious.txt"), "w").write("do not touch")
rc, out = cli(["unpack", synth_nsp_path, existing_nonempty])
check(rc == 1 and "refusing to overwrite non-empty output directory" in out and "Traceback" not in out,
      "unpack without --force refuses non-empty directory", out[:120])
check(os.path.isfile(os.path.join(existing_nonempty, "precious.txt")),
      "precious file survived rejected unpack")

# 2. Overwrite with --force succeeds atomically
rc, out = cli(["unpack", synth_nsp_path, existing_nonempty, "--force", "-q"])
check(rc == 0 and os.path.isfile(os.path.join(existing_nonempty, "base", "exefs", "main.npdm"))
      and not os.path.isfile(os.path.join(existing_nonempty, "precious.txt")),
      "unpack with --force replaces non-empty directory cleanly", out[:120])

# 3. Refuse unpack when output contains source
rc, out = cli(["unpack", synth_nsp_path, work])
check(rc == 1 and "contains the source file" in out and "Traceback" not in out,
      "unpack refusing when output directory contains source", out[:120])

# 4. Failed/cancelled unpack sweeps partial directories (no residue)
synth_cancel_out = os.path.join(work, "synth_cancel_sweep")
cancelled_caught = False
try:
    unpack(Path(synth_nsp_path), Path(synth_cancel_out), cancel=lambda: True)
except CancelledError:
    cancelled_caught = True
check(cancelled_caught and not os.path.exists(synth_cancel_out)
      and not list(Path(work).glob(".synth_cancel_sweep.partial_*")),
      "cancelled unpack leaves zero output or .partial_* residue")

# 5. Path traversal attempt in container rejected
evil_exefs = build_pfs0([("..\\..\\evil.txt", b"EVIL")])
evil_prog_nca = build_nca(0, synth_tid, 1, 2, evil_exefs)
evil_cnmt_data = bytearray(0x20 + 0x38)
struct.pack_into("<QIBBH", evil_cnmt_data, 0, synth_tid, 0, 0x80, 0, 0)
struct.pack_into("<H", evil_cnmt_data, 0x10, 1)
evil_cnmt_data[0x20 + 0x20:0x20 + 0x30] = bytes.fromhex(prog_cid)
struct.pack_into("<I", evil_cnmt_data, 0x20 + 0x30, len(evil_prog_nca))
evil_cnmt_data[0x20 + 0x36] = 1
evil_meta_pfs0 = build_pfs0([("evil.cnmt", bytes(evil_cnmt_data))])
evil_meta_nca = build_nca(1, synth_tid, 1, 2, evil_meta_pfs0)
evil_nsp_path = os.path.join(work, "evil_traversal.nsp")
open(evil_nsp_path, "wb").write(build_pfs0([
    (f"{prog_cid}.nca", evil_prog_nca),
    ("evil.cnmt.nca", evil_meta_nca),
]))
evil_out = os.path.join(work, "evil_extracted")
traversal_blocked = False
try:
    unpack(Path(evil_nsp_path), Path(evil_out), no_control=True)
except UnpackError as exc:
    if "unsafe file path" in str(exc) or "escapes destination" in str(exc):
        traversal_blocked = True
check(traversal_blocked and not os.path.exists(os.path.join(work, "evil.txt")),
      "path traversal in dump rejected with UnpackError and no file escaped")

# ---------- R14: direct convert (dump -> .nup in one streaming step) ----------
direct_nup = os.path.join(work, "direct.nup")
convert(Path(synth_nsp_path), Path(direct_nup), fast=True)
ok, probs = verify(direct_nup, deep=True)
check(ok and not probs, "direct convert: container verifies deep OK", str(probs))

with NupReader(direct_nup) as r:
    check(len(r.packages) == 1 and r.packages[0].title_id == synth_tid,
          "direct convert: package title ID matches synthetic dump")
    meta = app_meta(r, r.packages[0])
    name = meta.get(F.TLV_TITLE_NAME, b"").decode("utf-8")
    pub = meta.get(F.TLV_PUBLISHER, b"").decode("utf-8")
    disp_ver = meta.get(F.TLV_DISPLAY_VERSION, b"").decode("utf-8")
    check(name == "Synthetic Game"
          and pub == "Antigravity"
          and disp_ver == "1.2.3",
          "direct convert: extracted NACP metadata preserved in .nup",
          f"name={name}, pub={pub}, ver={disp_ver}")

direct_extract = os.path.join(work, "direct_extracted")
with NupReader(direct_nup) as r:
    extract_tree(r, direct_extract, r.packages[0].root_dir)
check(os.path.isfile(os.path.join(direct_extract, "exefs", "main.npdm"))
      and os.path.isfile(os.path.join(direct_extract, "romfs", "game_data.bin")),
      "direct convert: extracted files match synthetic exefs/romfs")
with open(os.path.join(direct_extract, "romfs", "game_data.bin"), "rb") as fh:
    check(fh.read() == b"synthetic romfs payload 12345",
          "direct convert: virtual romfs stream content byte-identical")

# CLI nup convert
direct_cli_nup = os.path.join(work, "direct_cli.nup")
rc, out = cli(["convert", synth_nsp_path, direct_cli_nup, "--fast", "-q"])
check(rc == 0 and os.path.isfile(direct_cli_nup),
      "CLI convert succeeds", out[:120])
ok, probs = verify(direct_cli_nup, deep=True)
check(ok and not probs, "CLI converted container verifies deep OK")

# Cooperative cancel sweeps partial
direct_cancel_nup = os.path.join(work, "direct_cancel.nup")
cancelled_caught = False
try:
    convert(Path(synth_nsp_path), Path(direct_cancel_nup), cancel=lambda: True)
except CancelledError:
    cancelled_caught = True
check(cancelled_caught and not os.path.exists(direct_cancel_nup)
      and not os.path.exists(direct_cancel_nup + ".partial"),
      "direct convert cancel leaves zero output or .partial residue")

# ---------- R15: multi-package consolidation (Base + DLC All-in-One) ----------
dlc_tid = synth_tid + 0x1000
dlc_romfs_bytes = build_romfs([("dlc_bonus.bin", b"DLC Bonus Content 99999")])
dlc_nca_bytes = build_nca(4, dlc_tid, 0, 3, dlc_romfs_bytes)
dlc_cid = "33" * 16

dlc_cnmt_data = bytearray(0x20 + 8 + 0x38)
struct.pack_into("<QIBBH", dlc_cnmt_data, 0, dlc_tid, 0, 0x82, 0, 8)
struct.pack_into("<H", dlc_cnmt_data, 0x10, 1)
struct.pack_into("<Q", dlc_cnmt_data, 0x20, synth_tid)
dlc_cnmt_data[0x28 + 0x20:0x28 + 0x30] = bytes.fromhex(dlc_cid)
struct.pack_into("<I", dlc_cnmt_data, 0x28 + 0x30, len(dlc_nca_bytes))
dlc_cnmt_data[0x28 + 0x36] = 6

dlc_meta_pfs0 = build_pfs0([("addon.cnmt", bytes(dlc_cnmt_data))])
dlc_meta_nca = build_nca(1, dlc_tid, 1, 2, dlc_meta_pfs0)

synth_dlc_bytes = build_pfs0([
    (f"{dlc_cid}.nca", dlc_nca_bytes),
    ("addon.cnmt.nca", dlc_meta_nca),
])
synth_dlc_path = os.path.join(work, "synth_dlc.nsp")
open(synth_dlc_path, "wb").write(synth_dlc_bytes)

direct_aio_nup = os.path.join(work, "direct_aio.nup")
convert(Path(synth_nsp_path), Path(direct_aio_nup), dlcs=[Path(synth_dlc_path)], threads=-1)
ok, probs = verify(direct_aio_nup, deep=True)
check(ok and not probs, "multi-package convert: verifies deep OK", str(probs))

with NupReader(direct_aio_nup) as r:
    check(len(r.packages) == 2, "multi-package convert: contains 2 packages (Base + DLC)")
    check(r.packages[0].kind == F.KIND_BASE and r.packages[0].title_id == synth_tid,
          "multi-package convert: package 0 is Base")
    check(r.packages[1].kind == F.KIND_ADDON and r.packages[1].title_id == dlc_tid,
          "multi-package convert: package 1 is Addon (DLC)")

aio_extract = os.path.join(work, "aio_extracted")
with NupReader(direct_aio_nup) as r:
    extract_tree(r, aio_extract, r.packages[1].root_dir)
check(os.path.isfile(os.path.join(aio_extract, "romfs", "dlc_bonus.bin")),
      "multi-package convert: DLC romfs file extracted")
with open(os.path.join(aio_extract, "romfs", "dlc_bonus.bin"), "rb") as fh:
    check(fh.read() == b"DLC Bonus Content 99999",
          "multi-package convert: DLC content byte-identical")

# Directory source convert: directory containing base.nsp + dlc.nsp
dir_source = os.path.join(work, "dumps_dir")
os.makedirs(dir_source, exist_ok=True)
shutil.copyfile(synth_nsp_path, os.path.join(dir_source, "game_base.nsp"))
shutil.copyfile(synth_dlc_path, os.path.join(dir_source, "game_dlc.nsp"))
dir_aio_nup = os.path.join(work, "dir_aio.nup")
convert(Path(dir_source), Path(dir_aio_nup), threads=-1)
ok, probs = verify(dir_aio_nup, deep=True)
check(ok and not probs, "directory convert: verifies deep OK")
with NupReader(dir_aio_nup) as r:
    check(len(r.packages) == 2, "directory convert: auto-packages Base + DLC")

# CLI convert with --dlc and --threads
cli_aio_nup = os.path.join(work, "cli_aio.nup")
rc, out = cli(["convert", synth_nsp_path, cli_aio_nup, "--dlc", synth_dlc_path, "--threads", "-1", "-q"])
check(rc == 0 and os.path.isfile(cli_aio_nup), "CLI multi-package convert succeeds", out[:120])
ok, probs = verify(cli_aio_nup, deep=True)
check(ok and not probs, "CLI multi-package container verifies deep OK")

# ---------- R16: Batch Converter (nup batch) ----------
batch_in = os.path.join(work, "batch_input")
batch_out = os.path.join(work, "batch_output")
os.makedirs(batch_in, exist_ok=True)

# Game 1: Base + DLC
shutil.copyfile(synth_nsp_path, os.path.join(batch_in, "Game1_Base.nsp"))
shutil.copyfile(synth_dlc_path, os.path.join(batch_in, "Game1_DLC.nsp"))

# Game 2: Second Game Base
synth2_tid = 0x0100777788880000
synth2_npdm = bytearray(b"\0" * 0x40)
synth2_npdm[0:4] = b"ACI0"
struct.pack_into("<Q", synth2_npdm, 0x10, synth2_tid)
exefs2_bytes = build_pfs0([("main", b"NSO0" + b"\0" * 0x5C), ("main.npdm", bytes(synth2_npdm))])
romfs2_bytes = build_romfs([("game_data.bin", b"second game romfs payload")])
prog2_nca_bytes = build_nca(0, synth2_tid, 1, 2, exefs2_bytes, 0, 3, romfs2_bytes)

nacp2_data = bytearray(0x4000)
nacp2_data[0:0x20] = b"Second Game\0"
nacp2_data[0x200:0x220] = b"Antigravity\0"
nacp2_data[0x3060:0x3068] = b"2.0.0\0"
ctrl2_romfs_bytes = build_romfs([("control.nacp", bytes(nacp2_data))])
ctrl2_nca_bytes = build_nca(3, synth2_tid, 0, 3, ctrl2_romfs_bytes)

cnmt2_data = bytearray(0x20 + 0x38 * 2)
struct.pack_into("<QIBBH", cnmt2_data, 0, synth2_tid, 0, 0x80, 0, 0)
struct.pack_into("<H", cnmt2_data, 0x10, 2)
cnmt2_data[0x20 + 0x20:0x20 + 0x30] = bytes.fromhex(prog_cid)
struct.pack_into("<I", cnmt2_data, 0x20 + 0x30, len(prog2_nca_bytes))
cnmt2_data[0x20 + 0x36] = 1
cnmt2_data[0x20 + 0x38 + 0x20:0x20 + 0x38 + 0x30] = bytes.fromhex(ctrl_cid)
struct.pack_into("<I", cnmt2_data, 0x20 + 0x38 + 0x30, len(ctrl2_nca_bytes))
cnmt2_data[0x20 + 0x38 + 0x36] = 3

meta2_pfs0 = build_pfs0([("game.cnmt", bytes(cnmt2_data))])
meta2_nca_bytes = build_nca(1, synth2_tid, 1, 2, meta2_pfs0)

synth2_nsp_bytes = build_pfs0([
    (f"{prog_cid}.nca", prog2_nca_bytes),
    (f"{ctrl_cid}.nca", ctrl2_nca_bytes),
    ("game.cnmt.nca", meta2_nca_bytes),
])
synth2_nsp_path = os.path.join(batch_in, "Game2.nsp")
open(synth2_nsp_path, "wb").write(synth2_nsp_bytes)

# Run batch convert API
batch_res = batch_convert(batch_in, batch_out, threads=-1)
check(batch_res.total_games == 2, "batch convert: detected 2 game groups")
check(batch_res.succeeded == 2 and batch_res.failed == 0, "batch convert: both games converted")
check(len(batch_res.containers) == 2, "batch convert: 2 containers produced")

for c_path in batch_res.containers:
    ok, probs = verify(str(c_path), deep=True)
    check(ok and not probs, f"batch container verifies deep OK: {c_path.name}")

# Verify Game 1 has Base + DLC
game1_out = next(p for p in batch_res.containers if "Synthetic Game" in p.name or "Game1" in p.name)
with NupReader(str(game1_out)) as r:
    check(len(r.packages) == 2, "batch game 1: consolidated Base + DLC")

# Output dir inside input dir rejected cleanly
try:
    batch_convert(batch_in, os.path.join(batch_in, "sub_out"))
    check(False, "batch convert: nested out_dir should fail")
except UnpackError as exc:
    check("cannot be inside input directory" in str(exc), "batch convert: nested out_dir rejected cleanly")

# CLI batch
cli_batch_out = os.path.join(work, "cli_batch_output")
rc, out = cli(["batch", batch_in, cli_batch_out, "--threads", "-1", "-q"])
check(rc == 0 and os.path.isdir(cli_batch_out), "CLI batch convert succeeds", out[:120])
cli_batch_files = [f for f in os.listdir(cli_batch_out) if f.endswith(".nup")]
check(len(cli_batch_files) == 2, "CLI batch produced 2 containers")

# ---------- R17: LayeredFS Mod Patcher (nup patch) ----------
mod_dir = os.path.join(work, "test_mod")
mod_romfs = os.path.join(mod_dir, "romfs")
os.makedirs(mod_romfs, exist_ok=True)

# Replace existing romfs file and add a new one
open(os.path.join(mod_romfs, "game_data.bin"), "wb").write(b"PATCHED ROMFS DATA V2")
open(os.path.join(mod_romfs, "mod_extra.txt"), "wb").write(b"NEW MOD ASSET CONTENT")

patched_nup = os.path.join(work, "patched.nup")
patch_res = patch(direct_aio_nup, mod_dir, patched_nup, threads=-1)
check(patch_res.files_replaced == 1, "patch: 1 file replaced")
check(patch_res.files_added == 1, "patch: 1 file added")

ok, probs = verify(patched_nup, deep=True)
check(ok and not probs, "patched container verifies deep OK", str(probs))

patch_extract = os.path.join(work, "patched_extracted")
with NupReader(patched_nup) as r:
    check(len(r.packages) == 2, "patched container preserves all packages (Base + DLC)")
    extract_tree(r, patch_extract, r.packages[0].root_dir)

with open(os.path.join(patch_extract, "romfs", "game_data.bin"), "rb") as fh:
    check(fh.read() == b"PATCHED ROMFS DATA V2", "patched: replaced file content verified")
with open(os.path.join(patch_extract, "romfs", "mod_extra.txt"), "rb") as fh:
    check(fh.read() == b"NEW MOD ASSET CONTENT", "patched: added file content verified")
with open(os.path.join(patch_extract, "exefs", "main.npdm"), "rb") as fh:
    check(fh.read() == bytes(synth_npdm), "patched: exefs main.npdm untouched")

# In-place patching
inplace_nup = os.path.join(work, "inplace_test.nup")
shutil.copyfile(direct_aio_nup, inplace_nup)
in_res = patch(inplace_nup, mod_dir, threads=-1)
check(in_res.files_replaced == 1, "in-place patch: 1 file replaced")
ok, probs = verify(inplace_nup, deep=True)
check(ok and not probs, "in-place patched container verifies deep OK")

# Atmosphere contents layout detection: mod/contents/<tid>/romfs/...
atmo_dir = os.path.join(work, "atmo_mod")
atmo_romfs = os.path.join(atmo_dir, "contents", f"{synth_tid:016x}", "romfs")
os.makedirs(atmo_romfs, exist_ok=True)
open(os.path.join(atmo_romfs, "game_data.bin"), "wb").write(b"ATMOSPHERE PATCHED CONTENT")

atmo_out_nup = os.path.join(work, "atmo_patched.nup")
atmo_res = patch(direct_aio_nup, atmo_dir, atmo_out_nup, threads=-1)
check(atmo_res.files_replaced == 1, "Atmosphere contents patch: auto-detected tid and replaced file")
ok, probs = verify(atmo_out_nup, deep=True)
check(ok and not probs, "Atmosphere patched container verifies deep OK")

# CLI patch
cli_patch_nup = os.path.join(work, "cli_patched.nup")
rc, out = cli(["patch", direct_aio_nup, mod_dir, cli_patch_nup, "--threads", "-1", "-q"])
check(rc == 0 and os.path.isfile(cli_patch_nup), "CLI patch succeeds", out[:120])
ok, probs = verify(cli_patch_nup, deep=True)
check(ok and not probs, "CLI patched container verifies deep OK")

# ---------- R18: Container Exporter (nup export) ----------
# 1. Export Atmosphere SD format
export_atmo_dir = os.path.join(work, "export_atmo")
exp_atmo_res = export_container(direct_aio_nup, export_atmo_dir, fmt="atmosphere")
check(exp_atmo_res.format == "atmosphere", "export: format atmosphere")
check(os.path.isdir(os.path.join(export_atmo_dir, "atmosphere", "contents", f"{synth_tid:016X}", "romfs")),
      "export atmosphere: contents romfs directory created")
with open(os.path.join(export_atmo_dir, "atmosphere", "contents", f"{synth_tid:016X}", "romfs", "game_data.bin"), "rb") as fh:
    check(fh.read() == b"synthetic romfs payload 12345", "export atmosphere: romfs file content verified")
check(os.path.isfile(os.path.join(export_atmo_dir, "atmosphere", "contents", f"{synth_tid:016X}", "exefs", "main.npdm")),
      "export atmosphere: exefs main.npdm present")

# 2. Export Dump layout
export_dump_dir = os.path.join(work, "export_dump")
exp_dump_res = export_container(direct_aio_nup, export_dump_dir, fmt="dump")
check(os.path.isfile(os.path.join(export_dump_dir, "base", "romfs", "game_data.bin")),
      "export dump: base romfs file present")
check(os.path.isfile(os.path.join(export_dump_dir, "dlc", f"{dlc_tid:016X}", "0", "romfs", "dlc_bonus.bin")),
      "export dump: dlc romfs file present")
check(os.path.isfile(os.path.join(export_dump_dir, "_meta", "info.txt")),
      "export dump: _meta info.txt present")

# 3. Export Repacked NSP
export_nsp_dir = os.path.join(work, "export_nsp")
exp_nsp_res = export_container(direct_aio_nup, export_nsp_dir, fmt="nsp")
check(exp_nsp_res.output_path.is_file() and exp_nsp_res.output_path.suffix.lower() == ".nsp",
      "export nsp: .nsp file produced")

# Round-trip unpack test: unpack the exported NSP and verify extracted files match!
re_unpacked_dir = os.path.join(work, "re_unpacked_nsp")
unpack(exp_nsp_res.output_path, Path(re_unpacked_dir), no_control=True)
check(os.path.isfile(os.path.join(re_unpacked_dir, "base", "romfs", "game_data.bin")),
      "repacked nsp roundtrip: base romfs file extracted")
with open(os.path.join(re_unpacked_dir, "base", "romfs", "game_data.bin"), "rb") as fh:
    check(fh.read() == b"synthetic romfs payload 12345",
          "repacked nsp roundtrip: content byte-identical")

# 4. CLI export
cli_export_dir = os.path.join(work, "cli_export_atmo")
rc, out = cli(["export", direct_aio_nup, cli_export_dir, "--format", "atmosphere", "-q"])
check(rc == 0 and os.path.isdir(cli_export_dir), "CLI export succeeds", out[:120])

# ---------- summary ----------
print()
if fails:
    print(f"FAILED {len(fails)} checks:")
    for f in fails:
        print("  -", f)
    sys.exit(1)
print("ALL CHECKS PASSED")
shutil.rmtree(work, ignore_errors=True)
