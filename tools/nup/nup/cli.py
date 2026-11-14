"""nup - reference CLI for the NUP (NX Package) format."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import sys
import time
from typing import TYPE_CHECKING 

from . import format as F
from .access import app_meta, build_id, extract_tree, find_package, iter_children, \
    localized_titles, resolve_path, write_extracted_file
from . import edit as edit_cmd
from .discover import scan_source
from .pack import out_inside_src, pack
from .read import NupReader
from .verify import verify

if TYPE_CHECKING:
    from .discover import FileObj
    from .read import NodeRef


def _parse_kv_flags(default: str | None, lang_flags: list[str], what: str
                    ) -> dict[str | None, str]:
    """Merge --name/--icon (default language) with --lang-name/--lang-icon LANG=VALUE."""
    out: dict[str | None, str] = {}
    if default:
        out[None] = default
    for item in lang_flags or []:
        lang, sep, value = item.partition("=")
        if not sep or not value:
            raise SystemExit(f"nup: --lang-{what} expects LANG=VALUE, got {item!r}")
        out[lang.lower()] = value
    return out


def _title_id_arg(value: str | None) -> int | None:
    """Validate --title-id as 1..16 hex digits (u64) before packing uses it."""
    if not value:
        return None
    if not (1 <= len(value) <= 16) or any(
            c not in "0123456789abcdefABCDEF" for c in value):
        raise SystemExit(f"nup: --title-id expects 1-16 hex digits, got {value!r}")
    return int(value, 16)


def _cmd_pack(args: argparse.Namespace) -> int:
    t0 = time.time()
    last = [0.0]

    def progress(done: int, total: int, fnode: NodeRef | FileObj) -> None:
        now = time.time()
        if now - last[0] >= 0.5 or done == total:
            last[0] = now
            pct = done * 100 // total if total else 100
            sys.stdout.write(f"\rpack: {done}/{total} files ({pct}%)")
            sys.stdout.flush()

    packages = pack(args.output, args.source, level=args.level,
                    keep_listings=args.keep_listings,
                    base_title_id=_title_id_arg(args.title_id),
                    display_version=args.display_version,
                    publisher=args.publisher,
                    names=_parse_kv_flags(args.name, args.lang_name, "name"),
                    icons=_parse_kv_flags(args.icon, args.lang_icon, "icon"),
                    split=args.split,
                    progress=None if args.quiet else progress)
    if not args.quiet:
        print()
    for p in packages:
        print(f"  {F.KIND_NAMES[p.kind]:<6} {p.title_id:016X} v{p.version} <- {p.src}")
    print(f"pack: wrote {args.output} in {time.time() - t0:.1f}s")
    return 0


def _print_tree(r: NupReader, dir_index: int, prefix: str, max_depth: int, depth: int = 0,
                show_files: bool = True) -> None:
    for child in iter_children(r, dir_index):
        label = child.name.decode("utf-8", "surrogateescape")
        if child.is_dir:
            print(f"{prefix}{label}/")
            if depth + 1 < max_depth:
                _print_tree(r, child.index, prefix + "  ", max_depth, depth + 1, show_files)
            elif any(c.is_dir for c in iter_children(r, child.index)):
                print(f"{prefix}  ...")
        elif show_files:
            name, size, sha, eoff, esz, codec = r.file_info(child.index)
            tag = "zstd" if codec == F.CODEC_ZSTD else ("raw" if size else "empty")
            print(f"{prefix}{label}  [{size} B, {tag}]")


def _cmd_info(args: argparse.Namespace) -> int:
    with NupReader(args.file) as r:
        s = r.super
        uuid = s["uuid"].hex()
        print(f"file:      {args.file}")
        print(f"version:   NUP v1 (header 0x{s['header_size']:x}, v{s['header_version']})")
        print(f"size:      {s['file_size']:,} bytes")
        print(f"uuid:      {uuid[:8]}-{uuid[8:12]}-{uuid[12:16]}")
        print(f"toc:       @{s['toc_offset']:#x} +{s['toc_size']:,} B")
        print(f"blobs:     @{s['blob_offset']:#x}")
        print(f"packages:  {len(r.packages)}  (dirs {r.dir_count}, files {r.file_count})")
        for p in r.packages:
            meta = app_meta(r, p)
            name = meta.get(F.TLV_TITLE_NAME, b"").decode("utf-8", "replace")
            pub = meta.get(F.TLV_PUBLISHER, b"").decode("utf-8", "replace")
            label = f" {name!r}" if name else ""
            if pub:
                label += f" by {pub!r}"
            if p.kind == F.KIND_UPDATE and (p.flags & F.PKG_FLAG_STANDALONE_UPDATE):
                label += " [standalone]"
            # Version reporting: the display version TLV is the truth. The raw
            # NCM value decodes to major.minor.micro only on Switch 1; Switch 2
            # titles store a per-title content revision counter there (one
            # 0x10000 step per released update), so label revision-aligned
            # values as revisions instead of pretending the decode is a version.
            disp = meta.get(F.TLV_DISPLAY_VERSION, b"").decode("utf-8", "replace")
            if disp:
                ver = f"display {disp} (NCM v{p.version:#x})"
            elif p.version == 0:
                ver = "no version stored"
            elif p.version & 0xFFFF == 0:
                ver = f"content revision {p.version >> 16} (NCM v{p.version:#x}; " \
                      f"S1-style decode {p.version_str}, display unknown)"
            else:
                ver = f"{p.version_str} (NCM v{p.version:#x})"
            print(f"  [{p.index}] {p.kind_name:<6} {p.title_id:016X} {ver}{label}")
            loc = localized_titles(r, p)
            if loc:
                langs = ", ".join(f"{l.decode()}={n.decode('utf-8', 'replace')!r}"
                                  for l, n in sorted(loc.items()))
                print(f"         localized: {langs}")
            bid = build_id(r, p)
            if bid:
                print(f"         build-id: {bid.rstrip(bytes(1)).hex().upper()}")
            if not args.tree:
                continue
            if p.exefs_dir != F.NO_DIR:
                print(f"      exefs/")
                _print_tree(r, p.exefs_dir, "        ", args.depth)
            if p.romfs_dir != F.NO_DIR:
                print(f"      romfs/  (top {args.depth} levels)")
                _print_tree(r, p.romfs_dir, "        ", args.depth, show_files=False)
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    with NupReader(args.file) as r:
        for fi, (name, size, sha, eoff, esz, codec) in enumerate(r.files):
            tag = "zstd" if codec == F.CODEC_ZSTD else ("raw" if size else "empty")
            print(f"{fi:>8}  {size:>12}  {tag:<4}  {name.decode('utf-8', 'surrogateescape')}")
    return 0


def _cmd_extract(args: argparse.Namespace) -> int:
    with NupReader(args.file) as r:
        if args.flat:
            # Rescue mode: dump the file table directly, ignoring the directory
            # tree. Recovers content from containers whose children array is
            # broken (files present but not linked into any directory).
            os.makedirs(args.dest, exist_ok=True)
            n = 0
            for fi in range(r.file_count):
                name, size, sha, eoff, esz, codec = r.file_info(fi)
                # the index prefix keeps names unique and non-empty; strip
                # anything that could still denote a path component (§6.1.5)
                label = name.decode("utf-8", "surrogateescape")
                for ch in "/\\:*?\"<>|\0":
                    label = label.replace(ch, "_")
                target = os.path.join(args.dest, f"{fi:05d}_{label}")
                write_extracted_file(r, fi, target)
                n += 1
            print(f"extract: {n} files -> {args.dest}")
            return 0
        pkg = find_package(r, kind=_kind_arg(args.package)) if args.package else r.packages[0]
        if pkg is None:
            print(f"extract: no package matches {args.package!r}", file=sys.stderr)
            return 1
        src_dir = pkg.root_dir
        if args.subtree:
            ref = resolve_path(r, pkg, args.subtree)
            if ref is None:
                print(f"extract: no such subtree {args.subtree!r}", file=sys.stderr)
                return 1
            if not ref.is_dir:
                print(f"extract: {args.subtree!r} is a file; use the tree root", file=sys.stderr)
                return 1
            src_dir = ref.index
        n = extract_tree(r, args.dest, src_dir)
        print(f"extract: {n} files -> {args.dest}")
    return 0


def _kind_arg(name: str) -> int | None:
    for k, v in F.KIND_NAMES.items():
        if v == name:
            return k
    try:
        return int(name, 0)
    except ValueError:
        return None


def _cmd_verify(args: argparse.Namespace) -> int:
    ok, problems = verify(args.file, deep=not args.fast)
    if ok:
        print(f"verify: OK ({'deep' if not args.fast else 'fast'}) - {args.file}")
        return 0
    print(f"verify: FAILED - {args.file}")
    for p in problems[:args.max_problems]:
        print(f"  - {p}")
    if len(problems) > args.max_problems:
        print(f"  ... and {len(problems) - args.max_problems} more")
    return 1


def _cmd_auto(args: argparse.Namespace) -> int:
    """One-shot pipeline: scan -> pack -> deep verify, nothing manual."""
    src, out = args.source, args.output
    if not os.path.isdir(src):
        print(f"nup: auto: source is not a directory: {src}", file=sys.stderr)
        return 2
    if not out.lower().endswith(".nup"):
        out += ".nup"
    if out_inside_src(out, src):
        # check BEFORE the --force remove: a .nup inside the dump would be
        # swallowed by pack's own walk of the source (and --force would
        # delete a source file)
        print(f"nup: auto: refusing to write {out} inside the source tree "
              f"{src} - choose an output outside the dump", file=sys.stderr)
        return 2
    if os.path.exists(out):
        if not args.force:
            print(f"nup: auto: refusing to overwrite {out} "
                  "(pass --force to replace)", file=sys.stderr)
            return 2
        # do NOT delete the old file up front: pack(replace=True) swaps the
        # new container in atomically on success, so a failed rebuild keeps
        # the previous good output intact
    replacing = os.path.exists(out)
    parent = os.path.dirname(os.path.abspath(out))
    if parent:
        os.makedirs(parent, exist_ok=True)

    t0 = time.time()
    last = [0.0]

    def tick(label: str, done: int, total: int) -> None:
        now = time.time()
        if now - last[0] >= 0.5 or done == total:
            last[0] = now
            pct = done * 100 // total if total else 100
            sys.stdout.write(f"\r{label}: {done}/{total} ({pct}%)")
            sys.stdout.flush()

    # 1) scan — totals the packer will match
    if not args.quiet:
        print(f"auto: scanning {src} ...")
    try:
        files, nbytes = scan_source(src)
    except SystemExit as e:
        print(f"nup: auto: {e}", file=sys.stderr)
        return 2
    if files == 0:
        print("nup: auto: no packable files found in dump", file=sys.stderr)
        return 2
    if not args.quiet:
        print(f"auto: {files:,} files, {nbytes:,} bytes to pack")
    # warn early instead of dying on disk-full minutes into the pack
    # (heuristic: a packed container is typically well under half the dump)
    try:
        free = shutil.disk_usage(parent or os.curdir).free
    except OSError:
        free = -1
    if 0 <= free < max(nbytes // 2, 1 << 30):
        print(f"nup: auto: warning: only {free / (1 << 30):.1f} GB free for a "
              f"{nbytes / (1 << 30):.1f} GB dump - the output may not fit",
              file=sys.stderr)

    # 2) pack
    def pack_progress(done: int, total: int, fnode: FileObj) -> None:
        if not args.quiet:
            tick("pack", done, total)

    packages = pack(out, src, level=args.level, replace=replacing,
                    progress=pack_progress)
    if not args.quiet:
        print()
    for p in packages:
        print(f"  {F.KIND_NAMES[p.kind]:<6} {p.title_id:016X} "
              f"v{p.version} <- {p.src}")

    # 3) deep verify — the output only counts if every hash matches
    def verify_progress(done: int, total: int, _bytes: int) -> None:
        if not args.quiet:
            tick("verify", done, total)

    ok, problems = verify(out, deep=not args.fast, progress=verify_progress)
    if not args.quiet:
        print()
    if not ok:
        print(f"auto: FAILED verify - {out}", file=sys.stderr)
        for prob in problems[:20]:
            print(f"  - {prob}", file=sys.stderr)
        return 1

    size = os.path.getsize(out)
    print(f"auto: OK - {out} ({size:,} bytes, {files:,} files, "
          f"{time.time() - t0:.1f}s)")
    return 0


def _cmd_unpack(args: argparse.Namespace) -> int:
    from .switchfs import unpack, Progress, UnpackError, CancelledError

    src = Path(args.source)
    out = Path(args.out_dir)
    keys_p = Path(args.keys) if args.keys else None
    tkeys_p = Path(args.title_keys) if args.title_keys else None
    base_p = Path(args.base) if args.base else None

    t0 = time.time()
    last = [0.0]
    seen_warnings: set[str] = set()

    def on_progress(p: Progress) -> None:
        if args.quiet:
            return
        now = time.time()
        for w in p.warnings:
            if w not in seen_warnings:
                seen_warnings.add(w)
                sys.stdout.write(f"\r\033[Kwarning: {w}\n")
                sys.stdout.flush()

        if now - last[0] >= 0.25 or p.stage == "done":
            last[0] = now
            elapsed = now - t0
            speed = p.bytes_done / elapsed if elapsed > 0.5 else 0.0
            eta = (p.bytes_total - p.bytes_done) / speed if speed > 0 and p.bytes_total > p.bytes_done else 0.0
            pct = (p.bytes_done * 100 // p.bytes_total) if p.bytes_total else 0

            speed_str = f"{speed / (1024 * 1024):.1f} MB/s" if speed >= 1024 * 1024 else f"{speed / 1024:.1f} KB/s"
            eta_str = f"{int(eta)}s" if eta < 3600 else f"{int(eta // 3600)}h{int((eta % 3600) // 60)}m"
            cur = p.current
            if len(cur) > 35:
                cur = "..." + cur[-32:]
            msg = f"\runpack: {p.stage} {p.bytes_done:,}/{p.bytes_total:,} ({pct}%) [{speed_str}, ETA {eta_str}] {cur}"
            sys.stdout.write(msg.ljust(80)[:80])
            sys.stdout.flush()

    try:
        unpack(
            src,
            out,
            keys_path=keys_p,
            title_keys_path=tkeys_p,
            base=base_p,
            no_control=args.no_control,
            replace=args.force,
            progress=on_progress,
        )
    except CancelledError:
        if not args.quiet:
            sys.stdout.write("\n")
        print("nup: unpack cancelled", file=sys.stderr)
        return 130
    except UnpackError as exc:
        if not args.quiet:
            sys.stdout.write("\n")
        print(f"nup: unpack: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        sys.stdout.write("\n")

    print(f"unpack: OK - {src} -> {out} ({time.time() - t0:.1f}s)")
    base_dir = out / "base"
    if base_dir.is_dir():
        print(f"  base:    {base_dir}")
    upd_dir = out / "updates"
    if upd_dir.is_dir():
        for u in sorted(upd_dir.iterdir()):
            if u.is_dir():
                print(f"  update:  {u}")
    dlc_dir = out / "dlc"
    if dlc_dir.is_dir():
        for d in sorted(dlc_dir.iterdir()):
            if d.is_dir():
                print(f"  dlc:     {d}")
    meta_dir = out / "_meta"
    if meta_dir.is_dir():
        print(f"  meta:    {meta_dir}")

    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    from .convert import convert
    from .switchfs import Progress, UnpackError, CancelledError

    src = Path(args.source)
    out = Path(args.output)
    keys_p = Path(args.keys) if args.keys else None
    tkeys_p = Path(args.title_keys) if args.title_keys else None
    base_p = Path(args.base) if args.base else None

    t0 = time.time()
    last = [0.0]
    seen_warnings: set[str] = set()

    def on_progress(p: Progress) -> None:
        if args.quiet:
            return
        now = time.time()
        for w in p.warnings:
            if w not in seen_warnings:
                seen_warnings.add(w)
                sys.stdout.write(f"\r\033[Kwarning: {w}\n")
                sys.stdout.flush()

        if now - last[0] >= 0.25 or p.stage == "done":
            last[0] = now
            elapsed = now - t0
            speed = p.bytes_done / elapsed if elapsed > 0.5 else 0.0
            eta = (p.bytes_total - p.bytes_done) / speed if speed > 0 and p.bytes_total > p.bytes_done else 0.0
            pct = (p.bytes_done * 100 // p.bytes_total) if p.bytes_total else 0

            speed_str = f"{speed / (1024 * 1024):.1f} MB/s" if speed >= 1024 * 1024 else f"{speed / 1024:.1f} KB/s"
            eta_str = f"{int(eta)}s" if eta < 3600 else f"{int(eta // 3600)}h{int((eta % 3600) // 60)}m"
            cur = p.current
            if len(cur) > 35:
                cur = "..." + cur[-32:]
            msg = f"\rconvert: {p.stage} {p.bytes_done:,}/{p.bytes_total:,} ({pct}%) [{speed_str}, ETA {eta_str}] {cur}"
            sys.stdout.write(msg.ljust(80)[:80])
            sys.stdout.flush()

    try:
        pkgs = convert(
            src,
            out,
            keys_path=keys_p,
            title_keys_path=tkeys_p,
            base=base_p,
            updates=args.updates,
            dlcs=args.dlcs,
            merge_siblings=args.merge_siblings,
            threads=args.threads,
            level=args.level,
            replace=args.force,
            fast=args.fast,
            name=args.name,
            publisher=args.publisher,
            display_version=args.display_version,
            no_control=args.no_control,
            progress=on_progress,
        )
    except CancelledError:
        if not args.quiet:
            sys.stdout.write("\n")
        print("nup: convert cancelled", file=sys.stderr)
        return 130
    except (UnpackError, SystemExit) as exc:
        if not args.quiet:
            sys.stdout.write("\n")
        print(f"nup: convert: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        sys.stdout.write("\n")

    sz = os.path.getsize(out)
    sz_str = f"{sz / (1024 * 1024):.1f} MB" if sz >= 1024 * 1024 else f"{sz / 1024:.1f} KB"
    print(f"convert: OK - {src} -> {out} ({sz_str}, {len(pkgs)} package(s), {time.time() - t0:.1f}s)")
    return 0


def _cmd_batch(args: argparse.Namespace) -> int:
    from .batch import batch_convert
    from .switchfs import Progress, UnpackError, CancelledError

    in_dir = Path(args.source)
    out_dir = Path(args.output)
    keys_p = Path(args.keys) if args.keys else None
    tkeys_p = Path(args.title_keys) if args.title_keys else None

    t0 = time.time()

    def on_progress(p: Progress) -> None:
        if args.quiet:
            return
        pct = (p.done * 100 // p.total) if p.total else 0
        cur = p.current
        if len(cur) > 35:
            cur = "..." + cur[-32:]
        msg = f"\rbatch: [{p.done}/{p.total}] ({pct}%) {cur}"
        sys.stdout.write(msg.ljust(80)[:80])
        sys.stdout.flush()

    try:
        res = batch_convert(
            in_dir,
            out_dir,
            keys_path=keys_p,
            title_keys_path=tkeys_p,
            threads=args.threads,
            level=args.level,
            replace=args.force,
            fast=args.fast,
            no_control=args.no_control,
            progress=on_progress,
        )
    except CancelledError:
        if not args.quiet:
            sys.stdout.write("\n")
        print("nup: batch cancelled", file=sys.stderr)
        return 130
    except (UnpackError, SystemExit) as exc:
        if not args.quiet:
            sys.stdout.write("\n")
        print(f"nup: batch: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        sys.stdout.write("\n")

    elapsed = time.time() - t0
    if res.failed == 0:
        print(f"batch: OK - {res.succeeded}/{res.total_games} game(s) converted to {out_dir} ({elapsed:.1f}s)")
        return 0
    else:
        print(f"batch: {res.succeeded}/{res.total_games} game(s) succeeded, {res.failed} failed ({elapsed:.1f}s):", file=sys.stderr)
        for label, err in res.errors.items():
            print(f"  - {label}: {err}", file=sys.stderr)
        return 1


def _cmd_patch(args: argparse.Namespace) -> int:
    from .patch import patch
    from .switchfs import Progress, CancelledError
    from . import format as F

    container_p = Path(args.container)
    mod_p = Path(args.mod)
    out_p = Path(args.output) if args.output else None

    t0 = time.time()

    def on_progress(p: Progress) -> None:
        if args.quiet:
            return
        pct = (p.bytes_done * 100 // p.bytes_total) if p.bytes_total else 0
        cur = p.current
        if len(cur) > 35:
            cur = "..." + cur[-32:]
        msg = f"\rpatch: {p.stage} {p.done}/{p.total} ({pct}%) {cur}"
        sys.stdout.write(msg.ljust(80)[:80])
        sys.stdout.flush()

    try:
        res = patch(
            container_p,
            mod_p,
            out_p,
            package=args.package,
            threads=args.threads,
            level=args.level,
            replace=args.force,
            fast=args.fast,
            progress=on_progress,
        )
    except CancelledError:
        if not args.quiet:
            sys.stdout.write("\n")
        print("nup: patch cancelled", file=sys.stderr)
        return 130
    except (F.NupError, SystemExit) as exc:
        if not args.quiet:
            sys.stdout.write("\n")
        print(f"nup: patch: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        sys.stdout.write("\n")

    elapsed = time.time() - t0
    dest_str = str(res.container_path)
    print(f"patch: OK - {res.files_replaced} replaced, {res.files_added} added "
          f"({res.total_files} total) in {dest_str} ({elapsed:.1f}s)")
    return 0


def _cmd_export(args: argparse.Namespace) -> int:
    from .export import export_container
    from .switchfs import Progress, CancelledError
    from . import format as F

    container_p = Path(args.container)
    out_dir = Path(args.output)
    keys_p = Path(args.keys) if args.keys else None
    tkeys_p = Path(args.title_keys) if args.title_keys else None

    t0 = time.time()

    def on_progress(p: Progress) -> None:
        if args.quiet:
            return
        pct = (p.bytes_done * 100 // p.bytes_total) if p.bytes_total else 0
        cur = p.current
        if len(cur) > 35:
            cur = "..." + cur[-32:]
        msg = f"\rexport: {p.stage} {p.done}/{p.total} ({pct}%) {cur}"
        sys.stdout.write(msg.ljust(80)[:80])
        sys.stdout.flush()

    try:
        res = export_container(
            container_p,
            out_dir,
            fmt=args.format,
            package=args.package,
            keys_path=keys_p,
            title_keys_path=tkeys_p,
            replace=args.force,
            progress=on_progress,
        )
    except CancelledError:
        if not args.quiet:
            sys.stdout.write("\n")
        print("nup: export cancelled", file=sys.stderr)
        return 130
    except (F.NupError, SystemExit) as exc:
        if not args.quiet:
            sys.stdout.write("\n")
        print(f"nup: export: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        sys.stdout.write("\n")

    elapsed = time.time() - t0
    dest_str = str(res.output_path)
    print(f"export: OK - {res.files_exported} files ({res.format}) written to {dest_str} ({elapsed:.1f}s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    from . import __version__
    ap = argparse.ArgumentParser(
        prog="nupull",
        description="Nupull — Modern NX Package (NUP) container studio",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack", help="pack a dump directory into an .nup")
    p.add_argument("source", help="dump dir (base/updates/dlc layout, or a content dir)")
    p.add_argument("output", help="output .nup path")
    p.add_argument("--level", type=int, default=3, help="zstd level (default 3)")
    p.add_argument("--title-id", help="override base title ID (16 hex digits)")
    p.add_argument("--display-version", help="store a display version string in meta")
    p.add_argument("--publisher", help="store a publisher string in meta (TLV 0x0006)")
    p.add_argument("--name", help="game title, default language (TLV 0x0005)")
    p.add_argument("--lang-name", action="append", metavar="LANG=NAME",
                   help="localized title, repeatable, BCP-47 tag (e.g. --lang-name ja=ゼルダ)")
    p.add_argument("--icon", metavar="PATH", help="icon image, default language (TLV 0x0003)")
    p.add_argument("--lang-icon", action="append", metavar="LANG=PATH",
                   help="localized icon, repeatable (e.g. --lang-icon ja=icon_ja.dat)")
    p.add_argument("--keep-listings", action="store_true", help="keep .listing artifacts")
    p.add_argument("--split", action="store_true",
                   help="write one .nup per package group instead of a single container: "
                        "base (boots alone), one per update (swap/downgrade by file), dlc")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(fn=_cmd_pack)

    edit_cmd.register(sub)

    p = sub.add_parser("info", help="show container info")
    p.add_argument("file")
    p.add_argument("--tree", action="store_true", help="also print trees")
    p.add_argument("--depth", type=int, default=2)
    p.set_defaults(fn=_cmd_info)

    p = sub.add_parser("list", help="list all file nodes")
    p.add_argument("file")
    p.set_defaults(fn=_cmd_list)

    p = sub.add_parser("extract", help="extract a package (or subtree) without replacing files")
    p.add_argument("file")
    p.add_argument("dest")
    p.add_argument("--package", help="kind name (base/update/addon) or index")
    p.add_argument("--subtree", help="relative path from package root, e.g. romfs")
    p.add_argument("--flat", action="store_true",
                   help="rescue mode: dump the file table directly, ignoring the "
                        "directory tree (for containers with a broken tree)")
    p.set_defaults(fn=_cmd_extract)

    p = sub.add_parser("verify", help="verify integrity (structure + per-file SHA-256)")
    p.add_argument("file")
    p.add_argument("--fast", action="store_true", help="skip per-file SHA-256 recompute")
    p.add_argument("--max-problems", type=int, default=20)
    p.set_defaults(fn=_cmd_verify)

    p = sub.add_parser(
        "auto",
        help="one-shot: scan a dump, pack it, deep-verify the result")
    p.add_argument("source", help="dump dir (base/updates/dlc, or a content dir)")
    p.add_argument("output", help="output .nup path (created for you)")
    p.add_argument("--level", type=int, default=3, help="zstd level (default 3)")
    p.add_argument("--force", action="store_true",
                   help="replace the output file if it already exists")
    p.add_argument("--fast", action="store_true",
                   help="skip the deep per-file SHA-256 recompute")
    p.add_argument("-q", "--quiet", action="store_true")
    p.set_defaults(fn=_cmd_auto)

    p = sub.add_parser("unpack", help="unpack an NSP/NSZ/XCI/XCZ/NCA dump")
    p.add_argument("source", help="source dump file (.nsp, .nsz, .xci, .xcz, .nca, .ncz)")
    p.add_argument("out_dir", help="output directory for dump layout")
    p.add_argument("--keys", help="path to prod.keys (overrides auto-discovery)")
    p.add_argument("--title-keys", help="path to title.keys (overrides auto-discovery)")
    p.add_argument("--base", help="path to base package for BKTR update RomFS merge")
    p.add_argument("--no-control", action="store_true", help="skip control NCA (_meta) extraction")
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing non-empty output directory")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.set_defaults(fn=_cmd_unpack)

    p = sub.add_parser("convert", help="directly convert an NSP/NSZ/XCI/XCZ dump into .nup")
    p.add_argument("source", help="source dump file (.nsp, .nsz, .xci, .xcz, .nca, .ncz)")
    p.add_argument("output", help="output .nup path")
    p.add_argument("--keys", help="path to prod.keys (overrides auto-discovery)")
    p.add_argument("--title-keys", help="path to title.keys (overrides auto-discovery)")
    p.add_argument("--base", help="path to base package for BKTR update RomFS merge")
    p.add_argument("--update", dest="updates", action="append", help="explicit update dump(s) to include")
    p.add_argument("--dlc", dest="dlcs", action="append", help="explicit DLC dump(s) to include")
    p.add_argument("--merge-siblings", action="store_true", help="auto-discover and merge sibling updates and DLCs")
    p.add_argument("--threads", type=int, default=0, help="compression worker threads (0=default single, -1=all cores)")
    p.add_argument("--no-control", action="store_true", help="skip control metadata and icons")
    p.add_argument("--level", type=int, default=3, help="zstd level (default 3)")
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing output file")
    p.add_argument("--fast", action="store_true", help="skip deep SHA-256 recompute")
    p.add_argument("--name", help="game title override")
    p.add_argument("--publisher", help="publisher string override")
    p.add_argument("--display-version", help="display version string override")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.set_defaults(fn=_cmd_convert)

    p = sub.add_parser("batch", help="batch convert all Switch dumps in a folder into .nup containers")
    p.add_argument("source", help="source directory containing Switch dumps")
    p.add_argument("output", help="destination directory for .nup containers")
    p.add_argument("--keys", help="path to prod.keys (overrides auto-discovery)")
    p.add_argument("--title-keys", help="path to title.keys (overrides auto-discovery)")
    p.add_argument("--threads", type=int, default=-1, help="compression worker threads (default -1 = all CPU cores)")
    p.add_argument("--level", type=int, default=19, help="zstd level (default 19)")
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing output containers")
    p.add_argument("--fast", action="store_true", help="skip deep SHA-256 recompute")
    p.add_argument("--no-control", action="store_true", help="skip control metadata and icons")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.set_defaults(fn=_cmd_batch)

    p = sub.add_parser("patch", help="apply a LayeredFS mod directory onto a .nup container")
    p.add_argument("container", help="target .nup container to patch")
    p.add_argument("mod", help="mod directory (LayeredFS romfs/exefs or Atmosphere contents)")
    p.add_argument("output", nargs="?", default=None, help="output .nup path (default: in-place modification)")
    p.add_argument("--package", help="target package title ID or index (default: base package)")
    p.add_argument("--threads", type=int, default=-1, help="compression worker threads (default -1 = all CPU cores)")
    p.add_argument("--level", type=int, default=19, help="zstd level (default 19)")
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing output file")
    p.add_argument("--fast", action="store_true", help="skip deep SHA-256 verification")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.set_defaults(fn=_cmd_patch)

    p = sub.add_parser("export", help="export a .nup container to Atmosphere SD layout, dump dir, or .nsp")
    p.add_argument("container", help="source .nup container")
    p.add_argument("output", help="output directory or .nsp file path")
    p.add_argument("--format", default="atmosphere", choices=["atmosphere", "layeredfs", "dump", "nsp"],
                   help="export format: atmosphere (default), dump, or nsp")
    p.add_argument("--package", help="package title ID or index to export (default: base game)")
    p.add_argument("--keys", help="path to prod.keys (for NSP export)")
    p.add_argument("--title-keys", help="path to title.keys")
    p.add_argument("-f", "--force", action="store_true", help="overwrite existing output file")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")
    p.set_defaults(fn=_cmd_export)

    args = ap.parse_args(argv)
    try:
        return int(args.fn(args))
    except KeyboardInterrupt:
        # Ctrl+C: pack() already removed its .partial output - exit cleanly
        # with a conventional code instead of dumping a traceback
        print("\nnup: interrupted", file=sys.stderr)
        return 130
    except F.NupError as e:
        print(f"nup: error: {e}", file=sys.stderr)
        return 2
    except Exception as e:
        # Fail closed with a clean message instead of a traceback: malformed
        # input surfaces as struct.error/OSError/ZstdError/etc. depending on
        # where it was hit. SystemExit (pack/edit user errors) propagates
        # untouched; KeyboardInterrupt is handled just above.
        print(f"nup: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
