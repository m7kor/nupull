"""NUP verifier: structural conformance + deep content verification."""

from __future__ import annotations

import hashlib
from collections.abc import Callable

from . import format as F
from .read import NupReader


def verify(
    path: str,
    deep: bool = False,
    progress: Callable[[int, int, int], None] | None = None,
) -> tuple[bool, list[str]]:
    """Returns (ok, problems). `deep` recomputes every file's SHA-256.

    `progress` (optional) is called with (done, total, bytes_done) per file
    during the deep pass so front-ends can show live tracking.
    """
    problems: list[str] = []
    try:
        r = NupReader(path)
    except F.NupError as e:
        return False, [f"open: {e}"]
    except OSError as e:
        # missing/unreadable file: verify() reports problems, it does not raise
        return False, [f"open: {type(e).__name__}: {e}"]

    def fail(msg: str) -> None:
        problems.append(msg)

    # slot overlap check: ranges must be disjoint
    ranges = sorted((first, first + count, i)
                    for i, (_, first, count) in enumerate(r.dirs))
    for (a1, a2, ai), (b1, b2, bi) in zip(ranges, ranges[1:]):
        if a2 > b1:
            fail(f"child slot ranges overlap: dirs {ai} and {bi}")

    # sorted + unique children per dir (producer conformance §6.2)
    for di, (name, first, count) in enumerate(r.dirs):
        kids = r.children[first:first + count]
        names = []
        for cid in kids:
            if cid >= r.dir_count:
                names.append(r.files[cid - r.dir_count][0])
            else:
                names.append(r.dirs[cid][0])
        if names != sorted(names):
            fail(f"dir {di} ({name!r}): children not sorted")
        if len(set(names)) != len(names):
            fail(f"dir {di} ({name!r}): duplicate child names")

    # one global traversal from package roots: cycle + orphan detection, O(n)
    visited: set[int] = set()
    for p in r.packages:
        stack: list[tuple[int, tuple[int, ...]]] = [(p.root_dir, (p.root_dir,))]
        while stack:
            di, path_ids = stack.pop()
            if di in path_ids[:-1]:
                fail(f"cycle detected through dir {di}")
                continue
            if di in visited:
                continue
            visited.add(di)
            _, first, count = r.dirs[di]
            for cid in r.children[first:first + count]:
                if cid < r.dir_count:
                    stack.append((cid, path_ids + (cid,)))
    orphans = set(range(r.dir_count)) - visited
    if orphans:
        fail(f"{len(orphans)} unreachable dir nodes (orphans)")

    referenced: set[int] = {cid - r.dir_count for cid in r.children if cid >= r.dir_count}
    unreferenced = set(range(r.file_count)) - referenced
    if unreferenced:
        names = [r.files[fi][0] for fi in sorted(unreferenced)[:8]]
        more = "..." if len(unreferenced) > len(names) else ""
        fail(f"{len(unreferenced)} file node(s) not referenced by any child slot "
             f"(unextractable): {[n.decode('utf-8', 'replace') for n in names]}{more}")

    if deep:
        seen_extents: dict[tuple[int, int, int], bytes] = {}
        total = len(r.files)
        bytes_done = 0
        for fi, (name, size, sha, eoff, esz, codec) in enumerate(r.files):
            if progress:
                progress(fi, total, bytes_done)
            try:
                data = r.read_file(fi)
            except F.NupError as e:
                fail(f"file {fi} ({name!r}): read failed: {e}")
                bytes_done += size
                continue
            except Exception as e:
                # zstd framing errors etc. on crafted input: report the file,
                # keep verifying the rest instead of aborting the run
                fail(f"file {fi} ({name!r}): read failed: {type(e).__name__}: {e}")
                bytes_done += size
                continue
            if hashlib.sha256(data).digest() != sha:
                fail(f"file {fi} ({name!r}): SHA-256 mismatch")
            if codec == F.CODEC_RAW and esz != size:
                fail(f"file {fi} ({name!r}): raw extent size {esz} != {size}")
            key = (eoff, esz, codec)
            if key in seen_extents:
                if seen_extents[key] != sha:
                    fail(f"file {fi} ({name!r}): shares extent with different hash")
            else:
                seen_extents[key] = sha
            bytes_done += size
        if progress:
            progress(total, total, bytes_done)

    r.close()
    return not problems, problems
