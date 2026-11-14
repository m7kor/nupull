"""Verify standalone binary build metadata, provenance, and smoke test."""
from __future__ import annotations

import re
import subprocess
import sys


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("Usage: python tools/verify_build.py <expected_commit_sha>")
    expected = sys.argv[1].strip()

    # 1. Version check
    r_ver = subprocess.run(
        ["dist/Nupull.exe", "--version"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    print("Executable Version Output:", r_ver.stdout.strip())
    if r_ver.returncode != 0:
        sys.exit(f"CRITICAL: --version exited with code {r_ver.returncode}")

    # 2. Build info check & provenance assertion
    r_info = subprocess.run(
        ["dist/Nupull.exe", "--build-info"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    print(r_info.stdout)
    if r_info.returncode != 0:
        sys.exit(f"CRITICAL: --build-info exited with code {r_info.returncode}")

    m = re.search(r"Source Commit\s*:\s*([a-f0-9]{40})", r_info.stdout)
    if not m:
        sys.exit("CRITICAL: Failed to parse 40-character Source Commit from --build-info output!")
    embedded = m.group(1).strip()
    if embedded != expected:
        sys.exit(f"CRITICAL: Embedded commit ({embedded}) does not match expected Git HEAD ({expected})!")
    print(f"PROVENANCE VERIFIED: Executable embedded commit matches Git HEAD exactly ({embedded}).")

    # 3. GUI smoke test
    r_smoke = subprocess.run(
        ["dist/Nupull.exe", "--smoke", "--page", "auto"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    print(r_smoke.stdout)
    if "SMOKE-OK" not in r_smoke.stdout or r_smoke.returncode != 0:
        sys.exit(
            f"CRITICAL: Packaged executable failed GUI smoke test! "
            f"code={r_smoke.returncode}, output={r_smoke.stdout.strip()}"
        )
    print("GUI SMOKE TEST PASSED.")


if __name__ == "__main__":
    main()
