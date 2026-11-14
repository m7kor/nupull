"""Generate _build_meta.py with current Git commit SHA."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1].strip():
        commit = sys.argv[1].strip()
    else:
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip()

    out_path = Path(__file__).resolve().parent / "nup" / "nup" / "_build_meta.py"
    out_path.write_text(f"COMMIT = '{commit}'\n", encoding="utf-8")
    print(f"Generated {out_path} with COMMIT = '{commit}'")


if __name__ == "__main__":
    main()
