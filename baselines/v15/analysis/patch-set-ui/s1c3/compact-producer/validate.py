#!/usr/bin/env python3
"""Offline validator for generated S1-C3 compact producer artifacts."""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
sys.path.insert(0, str(HERE))

import build_compact_producer  # noqa: E402


def main() -> int:
    lines = build_compact_producer.run(write=False, check_files=True)
    sums = HERE / "SHA256SUMS"
    if not sums.exists():
        raise SystemExit("FAIL: SHA256SUMS missing")
    subprocess.run(["shasum", "-a", "256", "-c", "SHA256SUMS"], cwd=HERE, check=True)
    print("S1-C3 compact sequential producer validation: PASS")
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
