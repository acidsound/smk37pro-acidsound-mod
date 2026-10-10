#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fetch the pinned upstream SLOOP (sloop-fm1) tree this port is built on.

    tools/fetch_sloop.py [DEST]

DEST defaults to sloop-smk37/upstream/sloop-fm1. The commit is pinned in
sloop-smk37/SLOOP_PIN (see PROVENANCE.md); a shallow fetch of exactly that
commit is verified before the build accepts the tree. Offline-safe: an
existing DEST at the pinned commit is reused as is (set SLOOP_SRC to any
checkout to bypass fetching altogether).
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PIN_FILE = ROOT / "SLOOP_PIN"
UPSTREAM = "https://github.com/isod89/sloop-fm1.git"
REQUIRED = ["firmware/src/felucca.c", "firmware/hal/fm1_input.h", "firmware/app.ld",
            "tools/build.py", "tools/gen_tables.py", "tests/hostsim.c"]


def pin() -> str:
    return PIN_FILE.read_text().split()[0]


def main() -> int:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "upstream" / "sloop-fm1"
    want = pin()
    if dest.exists():
        r = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == want:
            print(f"fetch_sloop: {dest} already at {want}")
            return 0
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(dest)], check=True)
    subprocess.run(["git", "-C", str(dest), "remote", "add", "origin", UPSTREAM],
                   check=False)
    subprocess.run(["git", "-C", str(dest), "fetch", "--depth", "1", "origin", want],
                   check=True)
    subprocess.run(["git", "-C", str(dest), "checkout", "-q", "FETCH_HEAD"], check=True)
    got = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    if got != want:
        sys.exit(f"fetch_sloop: fetched {got}, pin is {want}")
    missing = [p for p in REQUIRED if not (dest / p).exists()]
    if missing:
        sys.exit(f"fetch_sloop: {dest} lacks {missing}")
    print(f"fetch_sloop: {dest} at {want}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
