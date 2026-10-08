#!/usr/bin/env python3
"""Exact S1-C2 FWSC uploader gate.

This script validates the candidate package identity. It deliberately has no
transport implementation and performs no OTA/device action in this package.
"""
from __future__ import annotations
import argparse, hashlib
from pathlib import Path
EXPECTED_PACKAGE_SHA256 = "63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e"
def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("package", nargs="?", default="SMK37Pro-v15-S1C2-two-slot-selector-live.fwsc")
    p.add_argument("--attempt-upload", action="store_true", help="always refused in this offline artifact")
    args = p.parse_args()
    path = Path(args.package)
    if not path.is_absolute():
        path = Path(__file__).resolve().parent / path
    digest = sha(path)
    if digest != EXPECTED_PACKAGE_SHA256:
        raise SystemExit(f"refusing non-exact package: {digest}")
    print(f"exact package verified: {digest}")
    if args.attempt_upload:
        raise SystemExit("refusing upload: no device/OTA/flash/reset permitted by this package")
    print("validation only: no transport opened")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
