#!/usr/bin/env python3
"""Extract and hash-lock the stock FWSC UFW flash.bin representation.

This is an offline evidence tool. It never opens USB and never writes device
Flash. The FWSC file is used only as the historical source container for the
already-reviewed stock-v12 flash.bin representation; it is not a recovery
writer input.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import tempfile

from smk37_app_patch import (
    FWSC_BLOCK_SIZE,
    FWSC_DATA_SIZE,
    FWSC_SLOTS,
    Ufw,
    decode_fwsc_metadata,
)


EXPECTED_PACKAGE_SIZE = 701_140
EXPECTED_PACKAGE_SHA256 = (
    "c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a"
)
EXPECTED_FLASH_SIZE = 638_976
EXPECTED_FLASH_SHA256 = (
    "f36327e48e012845d69f661441a70beefc1eafad4acd02321de99345392e169a"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_flash(package: Path) -> bytes:
    raw = package.read_bytes()
    if len(raw) != EXPECTED_PACKAGE_SIZE:
        raise SystemExit(f"package size mismatch: {len(raw)}")
    if sha256(raw) != EXPECTED_PACKAGE_SHA256:
        raise SystemExit("package SHA-256 mismatch")

    decode_fwsc_metadata(raw)
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])

    flash = bytes(Ufw.parse(payload).flash())
    if len(flash) != EXPECTED_FLASH_SIZE:
        raise SystemExit(f"flash.bin size mismatch: {len(flash)}")
    if sha256(flash) != EXPECTED_FLASH_SHA256:
        raise SystemExit("flash.bin SHA-256 mismatch")
    return flash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    flash = extract_flash(args.package)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="wb", dir=args.output.parent, prefix=args.output.name + ".", delete=False
    ) as handle:
        handle.write(flash)
        temporary = Path(handle.name)
    temporary.replace(args.output)

    print(f"output: {args.output}")
    print(f"size: {len(flash)}")
    print(f"sha256: {sha256(flash)}")
    print("PASS: offline FWSC-unpacked stock flash.bin validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
