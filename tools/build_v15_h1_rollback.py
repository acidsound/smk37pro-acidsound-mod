#!/usr/bin/env python3
"""Build the offline-only guarded official-v15 rollback bundle for H1.

The output restores only sectors that differ between exact official v15 and the
exact H1 producer-unconsumed diagnostic package. It copies the already reviewed
R02 transport/restore implementation, then tightens identifiers, confirmations,
and sector allow-list to H1. This tool never opens USB or writes Flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

OFFICIAL_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
H1_PACKAGE_SHA256 = "139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf"
EXPECTED_SECTORS = (0x04000, 0x20000, 0x22000, 0x2A000, 0x62000)
SECTOR_SIZE = 0x1000
BUNDLE_NAME = "SMK37Pro-WL82-v15-H1-rollback-20260802-v1"
TEMPLATE_NAME = "SMK37Pro-WL82-v15-R02-rollback-20260802-v1"
CONFIRMATIONS = (
    "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_H1_SECTORS",
    "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_H1_TARGET_HASHES",
    "RESTORE_OFFICIAL_V15_SECTORS_NOW",
)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def flash_from_package(path: Path) -> bytes:
    raw = path.read_bytes()
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    return bytes(Ufw.parse(bytes(payload)).flash())


def patched_guard(template: str) -> str:
    result = template
    replacements = (
        ("v15 R02 rollback bundle", "v15 H1 rollback bundle"),
        ("exact four 4 KiB sectors", "exact five 4 KiB sectors"),
        ("{0x04000,0x20000,0x22000,0x2A000}", "{0x04000,0x20000,0x22000,0x2A000,0x62000}"),
        ("SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000}",
         "SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000, 0x62000}"),
        ("I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS", CONFIRMATIONS[0]),
        ("I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES", CONFIRMATIONS[1]),
        ("smk37-v15-r02-forced-recovery-plan-v1", "smk37-v15-h1-forced-recovery-plan-v1"),
        ("expected R02 hash", "expected H1 hash"),
        ("pre-erase R02 hash", "pre-erase H1 hash"),
        ("expected R02 target-sector hashes", "expected H1 target-sector hashes"),
        ("R02", "H1"),
        ("r02", "h1"),
    )
    for old, new in replacements:
        if old in result:
            result = result.replace(old, new)
    require("R02" not in result and "r02" not in result, "stale R02 token in H1 guard")
    for sector in ("0x04000", "0x20000", "0x22000", "0x2A000", "0x62000"):
        require(sector in result, f"H1 guard lacks sector {sector}")
    for confirmation in CONFIRMATIONS:
        require(confirmation in result, f"H1 guard missing confirmation: {confirmation}")
    return result


def patched_wrapper(template: str) -> str:
    result = template
    replacements = (
        ("I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS", CONFIRMATIONS[0]),
        ("I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES", CONFIRMATIONS[1]),
        ("R02", "H1"),
        ("r02", "h1"),
    )
    for old, new in replacements:
        if old in result:
            result = result.replace(old, new)
    require("R02" not in result and "r02" not in result, "stale R02 token in H1 elevated wrapper")
    for confirmation in CONFIRMATIONS:
        require(result.count(f"--confirm {confirmation}") == 1,
                f"H1 elevated wrapper confirmation mismatch: {confirmation}")
    return result


def write_hashes(root: Path) -> None:
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"):
        entries.append(f"{digest(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")


def write_zip(root: Path, output: Path) -> None:
    top = root.name
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for directory in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: p.as_posix()):
            name = f"{top}/{directory.relative_to(root).as_posix()}/"
            info = zipfile.ZipInfo(name, (2026, 8, 2, 0, 0, 0))
            info.external_attr = (0o755 << 16) | 0x10
            archive.writestr(info, b"")
        for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
            name = f"{top}/{path.relative_to(root).as_posix()}"
            info = zipfile.ZipInfo(name, (2026, 8, 2, 0, 0, 0))
            mode = 0o755 if os.access(path, os.X_OK) else 0o644
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--output-zip", type=Path, required=True)
    args = parser.parse_args()

    require(args.output_dir.name == BUNDLE_NAME, "unexpected H1 bundle directory name")
    require(not args.output_dir.exists(), "refusing to overwrite existing H1 rollback directory")
    require(not args.output_zip.exists(), "refusing to overwrite existing H1 rollback ZIP")
    require(args.template.name == TEMPLATE_NAME and args.template.is_dir(), "invalid R02 rollback template")
    require(digest(args.official.read_bytes()) == OFFICIAL_PACKAGE_SHA256, "official v15 package hash mismatch")
    require(digest(args.target.read_bytes()) == H1_PACKAGE_SHA256, "H1 package hash mismatch")

    stock = flash_from_package(args.official)
    target = flash_from_package(args.target)
    require(len(stock) == len(target), "flash length mismatch")
    sectors = tuple(
        address for address in range(0, len(stock), SECTOR_SIZE)
        if stock[address:address + SECTOR_SIZE] != target[address:address + SECTOR_SIZE]
    )
    require(sectors == EXPECTED_SECTORS, f"unexpected H1 sector set: {sectors}")

    for relative in (
        "tools/windows_scsi_transport.py",
        "THIRD-PARTY-NOTICES.md",
        "assets/wl82loader.bin",
    ):
        source = args.template / relative
        destination = args.output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    wrapper_source = (args.template / "restore/run-restore-elevated.ps1").read_text(encoding="utf-8")
    wrapper_path = args.output_dir / "restore/run-restore-elevated.ps1"
    wrapper_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper_path.write_text(patched_wrapper(wrapper_source), encoding="utf-8")

    guard_source = (args.template / "restore/smk37_wl82_guarded_restore.py").read_text(encoding="utf-8")
    guard_path = args.output_dir / "restore/smk37_wl82_guarded_restore.py"
    guard_path.write_text(patched_guard(guard_source), encoding="utf-8")

    records = []
    sector_dir = args.output_dir / "recovery-sectors"
    sector_dir.mkdir(parents=True, exist_ok=True)
    for address in sectors:
        stock_bytes = stock[address:address + SECTOR_SIZE]
        target_bytes = target[address:address + SECTOR_SIZE]
        name = f"stock-sector-{address:05x}.bin"
        (sector_dir / name).write_bytes(stock_bytes)
        records.append({
            "address": f"0x{address:05x}",
            "length": SECTOR_SIZE,
            "stock_file": name,
            "stock_sha256": digest(stock_bytes),
            "expected_target_sha256": digest(target_bytes),
            "changed_byte_count": sum(a != b for a, b in zip(stock_bytes, target_bytes)),
        })

    manifest = {
        "format": "smk37-v15-h1-forced-recovery-plan-v1",
        "hash_representation": "FWSC-unpacked flash.bin bytes; same representation previously validated against WL82 forced-loader dumps",
        "safety_policy": {
            "device_access": "none; offline artifact preparation only",
            "required_before_write": "two identical fresh 1 MiB forced-loader dumps and exact H1 target-sector hashes",
            "write_scope": "five audited 4 KiB application sectors only",
            "forbidden": "chip erase, full-flash write, key burn, boot-prefix write, reset, or run-app",
        },
        "stock_package_sha256": OFFICIAL_PACKAGE_SHA256,
        "h1_package_sha256": H1_PACKAGE_SHA256,
        "stock_flash_sha256": digest(stock),
        "h1_flash_sha256": digest(target),
        "flash_length": len(stock),
        "confirmations": list(CONFIRMATIONS),
        "sectors": records,
    }
    (sector_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "README.md").write_text(
        "# SMK-37 Pro v15 H1 guarded rollback\n\n"
        "Exact H1 producer-unconsumed diagnostic state only is restored to official v15.\n\n"
        f"- official v15 SHA-256: `{OFFICIAL_PACKAGE_SHA256}`\n"
        f"- H1 SHA-256: `{H1_PACKAGE_SHA256}`\n"
        "- permitted sectors: `0x04000`, `0x20000`, `0x22000`, `0x2A000`, `0x62000`\n\n"
        "This bundle is offline-prepared only. It requires two fresh identical 1 MiB dumps "
        "and exact H1 target hashes before any erase/write. Do not reuse for any other build.\n",
        encoding="utf-8",
    )
    write_hashes(args.output_dir)

    for path in (p for p in args.output_dir.rglob("*") if p.is_file()):
        data = path.read_bytes()
        require(b"R02" not in data and b"r02" not in data,
                f"stale R02 token in H1 bundle: {path.relative_to(args.output_dir)}")

    completed = subprocess.run([sys.executable, str(guard_path), "self-test"], check=False)
    require(completed.returncode == 0, "H1 guarded restore self-test failed")
    write_zip(args.output_dir, args.output_zip)
    print("H1 rollback bundle", digest(args.output_zip.read_bytes()))
    print("sectors", " ".join(f"0x{x:05x}" for x in sectors))
    print("confirmations", " ".join(CONFIRMATIONS))
    print("offline only; no device access or Flash mutation performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
