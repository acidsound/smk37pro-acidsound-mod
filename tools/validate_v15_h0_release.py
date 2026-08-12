#!/usr/bin/env python3
"""Validate the v15 H0 release gates offline.

Checks:
- committed H0 memory-boundary-only baseline rebuilds deterministically;
- exact-hash H0 OTA checker source is pinned, compiles, accepts only H0, and
  rejects official v15 and R03;
- guarded H0 rollback bundle is deterministic, has the expected ZIP hash,
  restores exactly two 4 KiB sectors, uses H0 confirmations, and contains no
  stale R02 tokens.

No device, USB transport, OTA upload, or Flash mutation is performed.
"""
from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from build_v15_h0_rollback import BUNDLE_NAME, CONFIRMATIONS, EXPECTED_SECTORS
from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

ROOT = Path(__file__).resolve().parents[1]
H0_BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/H0-memory-boundary-only"
H0_BUILDER = H0_BASELINE_DIR / "build_h0_memory_boundary_only.py"
H0_BUILD_DIR = ROOT / "build/SMK37Pro-v15-H0-memory-boundary-only"
H0_PACKAGE = H0_BUILD_DIR / "SMK37Pro-v15-H0-memory-boundary-only.fwsc"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
R03_PACKAGE = ROOT / "build/SMK37Pro-v15-R03-fixed-prefix.fwsc"
H0_OTA_SOURCE = ROOT / "tools/smk37_v15_h0_ota.c"
H0_OTA_BINARY = ROOT / "build/smk37-v15-h0-ota"
H0_ROLLBACK_BUILDER = ROOT / "tools/build_v15_h0_rollback.py"
H0_ROLLBACK_DIR = ROOT / "build" / BUNDLE_NAME
H0_ROLLBACK_ZIP = ROOT / "build" / f"{BUNDLE_NAME}.zip"
R02_TEMPLATE = ROOT / "build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1"

OFFICIAL_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
R03_PACKAGE_SHA256 = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
H0_PACKAGE_SHA256 = "114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566"
H0_APP_SHA256 = "ab2d4d210605f20e35b96a8471c9f2e1102c24e18f3b062d6eabd4970f9794ce"
H0_OTA_SOURCE_SHA256 = "058c92721694b2979254f5f0c8e675be39a4957453cb867d8d8fa573d765b2e9"
H0_ROLLBACK_ZIP_SHA256 = "05e22531e82b9b3a15338e09d1fde274e18f4697a17c60e00fcba063c7ea60ed"
H0_TOKEN = "INSTALL-SMK37PRO-V15-H0-114D814B"
IDENTITY = "SMK-37 Pro_015"
SECTOR_SIZE = 0x1000


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    return digest(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def run(command: list[str], *, expect: int = 0, capture: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=capture)
    if result.returncode != expect:
        raise SystemExit(
            f"command failed with {result.returncode}, expected {expect}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def flash_from_package(path: Path) -> bytes:
    raw = path.read_bytes()
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    return bytes(Ufw.parse(bytes(payload)).flash())


def pkg_config(args: list[str]) -> list[str]:
    result = run(["pkg-config", *args, "libusb-1.0"])
    return shlex.split(result.stdout.strip())


def compile_h0_ota() -> str:
    H0_OTA_BINARY.parent.mkdir(parents=True, exist_ok=True)
    command = [
        os.environ.get("CC", "cc"),
        "-O2",
        "-g",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        str(H0_OTA_SOURCE),
        "src/device_info.c",
        "src/fwsc.c",
        "src/protocol.c",
        "src/sha256.c",
        "src/usb_probe.c",
        "-o",
        str(H0_OTA_BINARY),
        *pkg_config(["--cflags", "--libs"]),
    ]
    run(command)
    return file_digest(H0_OTA_BINARY)


def validate_ota_checker() -> dict[str, object]:
    source = H0_OTA_SOURCE.read_text(encoding="utf-8")
    require(file_digest(H0_OTA_SOURCE) == H0_OTA_SOURCE_SHA256, "H0 OTA source hash mismatch")
    require(H0_PACKAGE_SHA256 in source or "0x11, 0x4d, 0x81, 0x4b" in source, "H0 package hash bytes missing")
    require(H0_TOKEN in source, "H0 install confirmation token missing")
    require("SMK-37 Pro" in source and "firmware.version != 15" in source, "H0 identity/version gate missing")
    binary_sha = compile_h0_ota()

    accept = run([str(H0_OTA_BINARY), "check", str(H0_PACKAGE)], expect=0)
    require("exact v15 H0 package: PASS" in accept.stdout, "H0 checker did not accept exact H0")
    official_reject = run([str(H0_OTA_BINARY), "check", str(OFFICIAL_PACKAGE)], expect=1)
    require("not exact v15 H0" in official_reject.stderr, "H0 checker did not reject official v15")
    r03_reject = run([str(H0_OTA_BINARY), "check", str(R03_PACKAGE)], expect=1)
    require("not exact v15 H0" in r03_reject.stderr, "H0 checker did not reject R03")
    return {
        "source_sha256": file_digest(H0_OTA_SOURCE),
        "binary_sha256": binary_sha,
        "accepted_h0_stdout": accept.stdout.strip(),
        "official_reject_stderr": official_reject.stderr.strip(),
        "r03_reject_stderr": r03_reject.stderr.strip(),
        "token": H0_TOKEN,
        "identity": IDENTITY,
    }


def validate_h0_baseline() -> dict[str, object]:
    run([sys.executable, str(H0_BUILDER), "--determinism-check"])
    require(file_digest(OFFICIAL_PACKAGE) == OFFICIAL_PACKAGE_SHA256, "official package hash mismatch")
    require(file_digest(R03_PACKAGE) == R03_PACKAGE_SHA256, "R03 package hash mismatch")
    require(file_digest(H0_PACKAGE) == H0_PACKAGE_SHA256, "H0 package hash mismatch")
    app_manifest = json.loads((H0_BASELINE_DIR / "app-manifest.json").read_text(encoding="utf-8"))
    package_manifest = json.loads((H0_BASELINE_DIR / "package-manifest.json").read_text(encoding="utf-8"))
    validation = json.loads((H0_BASELINE_DIR / "validation.json").read_text(encoding="utf-8"))
    require(app_manifest["output_app_sha256"] == H0_APP_SHA256, "H0 app manifest hash mismatch")
    require(app_manifest["changed_app_byte_count"] == 2, "H0 app must change exactly two bytes")
    require(package_manifest["output"]["sha256"] == H0_PACKAGE_SHA256, "H0 package manifest hash mismatch")
    require(package_manifest["changes"]["app_byte_count"] == 2, "H0 package app byte count mismatch")
    require(validation["changed_flash_sectors"] == ["0x04000", "0x62000"], "H0 baseline sector set mismatch")
    require(validation["protected_prefix_0x0000_0x3fff_unchanged"] is True, "H0 protected prefix mismatch")
    return {
        "package_sha256": file_digest(H0_PACKAGE),
        "app_sha256": app_manifest["output_app_sha256"],
        "changed_app_byte_count": app_manifest["changed_app_byte_count"],
        "changed_flash_sectors": validation["changed_flash_sectors"],
    }


def validate_bundle_tree(root: Path, zip_path: Path) -> dict[str, object]:
    manifest_path = root / "recovery-sectors/manifest.json"
    wrapper_path = root / "restore/run-restore-elevated.ps1"
    guard_path = root / "restore/smk37_wl82_guarded_restore.py"
    require(manifest_path.exists(), f"rollback manifest missing: {manifest_path}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sectors = manifest["sectors"]
    addresses = tuple(int(item["address"], 16) for item in sectors)
    require(addresses == EXPECTED_SECTORS, f"rollback sector set mismatch: {addresses}")
    require(manifest["format"] == "smk37-v15-h0-forced-recovery-plan-v1", "rollback format mismatch")
    require(manifest["h0_package_sha256"] == H0_PACKAGE_SHA256, "rollback H0 hash mismatch")
    require(manifest["confirmations"] == list(CONFIRMATIONS), "rollback confirmation list mismatch")
    require(all(item["length"] == SECTOR_SIZE for item in sectors), "rollback sector size must be 4 KiB")

    stock_flash = flash_from_package(OFFICIAL_PACKAGE)
    h0_flash = flash_from_package(H0_PACKAGE)
    changed_sectors = tuple(
        address for address in range(0, len(stock_flash), SECTOR_SIZE)
        if stock_flash[address:address + SECTOR_SIZE] != h0_flash[address:address + SECTOR_SIZE]
    )
    require(changed_sectors == EXPECTED_SECTORS, f"package changed sectors mismatch: {changed_sectors}")
    for item in sectors:
        address = int(item["address"], 16)
        stock = stock_flash[address:address + SECTOR_SIZE]
        target = h0_flash[address:address + SECTOR_SIZE]
        require(item["stock_sha256"] == digest(stock), f"stock sector hash mismatch at 0x{address:05x}")
        require(item["expected_target_sha256"] == digest(target), f"target sector hash mismatch at 0x{address:05x}")
        require(item["changed_byte_count"] == sum(a != b for a, b in zip(stock, target)),
                f"changed byte count mismatch at 0x{address:05x}")

    wrapper = wrapper_path.read_text(encoding="utf-8")
    guard = guard_path.read_text(encoding="utf-8")
    for confirmation in CONFIRMATIONS:
        require(wrapper.count(f"--confirm {confirmation}") == 1, f"wrapper confirmation mismatch: {confirmation}")
        require(confirmation in guard, f"guard missing confirmation: {confirmation}")
    require("R02" not in wrapper and "r02" not in wrapper, "stale R02 token in wrapper")
    require("R02" not in guard and "r02" not in guard, "stale R02 token in guard")
    require("0x20000" not in guard and "0x22000" not in guard and "0x2A000" not in guard,
            "guard contains stale non-H0 sectors")
    require("SECTORS = {0x04000, 0x62000}" in guard, "guard sector allow-list mismatch")

    run([sys.executable, str(guard_path), "self-test"])
    require(file_digest(zip_path) == H0_ROLLBACK_ZIP_SHA256, "rollback ZIP hash mismatch")
    with zipfile.ZipFile(zip_path, "r") as archive:
        names = archive.namelist()
    require(any(name.endswith("recovery-sectors/manifest.json") for name in names), "rollback ZIP lacks manifest")
    return {
        "zip_sha256": file_digest(zip_path),
        "sector_addresses": [item["address"] for item in sectors],
        "confirmations": list(CONFIRMATIONS),
        "wrapper_sha256": file_digest(wrapper_path),
        "guard_sha256": file_digest(guard_path),
    }


def validate_rollback() -> dict[str, object]:
    # Existing generated release artifact.
    existing = validate_bundle_tree(H0_ROLLBACK_DIR, H0_ROLLBACK_ZIP)

    # Deterministic fresh rebuild in scratch.
    with tempfile.TemporaryDirectory(prefix="h0-rollback-") as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / BUNDLE_NAME
        out_zip = tmp_path / f"{BUNDLE_NAME}.zip"
        run([
            sys.executable,
            str(H0_ROLLBACK_BUILDER),
            "--official",
            str(OFFICIAL_PACKAGE),
            "--target",
            str(H0_PACKAGE),
            "--template",
            str(R02_TEMPLATE),
            "--output-dir",
            str(out_dir),
            "--output-zip",
            str(out_zip),
        ])
        scratch = validate_bundle_tree(out_dir, out_zip)
        require(scratch["zip_sha256"] == existing["zip_sha256"], "rollback scratch ZIP differs from release ZIP")
    return existing


def main() -> int:
    baseline = validate_h0_baseline()
    ota = validate_ota_checker()
    rollback = validate_rollback()
    result = {
        "status": "PASS",
        "scope": "offline H0 release gates only; no device access or flash",
        "baseline": baseline,
        "ota_checker": ota,
        "rollback": rollback,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
