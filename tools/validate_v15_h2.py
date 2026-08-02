#!/usr/bin/env python3
"""Validate the exact-v15 H2 owned-source corrected-fallback release gates offline."""
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

from build_v15_h2_owned_source_corrected_fallback import (
    PACKAGE_NAME,
    build_cave,
)
from build_v15_h2_rollback import BUNDLE_NAME, CONFIRMATIONS, EXPECTED_SECTORS
from build_v15_r01_hand_drum import APP_SHA256, CODE_CAVE, MEMCPY, call32, jne_imm7, mov_imm32, mov_reg, off, word
from build_v15_r02_sysex_staging import RAM_STAGING
from build_v15_r03_fixed_prefix import (
    BSS_SIZE_INSN,
    BSS_SIZE_R03,
    HEAP_BEGIN_INSN,
    HEAP_BEGIN_R03,
    LOCK,
    PRODUCT_CALLS,
    SAVE_CALL,
    SAVE_REJECT_BRANCH,
    SAVE_REJECT_CALL,
    VALID,
    VOICE,
    short_call,
)
from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

ROOT = Path(__file__).resolve().parents[1]
BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback"
BUILD_DIR = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback"
H2_APP = BUILD_DIR / "app.bin"
H2_PACKAGE = BUILD_DIR / PACKAGE_NAME
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
H0_PACKAGE = ROOT / "build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc"
H1_PACKAGE = ROOT / "build/SMK37Pro-v15-H1-producer-unconsumed/SMK37Pro-v15-H1-producer-unconsumed.fwsc"
R02_PACKAGE = ROOT / "build/SMK37Pro-v15-R02-sysex-staging.fwsc"
R03_PACKAGE = ROOT / "build/SMK37Pro-v15-R03-fixed-prefix.fwsc"
H2_BUILDER = ROOT / "tools/build_v15_h2_owned_source_corrected_fallback.py"
H2_ROLLBACK_BUILDER = ROOT / "tools/build_v15_h2_rollback.py"
H2_OTA_SOURCE = ROOT / "tools/smk37_v15_h2_ota.c"
H2_OTA_BINARY = ROOT / "build/smk37-v15-h2-ota"
H2_ROLLBACK_DIR = ROOT / "build" / BUNDLE_NAME
H2_ROLLBACK_ZIP = ROOT / "build" / f"{BUNDLE_NAME}.zip"
R02_TEMPLATE = ROOT / "build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1"

OFFICIAL_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
H0_PACKAGE_SHA256 = "114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566"
H1_PACKAGE_SHA256 = "139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf"
R02_PACKAGE_SHA256 = "93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b"
R03_PACKAGE_SHA256 = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
H2_APP_SHA256 = "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59"
H2_PACKAGE_SHA256 = "c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011"
H2_ROLLBACK_ZIP_SHA256 = "c7e0f92852c78d5864a2d60d2bee86215babe7b810e0e62d3c9f2c7d5e69739c"
H2_BUILDER_SHA256 = "e993baeb9d32e38dfc602b8b13e1832ea15290a223b1db4da7caa3900a18b3a6"
H2_ROLLBACK_BUILDER_SHA256 = "f30a9aeb2a9095cd559db80c9ddac77b4cf0d989e35c1cda55a7dd1aa31fec6a"
H2_OTA_SOURCE_SHA256 = "6bbce7b25b68c0ec53f8de06f310304a162540fd0ce54d0a5be7e326c4452812"
H2_TOKEN = "INSTALL-SMK37PRO-V15-H2-C1752A69"
IDENTITY = "SMK-37 Pro_015"
SECTOR_SIZE = 0x1000
NOTE_OFF_CALL = 0x0201C63E
NOTE_ON_CALL = 0x0201C67C
CHANNEL_10 = 9


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_digest(path: Path) -> str:
    return digest(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def run(command: list[str], *, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True)
    if result.returncode != expect:
        raise SystemExit(
            f"command failed with {result.returncode}, expected {expect}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def pkg_config(args: list[str]) -> list[str]:
    result = run(["pkg-config", *args, "libusb-1.0"])
    return shlex.split(result.stdout.strip())


def flash_from_package(path: Path) -> bytes:
    raw = path.read_bytes()
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    return bytes(Ufw.parse(bytes(payload)).flash())


def compile_h2_ota() -> str:
    command = [
        os.environ.get("CC", "cc"),
        "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
        str(H2_OTA_SOURCE),
        "src/device_info.c", "src/fwsc.c", "src/protocol.c", "src/sha256.c", "src/usb_probe.c",
        "-o", str(H2_OTA_BINARY),
        *pkg_config(["--cflags", "--libs"]),
    ]
    run(command)
    return file_digest(H2_OTA_BINARY)


def expect_at(data: bytes, address: int, expected: bytes, label: str) -> None:
    actual = data[off(address):off(address) + len(expected)]
    require(actual == expected, f"{label} mismatch at 0x{address:08x}: {actual.hex()} != {expected.hex()}")


def validate_consumer_bytes(h2: bytes, layout: dict[str, int], prefix: str) -> dict[str, str]:
    channel_branch = layout[f"{prefix}_channel_branch"]
    valid_branch = layout[f"{prefix}_valid_branch"]
    owned = layout[f"{prefix}_owned"]
    stock = layout[f"{prefix}_stock"]

    expect_at(h2, channel_branch, jne_imm7(channel_branch, 3, CHANNEL_10, stock), f"{prefix} non-Ch10 branch to stock")
    expect_at(h2, valid_branch, jne_imm7(valid_branch, 0, 1, stock), f"{prefix} invalid branch to stock")
    expect_at(h2, owned, mov_reg(0, 5), f"{prefix} owned destination restore")
    expect_at(h2, owned + 2, mov_imm32(1, VOICE), f"{prefix} owned source immediate")
    expect_at(h2, owned + 8, word(0x3C62), f"{prefix} owned copy size")
    expect_at(h2, owned + 10, call32(owned + 10, MEMCPY), f"{prefix} owned memcpy")
    expect_at(h2, owned + 16, word(0x0459), f"{prefix} owned return")
    expect_at(h2, stock, mov_reg(0, 5), f"{prefix} stock destination restore")
    expect_at(h2, stock + 2, call32(stock + 2, MEMCPY), f"{prefix} stock memcpy")
    expect_at(h2, stock + 8, word(0x0459), f"{prefix} stock return")
    consumer = h2[off(layout[f"{prefix}_entry"]):off(layout[f"{prefix}_end"])]
    require(RAM_STAGING.to_bytes(4, "little") not in consumer, f"{prefix} consumer embeds staging pointer")
    return {
        "entry": f"0x{layout[f'{prefix}_entry']:08x}",
        "owned_path": f"0x{owned:08x}",
        "stock_path": f"0x{stock:08x}",
        "invalid_and_non_ch10_target": f"0x{stock:08x}",
        "stock_r0_restore": "mov r0,r5 immediately before stock memcpy",
    }


def validate_builder_and_app() -> dict[str, object]:
    require(file_digest(H2_BUILDER) == H2_BUILDER_SHA256, "H2 builder source hash mismatch")
    run([sys.executable, str(H2_BUILDER), "--determinism-check"])
    official = OFFICIAL_APP.read_bytes()
    h2 = H2_APP.read_bytes()
    require(file_digest(OFFICIAL_APP) == APP_SHA256, "official app hash mismatch")
    require(file_digest(H2_APP) == H2_APP_SHA256, "H2 app hash mismatch")
    require(file_digest(H2_PACKAGE) == H2_PACKAGE_SHA256, "H2 package hash mismatch")

    cave, layout = build_cave()
    require(h2[off(CODE_CAVE):off(CODE_CAVE) + len(cave)] == cave, "H2 cave bytes mismatch")
    require(h2[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL) + 6] == call32(NOTE_OFF_CALL, layout["off_entry"]),
            "Note Off is not routed to H2 corrected wrapper")
    require(h2[off(NOTE_ON_CALL):off(NOTE_ON_CALL) + 6] == call32(NOTE_ON_CALL, layout["on_entry"]),
            "Note On is not routed to H2 corrected wrapper")
    consumers = {
        "note_off": validate_consumer_bytes(h2, layout, "off"),
        "note_on": validate_consumer_bytes(h2, layout, "on"),
    }
    cave_bytes = h2[off(CODE_CAVE):off(layout["end"])]
    require(cave_bytes.count(VOICE.to_bytes(4, "little")) == 3, "H2 cave should embed owned source exactly twice in consumers and once in producer")
    require(RAM_STAGING.to_bytes(4, "little") not in cave_bytes, "H2 cave embeds staging pointer instead of receiving producer pointer in r0")
    require(VALID.to_bytes(4, "little") in cave_bytes, "H2 cave does not reference valid byte")
    require(LOCK.to_bytes(4, "little") in cave_bytes, "H2 cave does not reference lock byte")

    for address, _, _purpose in PRODUCT_CALLS:
        require(h2[off(address):off(address) + 4] == short_call(address, layout["producer"]),
                f"product callsite 0x{address:08x} does not target producer")
    require(h2[off(0x0201E46C):off(0x0201E46C) + 4] == bytes.fromhex("bfeaf838"),
            "direct product reload not preserved")
    require(h2[off(0x0201E4A0):off(0x0201E4A0) + 4] == bytes.fromhex("bfeade38"),
            "segmented product reload not preserved")
    require(h2[off(SAVE_REJECT_CALL):off(SAVE_REJECT_CALL) + 4] == SAVE_REJECT_BRANCH,
            "SAVE first write not blocked")
    require(h2[off(SAVE_CALL):off(SAVE_CALL) + 4] == b"\0" * 4, "SAVE packer call not neutralized")
    require(h2[off(BSS_SIZE_INSN):off(BSS_SIZE_INSN) + 6] == BSS_SIZE_R03, "H0 BSS boundary missing")
    require(h2[off(HEAP_BEGIN_INSN):off(HEAP_BEGIN_INSN) + 6] == HEAP_BEGIN_R03, "H0 HEAP boundary missing")

    app_manifest = json.loads((BASELINE_DIR / "app-manifest.json").read_text(encoding="utf-8"))
    package_manifest = json.loads((BASELINE_DIR / "package-manifest.json").read_text(encoding="utf-8"))
    require(app_manifest["h2_policy"]["stock_fallback_r0_restore"] is True, "manifest lacks fallback r0 restore policy")
    require(app_manifest["h2_policy"]["stock_fallback_preserves_original_r1_r2"] is True, "manifest lacks fallback r1/r2 preservation policy")
    require(app_manifest["h2_policy"]["product_reload_calls_preserved"] is True, "manifest lacks reload preservation")
    require(set(app_manifest["discriminator_outcomes"]) == {"intended_mooger_note_off_no_reboot", "stock_sound_no_reboot", "reboot"},
            "manifest missing H2 discriminator outcomes")
    require(package_manifest["output"]["sha256"] == H2_PACKAGE_SHA256, "package manifest hash mismatch")
    changed = {i for i, (a, b) in enumerate(zip(official, h2)) if a != b}
    require(len(changed) == app_manifest["changed_app_byte_count"], "changed app byte count mismatch")
    return {
        "app_sha256": file_digest(H2_APP),
        "package_sha256": file_digest(H2_PACKAGE),
        "changed_app_byte_count": len(changed),
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "consumers": consumers,
        "producer_owned_destination": f"0x{VOICE:08x}..0x{VALID:08x}",
    }


def validate_ota() -> dict[str, object]:
    require(file_digest(H2_OTA_SOURCE) == H2_OTA_SOURCE_SHA256, "H2 OTA source hash mismatch")
    source = H2_OTA_SOURCE.read_text(encoding="utf-8")
    require(H2_TOKEN in source, "H2 OTA token missing")
    require("0xc1, 0x75, 0x2a, 0x69" in source, "H2 package hash bytes missing")
    require("SMK-37 Pro" in source and "firmware.version != 15" in source, "H2 identity/version gate missing")
    binary_sha = compile_h2_ota()
    accept = run([str(H2_OTA_BINARY), "check", str(H2_PACKAGE)], expect=0)
    require("exact v15 H2 package: PASS" in accept.stdout, "H2 OTA checker did not accept H2")
    rejects = {}
    for name, path, expected_hash in [
        ("official", OFFICIAL_PACKAGE, OFFICIAL_PACKAGE_SHA256),
        ("h0", H0_PACKAGE, H0_PACKAGE_SHA256),
        ("h1", H1_PACKAGE, H1_PACKAGE_SHA256),
        ("r02", R02_PACKAGE, R02_PACKAGE_SHA256),
        ("r03", R03_PACKAGE, R03_PACKAGE_SHA256),
    ]:
        require(file_digest(path) == expected_hash, f"{name} package hash mismatch")
        result = run([str(H2_OTA_BINARY), "check", str(path)], expect=1)
        require("not exact v15 H2" in result.stderr, f"H2 OTA checker did not reject {name}")
        rejects[name] = result.stderr.strip()
    return {
        "source_sha256": file_digest(H2_OTA_SOURCE),
        "binary_sha256": binary_sha,
        "token": H2_TOKEN,
        "identity": IDENTITY,
        "accepted_h2_stdout": accept.stdout.strip(),
        "rejects": rejects,
    }


def validate_bundle_tree(root: Path, zip_path: Path) -> dict[str, object]:
    manifest_path = root / "recovery-sectors/manifest.json"
    wrapper_path = root / "restore/run-restore-elevated.ps1"
    guard_path = root / "restore/smk37_wl82_guarded_restore.py"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest["format"] == "smk37-v15-h2-forced-recovery-plan-v1", "rollback manifest format mismatch")
    require(manifest["h2_package_sha256"] == H2_PACKAGE_SHA256, "rollback package hash mismatch")
    require(manifest["confirmations"] == list(CONFIRMATIONS), "rollback confirmations mismatch")
    sectors = manifest["sectors"]
    addresses = tuple(int(item["address"], 16) for item in sectors)
    require(addresses == EXPECTED_SECTORS, f"rollback sectors mismatch: {addresses}")
    require(all(item["length"] == SECTOR_SIZE for item in sectors), "rollback sector length mismatch")

    stock_flash = flash_from_package(OFFICIAL_PACKAGE)
    h2_flash = flash_from_package(H2_PACKAGE)
    changed_sectors = tuple(
        address for address in range(0, len(stock_flash), SECTOR_SIZE)
        if stock_flash[address:address + SECTOR_SIZE] != h2_flash[address:address + SECTOR_SIZE]
    )
    require(changed_sectors == EXPECTED_SECTORS, f"package sector set mismatch: {changed_sectors}")
    for item in sectors:
        address = int(item["address"], 16)
        stock = stock_flash[address:address + SECTOR_SIZE]
        target = h2_flash[address:address + SECTOR_SIZE]
        require(item["stock_sha256"] == digest(stock), f"stock hash mismatch at 0x{address:05x}")
        require(item["expected_target_sha256"] == digest(target), f"target hash mismatch at 0x{address:05x}")
        require(item["changed_byte_count"] == sum(a != b for a, b in zip(stock, target)),
                f"changed count mismatch at 0x{address:05x}")

    wrapper = wrapper_path.read_text(encoding="utf-8")
    guard = guard_path.read_text(encoding="utf-8")
    for confirmation in CONFIRMATIONS:
        require(wrapper.count(f"--confirm {confirmation}") == 1, f"wrapper confirmation mismatch: {confirmation}")
        require(confirmation in guard, f"guard missing confirmation: {confirmation}")
    for stale in ("R02", "r02", "H1", "h1"):
        require(stale not in wrapper and stale not in guard, f"stale {stale} token in rollback")
    require("SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000, 0x62000}" in guard,
            "guard sector allow-list mismatch")
    run([sys.executable, str(guard_path), "self-test"])
    require(file_digest(zip_path) == H2_ROLLBACK_ZIP_SHA256, "rollback ZIP hash mismatch")
    with zipfile.ZipFile(zip_path, "r") as archive:
        require(any(name.endswith("recovery-sectors/manifest.json") for name in archive.namelist()),
                "rollback ZIP lacks manifest")
    return {
        "zip_sha256": file_digest(zip_path),
        "sector_addresses": [item["address"] for item in sectors],
        "confirmations": list(CONFIRMATIONS),
        "wrapper_sha256": file_digest(wrapper_path),
        "guard_sha256": file_digest(guard_path),
    }


def validate_rollback() -> dict[str, object]:
    require(file_digest(H2_ROLLBACK_BUILDER) == H2_ROLLBACK_BUILDER_SHA256, "H2 rollback builder hash mismatch")
    existing = validate_bundle_tree(ROOT / "build" / BUNDLE_NAME, H2_ROLLBACK_ZIP)
    with tempfile.TemporaryDirectory(prefix="h2-rollback-") as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / BUNDLE_NAME
        out_zip = tmp_path / f"{BUNDLE_NAME}.zip"
        run([
            sys.executable,
            str(H2_ROLLBACK_BUILDER),
            "--official", str(OFFICIAL_PACKAGE),
            "--target", str(H2_PACKAGE),
            "--template", str(R02_TEMPLATE),
            "--output-dir", str(out_dir),
            "--output-zip", str(out_zip),
        ])
        scratch = validate_bundle_tree(out_dir, out_zip)
        require(scratch["zip_sha256"] == existing["zip_sha256"], "rollback scratch ZIP mismatch")
    return existing


def main() -> int:
    baseline = validate_builder_and_app()
    ota = validate_ota()
    rollback = validate_rollback()
    result = {
        "status": "PASS",
        "scope": "offline H2 discriminator release gates only; no device access or flash",
        "baseline": baseline,
        "ota_checker": ota,
        "rollback": rollback,
        "discriminator_outcomes": {
            "intended_mooger_note_off_no_reboot": "owned source consumed safely with corrected fallback semantics",
            "stock_sound_no_reboot": "corrected fallback safe; producer not valid or product not accepted",
            "reboot": "H2 FAIL: owned-source consumption or corrected consumer path still faults",
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
