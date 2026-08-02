#!/usr/bin/env python3
"""Validate the exact-v15 H1 producer-unconsumed release gates offline."""
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

from build_v15_h1_producer_unconsumed import (
    PACKAGE_NAME,
    build_cave,
)
from build_v15_h1_rollback import BUNDLE_NAME, CONFIRMATIONS, EXPECTED_SECTORS
from build_v15_r01_hand_drum import APP_SHA256, CODE_CAVE, call32, off
from build_v15_r02_sysex_staging import RAM_STAGING
from build_v15_r03_fixed_prefix import (
    BSS_SIZE_INSN,
    BSS_SIZE_R03,
    HEAP_BEGIN_INSN,
    HEAP_BEGIN_R03,
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
BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/H1-producer-unconsumed"
BUILD_DIR = ROOT / "build/SMK37Pro-v15-H1-producer-unconsumed"
H1_APP = BUILD_DIR / "app.bin"
H1_PACKAGE = BUILD_DIR / PACKAGE_NAME
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
H0_PACKAGE = ROOT / "build/SMK37Pro-v15-H0-memory-boundary-only/SMK37Pro-v15-H0-memory-boundary-only.fwsc"
R02_PACKAGE = ROOT / "build/SMK37Pro-v15-R02-sysex-staging.fwsc"
R03_PACKAGE = ROOT / "build/SMK37Pro-v15-R03-fixed-prefix.fwsc"
H1_BUILDER = ROOT / "tools/build_v15_h1_producer_unconsumed.py"
H1_ROLLBACK_BUILDER = ROOT / "tools/build_v15_h1_rollback.py"
H1_OTA_SOURCE = ROOT / "tools/smk37_v15_h1_ota.c"
H1_OTA_BINARY = ROOT / "build/smk37-v15-h1-ota"
H1_ROLLBACK_DIR = ROOT / "build" / BUNDLE_NAME
H1_ROLLBACK_ZIP = ROOT / "build" / f"{BUNDLE_NAME}.zip"
R02_TEMPLATE = ROOT / "build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1"

OFFICIAL_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
H0_PACKAGE_SHA256 = "114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566"
R02_PACKAGE_SHA256 = "93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b"
R03_PACKAGE_SHA256 = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
H1_APP_SHA256 = "b082e8058cfacdb6e9d548dbe7033f31c0848fcf7d865859bc7c8fd969eac463"
H1_PACKAGE_SHA256 = "139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf"
H1_ROLLBACK_ZIP_SHA256 = "c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2"
H1_BUILDER_SHA256 = "a4327e46d9267e2a05b683ca2b9d8f6b201aa1d137a4d13431cc8c03292c2011"
H1_ROLLBACK_BUILDER_SHA256 = "55361c9adee6323cbcce2723e8410d4c8c720ea4ecbf709f56a6defb81224bf6"
H1_OTA_SOURCE_SHA256 = "ad82630263ec62dd85634ab55bfe9e753829885b1ead683918cb24be130e843d"
H1_TOKEN = "INSTALL-SMK37PRO-V15-H1-139AB42B"
IDENTITY = "SMK-37 Pro_015"
SECTOR_SIZE = 0x1000
NOTE_OFF_CALL = 0x0201C63E
NOTE_ON_CALL = 0x0201C67C


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


def compile_h1_ota() -> str:
    command = [
        os.environ.get("CC", "cc"),
        "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
        str(H1_OTA_SOURCE),
        "src/device_info.c", "src/fwsc.c", "src/protocol.c", "src/sha256.c", "src/usb_probe.c",
        "-o", str(H1_OTA_BINARY),
        *pkg_config(["--cflags", "--libs"]),
    ]
    run(command)
    return file_digest(H1_OTA_BINARY)


def validate_builder_and_app() -> dict[str, object]:
    require(file_digest(H1_BUILDER) == H1_BUILDER_SHA256, "H1 builder source hash mismatch")
    run([sys.executable, str(H1_BUILDER), "--determinism-check"])
    official = OFFICIAL_APP.read_bytes()
    h1 = H1_APP.read_bytes()
    require(file_digest(OFFICIAL_APP) == APP_SHA256, "official app hash mismatch")
    require(file_digest(H1_APP) == H1_APP_SHA256, "H1 app hash mismatch")
    require(file_digest(H1_PACKAGE) == H1_PACKAGE_SHA256, "H1 package hash mismatch")

    cave, layout = build_cave()
    require(h1[off(CODE_CAVE):off(CODE_CAVE) + len(cave)] == cave, "H1 cave bytes mismatch")
    require(h1[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL) + 6] == call32(NOTE_OFF_CALL, layout["r02_entry"]),
            "Note Off is not routed to R02 staging wrapper")
    require(h1[off(NOTE_ON_CALL):off(NOTE_ON_CALL) + 6] == call32(NOTE_ON_CALL, layout["r02_entry"]),
            "Note On is not routed to R02 staging wrapper")
    require(h1[off(0x0201E148):off(0x0201E148) + 6] == bytes.fromhex("c1ffd07fc301"),
            "consumer source is not 0x01c37fd0 staging")
    require(h1.find(VOICE.to_bytes(4, "little"), off(CODE_CAVE), off(layout["producer"])) == -1,
            "consumer prefix contains owned-source immediate")
    require(h1[off(layout["producer"]):off(layout["end"])].find(VOICE.to_bytes(4, "little")) >= 0,
            "producer does not reference owned voice")
    require(h1[off(layout["producer"]):off(layout["end"])].find(RAM_STAGING.to_bytes(4, "little")) == -1,
            "producer should receive staging pointer in r0, not embed staging immediate")
    for address, _, _purpose in PRODUCT_CALLS:
        require(h1[off(address):off(address) + 4] == short_call(address, layout["producer"]),
                f"product callsite 0x{address:08x} does not target producer")
    require(h1[off(0x0201E46C):off(0x0201E46C) + 4] == bytes.fromhex("bfeaf838"),
            "direct product reload not preserved")
    require(h1[off(0x0201E4A0):off(0x0201E4A0) + 4] == bytes.fromhex("bfeade38"),
            "segmented product reload not preserved")
    require(h1[off(SAVE_REJECT_CALL):off(SAVE_REJECT_CALL) + 4] == SAVE_REJECT_BRANCH,
            "SAVE first write not blocked")
    require(h1[off(SAVE_CALL):off(SAVE_CALL) + 4] == b"\0" * 4, "SAVE packer call not neutralized")
    require(h1[off(BSS_SIZE_INSN):off(BSS_SIZE_INSN) + 6] == BSS_SIZE_R03, "H0 BSS boundary missing")
    require(h1[off(HEAP_BEGIN_INSN):off(HEAP_BEGIN_INSN) + 6] == HEAP_BEGIN_R03, "H0 HEAP boundary missing")
    app_manifest = json.loads((BASELINE_DIR / "app-manifest.json").read_text(encoding="utf-8"))
    package_manifest = json.loads((BASELINE_DIR / "package-manifest.json").read_text(encoding="utf-8"))
    require(app_manifest["h1_policy"]["no_consumer_owned_ram"] is True, "manifest lacks no-owned-consumer policy")
    require(app_manifest["h1_policy"]["product_reload_calls_preserved"] is True, "manifest lacks reload preservation")
    require(set(app_manifest["discriminator_outcomes"]) == {"packet_time_reboot", "first_pad_reboot", "PASS"},
            "manifest missing H1 discriminator outcomes")
    require(package_manifest["output"]["sha256"] == H1_PACKAGE_SHA256, "package manifest hash mismatch")
    changed = {i for i, (a, b) in enumerate(zip(official, h1)) if a != b}
    require(len(changed) == app_manifest["changed_app_byte_count"], "changed app byte count mismatch")
    return {
        "app_sha256": file_digest(H1_APP),
        "package_sha256": file_digest(H1_PACKAGE),
        "changed_app_byte_count": len(changed),
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "consumer_source": "0x01c37fd0",
        "producer_owned_destination": f"0x{VOICE:08x}..0x{VALID:08x}",
    }


def validate_ota() -> dict[str, object]:
    require(file_digest(H1_OTA_SOURCE) == H1_OTA_SOURCE_SHA256, "H1 OTA source hash mismatch")
    source = H1_OTA_SOURCE.read_text(encoding="utf-8")
    require(H1_TOKEN in source, "H1 OTA token missing")
    require("0x13, 0x9a, 0xb4, 0x2b" in source, "H1 package hash bytes missing")
    require("SMK-37 Pro" in source and "firmware.version != 15" in source, "H1 identity/version gate missing")
    binary_sha = compile_h1_ota()
    accept = run([str(H1_OTA_BINARY), "check", str(H1_PACKAGE)], expect=0)
    require("exact v15 H1 package: PASS" in accept.stdout, "H1 OTA checker did not accept H1")
    rejects = {}
    for name, path, expected_hash in [
        ("official", OFFICIAL_PACKAGE, OFFICIAL_PACKAGE_SHA256),
        ("h0", H0_PACKAGE, H0_PACKAGE_SHA256),
        ("r02", R02_PACKAGE, R02_PACKAGE_SHA256),
        ("r03", R03_PACKAGE, R03_PACKAGE_SHA256),
    ]:
        require(file_digest(path) == expected_hash, f"{name} package hash mismatch")
        result = run([str(H1_OTA_BINARY), "check", str(path)], expect=1)
        require("not exact v15 H1" in result.stderr, f"H1 OTA checker did not reject {name}")
        rejects[name] = result.stderr.strip()
    return {
        "source_sha256": file_digest(H1_OTA_SOURCE),
        "binary_sha256": binary_sha,
        "token": H1_TOKEN,
        "identity": IDENTITY,
        "accepted_h1_stdout": accept.stdout.strip(),
        "rejects": rejects,
    }


def validate_bundle_tree(root: Path, zip_path: Path) -> dict[str, object]:
    manifest_path = root / "recovery-sectors/manifest.json"
    wrapper_path = root / "restore/run-restore-elevated.ps1"
    guard_path = root / "restore/smk37_wl82_guarded_restore.py"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(manifest["format"] == "smk37-v15-h1-forced-recovery-plan-v1", "rollback manifest format mismatch")
    require(manifest["h1_package_sha256"] == H1_PACKAGE_SHA256, "rollback package hash mismatch")
    require(manifest["confirmations"] == list(CONFIRMATIONS), "rollback confirmations mismatch")
    sectors = manifest["sectors"]
    addresses = tuple(int(item["address"], 16) for item in sectors)
    require(addresses == EXPECTED_SECTORS, f"rollback sectors mismatch: {addresses}")
    require(all(item["length"] == SECTOR_SIZE for item in sectors), "rollback sector length mismatch")

    stock_flash = flash_from_package(OFFICIAL_PACKAGE)
    h1_flash = flash_from_package(H1_PACKAGE)
    changed_sectors = tuple(
        address for address in range(0, len(stock_flash), SECTOR_SIZE)
        if stock_flash[address:address + SECTOR_SIZE] != h1_flash[address:address + SECTOR_SIZE]
    )
    require(changed_sectors == EXPECTED_SECTORS, f"package sector set mismatch: {changed_sectors}")
    for item in sectors:
        address = int(item["address"], 16)
        stock = stock_flash[address:address + SECTOR_SIZE]
        target = h1_flash[address:address + SECTOR_SIZE]
        require(item["stock_sha256"] == digest(stock), f"stock hash mismatch at 0x{address:05x}")
        require(item["expected_target_sha256"] == digest(target), f"target hash mismatch at 0x{address:05x}")
        require(item["changed_byte_count"] == sum(a != b for a, b in zip(stock, target)),
                f"changed count mismatch at 0x{address:05x}")

    wrapper = wrapper_path.read_text(encoding="utf-8")
    guard = guard_path.read_text(encoding="utf-8")
    for confirmation in CONFIRMATIONS:
        require(wrapper.count(f"--confirm {confirmation}") == 1, f"wrapper confirmation mismatch: {confirmation}")
        require(confirmation in guard, f"guard missing confirmation: {confirmation}")
    require("R02" not in wrapper and "r02" not in wrapper, "stale R02 token in wrapper")
    require("R02" not in guard and "r02" not in guard, "stale R02 token in guard")
    require("SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000, 0x62000}" in guard,
            "guard sector allow-list mismatch")
    run([sys.executable, str(guard_path), "self-test"])
    require(file_digest(zip_path) == H1_ROLLBACK_ZIP_SHA256, "rollback ZIP hash mismatch")
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
    require(file_digest(H1_ROLLBACK_BUILDER) == H1_ROLLBACK_BUILDER_SHA256, "H1 rollback builder hash mismatch")
    existing = validate_bundle_tree(ROOT / "build" / BUNDLE_NAME, H1_ROLLBACK_ZIP)
    with tempfile.TemporaryDirectory(prefix="h1-rollback-") as tmp:
        tmp_path = Path(tmp)
        out_dir = tmp_path / BUNDLE_NAME
        out_zip = tmp_path / f"{BUNDLE_NAME}.zip"
        run([
            sys.executable,
            str(H1_ROLLBACK_BUILDER),
            "--official", str(OFFICIAL_PACKAGE),
            "--target", str(H1_PACKAGE),
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
        "scope": "offline H1 discriminator release gates only; no device access or flash",
        "baseline": baseline,
        "ota_checker": ota,
        "rollback": rollback,
        "discriminator_outcomes": {
            "packet_time_reboot": "producer or post-product reload fault before Ch10 consumer",
            "first_pad_reboot": "R02 staging consumer plus producer side effect fault; not owned-source consumption",
            "PASS": "producer write/publish is safe when consumers remain on staging; R03 fault isolated to owned-source consumption or R03 consumer behavior",
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
