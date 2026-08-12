#!/usr/bin/env python3
"""Validate offline R02 artifacts.  This is not a live success claim."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from build_v15_r01_hand_drum import APP_SHA256, APP_SIZE, off
from build_v15_r02_sysex_staging import (
    CODE_CAVE,
    NOTE_OFF_MEMCPY_CALL,
    NOTE_ON_MEMCPY_CALL,
    PACKER_CALLS,
    PRODUCT_PACKET_HEADER,
    PRODUCT_PACKET_SHA256,
    PRODUCT_PACKET_SIZE,
    RAM_STAGING,
    build_wrapper,
)
from dx7_vmem import unpack_voice
from smk37_v15_app_patch import (
    FWSC_BLOCK_SIZE,
    FWSC_DATA_SIZE,
    FWSC_SLOTS,
    Ufw,
)


ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
R01C_APP = ROOT / "build/v15-R01c-mooger1-app.bin"
R02_APP = ROOT / "build/v15-R02-sysex-staging-app.bin"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
R02_PACKAGE = ROOT / "build/SMK37Pro-v15-R02-sysex-staging.fwsc"
PACKET = ROOT / "build/v15-R02-mooger1-runtime.syx"
CLEAN_DUMP = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R02/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R02/package-manifest.json"
ROLLBACK_ZIP = ROOT / "build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1.zip"

R02_APP_SHA256 = "eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948"
R02_PACKAGE_SHA256 = "93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b"
ROLLBACK_SHA256 = "7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d"
EXPECTED_SECTORS = (0x04000, 0x20000, 0x22000, 0x2A000)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def flash_from_package(path: Path) -> bytes:
    raw = path.read_bytes()
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    return bytes(Ufw.parse(payload).flash())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> int:
    official = OFFICIAL_APP.read_bytes()
    r01c = R01C_APP.read_bytes()
    r02 = R02_APP.read_bytes()
    require(len(official) == len(r02) == APP_SIZE, "app size mismatch")
    require(digest(official) == APP_SHA256, "official app hash mismatch")
    require(digest(r02) == R02_APP_SHA256, "R02 app hash mismatch")

    wrapper, layout = build_wrapper()
    start = off(CODE_CAVE)
    require(r02[start:start + len(wrapper)] == wrapper, "R02 wrapper bytes mismatch")
    require(layout["end"] == 0x0201E162, "R02 wrapper length changed")

    # R01c booted.  R02 must retain its exact wrapper instruction shape; only
    # the 32-bit source immediate is allowed to differ.
    r01c_wrapper = r01c[start:start + len(wrapper)]
    differences = [i for i, (a, b) in enumerate(zip(r01c_wrapper, wrapper)) if a != b]
    require(differences == [12, 13, 14, 15], f"unexpected R01c/R02 wrapper differences: {differences}")
    require(wrapper[10:12] == b"\xc1\xff", "source mov opcode changed")
    require(int.from_bytes(wrapper[12:16], "little") == RAM_STAGING, "RAM staging immediate mismatch")

    changed = {i for i, (a, b) in enumerate(zip(official, r02)) if a != b}
    allowed = set(range(start, start + len(wrapper)))
    allowed.update(range(off(NOTE_ON_MEMCPY_CALL), off(NOTE_ON_MEMCPY_CALL) + 6))
    allowed.update(range(off(NOTE_OFF_MEMCPY_CALL), off(NOTE_OFF_MEMCPY_CALL) + 6))
    for address, _, _ in PACKER_CALLS:
        allowed.update(range(off(address), off(address) + 4))
    require(changed <= allowed, "R02 changed bytes outside declared ranges")
    require(off(0x02005F9C) not in changed, "R02 contains forbidden boot-time post-init hook")

    packet = PACKET.read_bytes()
    require(len(packet) == PRODUCT_PACKET_SIZE, "packet size mismatch")
    require(digest(packet) == PRODUCT_PACKET_SHA256, "packet hash mismatch")
    require(packet[:6] == PRODUCT_PACKET_HEADER and packet[-1] == 0xF7, "packet framing mismatch")
    packed = CLEAN_DUMP.read_bytes()[0xF7680:0xF7700]
    runtime = unpack_voice(packed)
    require(packet[6:162] == runtime, "packet runtime voice mismatch")
    require(runtime[145:155] == b"Mooger #1 " and runtime[155] == 0x3F,
            "runtime voice identity mismatch")

    app_manifest = json.loads(APP_MANIFEST.read_text())
    require(app_manifest["output_app_sha256"] == R02_APP_SHA256, "app manifest hash mismatch")
    require(app_manifest["design"]["boot_time_hook"] is None, "manifest contains boot hook")
    require(len(app_manifest["changes"]) == 6, "unexpected app change count")

    package_raw = R02_PACKAGE.read_bytes()
    require(digest(package_raw) == R02_PACKAGE_SHA256, "R02 package hash mismatch")
    package_manifest = json.loads(PACKAGE_MANIFEST.read_text())
    require(package_manifest["output"]["sha256"] == R02_PACKAGE_SHA256,
            "package manifest hash mismatch")
    require(package_manifest["safety_gate"] == "PASS", "package safety gate failed")

    stock_flash = flash_from_package(OFFICIAL_PACKAGE)
    r02_flash = flash_from_package(R02_PACKAGE)
    sectors = tuple(
        address for address in range(0, len(stock_flash), 0x1000)
        if stock_flash[address:address + 0x1000] != r02_flash[address:address + 0x1000]
    )
    require(sectors == EXPECTED_SECTORS, f"unexpected changed sectors: {sectors}")
    require(digest(ROLLBACK_ZIP.read_bytes()) == ROLLBACK_SHA256, "rollback ZIP hash mismatch")

    print("v15 R02 artifact integrity and rollback readiness: PASS")
    print("not a live functional claim; no device access performed")
    print("app", R02_APP_SHA256)
    print("package", R02_PACKAGE_SHA256)
    print("runtime packet", PRODUCT_PACKET_SHA256)
    print("rollback", ROLLBACK_SHA256)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
