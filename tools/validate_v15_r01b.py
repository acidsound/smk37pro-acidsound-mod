#!/usr/bin/env python3
"""Validate R01b artifact integrity, not the disproven timbre identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "build/v15-R01b-buzz-bass-app.bin"
PACKAGE = ROOT / "build/SMK37Pro-v15-R01b-buzz-bass.fwsc"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01b/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01b/package-manifest.json"
OFFICIAL_APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
APP_SHA = "1bd69fa20d4e4dab35d1d9df12bda36e25516ce2d0c1dff00fd2b7c9e3e96c7f"
PACKAGE_SHA = "50aa3b27b17e4f9f8c682dd0ff053d2e3d198b7c736da63ed7b957627ccfa08d"
EXPECTED_ADDRESSES = {
    "0x0201c63e",
    "0x0201c67c",
    "0x0201e13e",
    "0x0201e468",
    "0x0201e49c",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    for path in (APP, PACKAGE, APP_MANIFEST, PACKAGE_MANIFEST):
        require(path.is_file(), f"missing {path.relative_to(ROOT)}")
    app_manifest = json.loads(APP_MANIFEST.read_text())
    package_manifest = json.loads(PACKAGE_MANIFEST.read_text())
    require(sha256(APP) == APP_SHA, "R01b app SHA mismatch")
    require(sha256(PACKAGE) == PACKAGE_SHA, "R01b package SHA mismatch")
    require(app_manifest["input_app_sha256"] == OFFICIAL_APP_SHA, "official app gate mismatch")
    require(app_manifest["output_app_sha256"] == APP_SHA, "app manifest output mismatch")
    require(app_manifest["format"] == "smk37-v15-r01b-channel10-factory-buzz-bass-noteoff-v1", "format mismatch")
    require({item["address"] for item in app_manifest["changes"]} == EXPECTED_ADDRESSES, "unexpected patch addresses")
    require(app_manifest["evidence"]["note_on_memcpy"] == "0x0201c67c", "Note On hook mismatch")
    require(app_manifest["evidence"]["note_off_memcpy"] == "0x0201c63e", "Note Off hook mismatch")
    require(app_manifest["evidence"]["channel_register"] == "r9", "channel register mismatch")
    require(app_manifest["voice"]["name"] == "BUZZ BASS ", "voice mismatch")
    require(app_manifest["voice"]["bank"] == 3 and app_manifest["voice"]["preset"] == 0, "voice index mismatch")
    require(package_manifest["safety_gate"] == "PASS", "package safety gate failed")
    require(package_manifest["output"]["app_sha256"] == APP_SHA, "package app mismatch")
    require(package_manifest["output"]["sha256"] == PACKAGE_SHA, "package SHA manifest mismatch")
    require(package_manifest["protected_flash_hashes_before"] == package_manifest["protected_flash_hashes_after"], "protected region changed")
    print("v15 R01b artifact integrity: PASS")
    print("app", APP_SHA)
    print("package", PACKAGE_SHA)
    print("hooks: Ch10 Note On + Note Off -> shared snapshot wrapper")
    print("live function: Note Off PASS; intended BUZZ BASS identity FAIL/REVOKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
