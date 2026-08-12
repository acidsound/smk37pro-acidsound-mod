#!/usr/bin/env python3
"""Validate R01c artifact integrity, not the disproven timbre identity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "build/v15-R01c-mooger1-app.bin"
PACKAGE = ROOT / "build/SMK37Pro-v15-R01c-mooger1.fwsc"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01c/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01c/package-manifest.json"
OFFICIAL_APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
APP_SHA = "37fe48e8215b7d8036c5cd98a0ff0962abe260dc2af13f633b749c527b96e2cb"
PACKAGE_SHA = "b34d19e144281e21d1aae141315c3214950d4cf06aa9b0db840d9ebdc15770a7"
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
    require(sha256(APP) == APP_SHA, "R01c app SHA mismatch")
    require(sha256(PACKAGE) == PACKAGE_SHA, "R01c package SHA mismatch")
    require(app_manifest["input_app_sha256"] == OFFICIAL_APP_SHA, "official app gate mismatch")
    require(app_manifest["output_app_sha256"] == APP_SHA, "app manifest output mismatch")
    require(app_manifest["format"] == "smk37-v15-r01c-channel10-factory-mooger1-noteoff-v1", "format mismatch")
    require({item["address"] for item in app_manifest["changes"]} == EXPECTED_ADDRESSES, "unexpected patch addresses")
    require(app_manifest["evidence"]["note_on_memcpy"] == "0x0201c67c", "Note On hook mismatch")
    require(app_manifest["evidence"]["note_off_memcpy"] == "0x0201c63e", "Note Off hook mismatch")
    require(app_manifest["evidence"]["channel_register"] == "r9", "channel register mismatch")
    require(app_manifest["voice"]["name"] == "Mooger #1 ", "voice mismatch")
    require(app_manifest["voice"]["bank"] == 3 and app_manifest["voice"]["preset"] == 13, "voice index mismatch")
    require(package_manifest["safety_gate"] == "PASS", "package safety gate failed")
    require(package_manifest["output"]["app_sha256"] == APP_SHA, "package app mismatch")
    require(package_manifest["output"]["sha256"] == PACKAGE_SHA, "package SHA manifest mismatch")
    require(package_manifest["protected_flash_hashes_before"] == package_manifest["protected_flash_hashes_after"], "protected region changed")
    print("v15 R01c artifact integrity: PASS")
    print("app", APP_SHA)
    print("package", PACKAGE_SHA)
    print("hooks: Ch10 Note On + Note Off -> shared snapshot wrapper")
    print("live function: Note Off PASS; intended Mooger #1 identity FAIL/REVOKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
