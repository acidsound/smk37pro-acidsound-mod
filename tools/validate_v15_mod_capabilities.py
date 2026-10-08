#!/usr/bin/env python3
"""Validate claims and checklist state in the official-v15 capability matrix."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "baselines/v15/analysis/mod-capability-matrix.md"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01/package-manifest.json"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
R01_APP = ROOT / "build/v15-R01-hand-drum-app.bin"
R01_PACKAGE = ROOT / "build/SMK37Pro-v15-R01-hand-drum.fwsc"
LIVE_REPORT = ROOT / "baselines/v15/analysis/flash-candidates/R01/live-validation-20260802.md"

OFFICIAL_APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
R01_APP_SHA = "e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7"
R01_PACKAGE_SHA = "292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462"
EXPECTED_CHANGE_ADDRESSES = {
    "0x0201c67c",
    "0x0201e13e",
    "0x0201e468",
    "0x0201e49c",
}
LIVE_VALIDATED_IDS = {
    "PKG-01",
    "MIDI-01",
    "VOICE-01",
    "VOICE-02",
    "NOTE-01",
}
STATIC_BUILD_ONLY_IDS = {
    "NOTE-02",
    "OTA-01",
}
UNVALIDATED_IDS = {
    "DRUM-01",
    "FM-01",
    "UI-02",
    "UI-03",
    "CTRL-01",
    "POLY-01",
    "SYSEX-01",
    "STAB-01",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def table_row(text: str, capability_id: str) -> str:
    match = re.search(rf"^\| `{re.escape(capability_id)}` \|.*$", text, re.MULTILINE)
    require(match is not None, f"missing capability row {capability_id}")
    return match.group(0)


def main() -> int:
    for path in (DOC, APP_MANIFEST, PACKAGE_MANIFEST, OFFICIAL_APP, R01_APP, R01_PACKAGE, LIVE_REPORT):
        require(path.is_file(), f"missing required file: {path.relative_to(ROOT)}")

    text = DOC.read_text()
    live_report = LIVE_REPORT.read_text()
    app_manifest = json.loads(APP_MANIFEST.read_text())
    package_manifest = json.loads(PACKAGE_MANIFEST.read_text())

    require(sha256(OFFICIAL_APP) == OFFICIAL_APP_SHA, "official v15 app SHA mismatch")
    require(sha256(R01_APP) == R01_APP_SHA, "R01 app SHA mismatch")
    require(sha256(R01_PACKAGE) == R01_PACKAGE_SHA, "R01 package SHA mismatch")
    require(app_manifest["input_app_sha256"] == OFFICIAL_APP_SHA, "app manifest input SHA mismatch")
    require(app_manifest["output_app_sha256"] == R01_APP_SHA, "app manifest output SHA mismatch")
    require(package_manifest["output"]["app_sha256"] == R01_APP_SHA, "package app SHA mismatch")
    require(package_manifest["output"]["sha256"] == R01_PACKAGE_SHA, "package SHA mismatch")
    require(package_manifest["safety_gate"] == "PASS", "package safety gate is not PASS")
    require(
        package_manifest["protected_flash_hashes_before"]
        == package_manifest["protected_flash_hashes_after"],
        "protected flash hashes changed",
    )

    changes = {change["address"] for change in app_manifest["changes"]}
    require(changes == EXPECTED_CHANGE_ADDRESSES, f"unexpected R01 change addresses: {sorted(changes)}")
    evidence = app_manifest["evidence"]
    require(evidence["dispatcher"] == "0x0201c5ec", "dispatcher address mismatch")
    require(evidence["note_on_memcpy"] == "0x0201c67c", "Note On address mismatch")
    require(evidence["note_off_memcpy_unchanged"] == "0x0201c63e", "Note Off address mismatch")
    require(evidence["factory_loader"] == "0x02005660", "factory loader address mismatch")
    require(evidence["memcpy"] == "0x02048cce", "memcpy address mismatch")
    require(evidence["channel_register"] == "r9", "channel register mismatch")
    require(app_manifest["voice"]["name"] == "HAND DRUM ", "factory voice identity mismatch")
    require(app_manifest["voice"]["runtime_sha256"] == "98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf", "runtime voice SHA mismatch")

    for capability_id in LIVE_VALIDATED_IDS:
        row = table_row(text, capability_id)
        require(row.count("[x]") >= 3, f"{capability_id} must retain static, build, and live checks")
    for capability_id in STATIC_BUILD_ONLY_IDS:
        row = table_row(text, capability_id)
        require(row.count("[x]") >= 2, f"{capability_id} must retain static and build checks")
        require("[ ]" in row, f"{capability_id} must remain device-unverified")
    voice3_row = table_row(text, "VOICE-03")
    require("[ ] | [x] | [ ]" in voice3_row, "VOICE-03 must record build-only, live-disproven state")
    require("직접 snapshot 주입 가설은 폐기" in voice3_row, "VOICE-03 revocation is missing")
    pad_row = table_row(text, "PAD-01")
    require("[x] 실기 확인" in pad_row, "PAD-01 physical Ch10 observation is missing")
    ui_row = table_row(text, "UI-01")
    require("[x] | [ ] | [x]" in ui_row, "UI-01 historical validation state changed")
    for capability_id in UNVALIDATED_IDS:
        row = table_row(text, capability_id)
        require("[ ]" in row, f"{capability_id} must remain explicitly unvalidated")

    for required_live_claim in (
        "Ch1/Ch10 branch separation | **PASS**",
        "Static 156-byte snapshot selects the named factory voice | **FAIL**",
        "Ch10 can yet be assigned an intentional known Patch | **NOT ESTABLISHED**",
        "The device was restored to exact official v15",
    ):
        require(required_live_claim in live_report, f"missing live-result claim: {required_live_claim}")

    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        require((DOC.parent / target).resolve().is_file(), f"broken local link: {target}")

    print("v15 mod capability matrix: PASS")
    print(f"official app: {OFFICIAL_APP_SHA}")
    print(f"R01 app:      {R01_APP_SHA}")
    print(f"R01 package:  {R01_PACKAGE_SHA}")
    print("live-validated capabilities: " + ", ".join(sorted(LIVE_VALIDATED_IDS)))
    print("VOICE-03 factory-voice snapshot injection: live-disproven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
