#!/usr/bin/env python3
"""Validate the official-v15 evidence gates used by design/report.md.

This script is read-only. It does not build, patch, package, or flash firmware.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
REPORT = HERE / "report.md"
APP = ROOT / "build/v15-official-app.bin"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
LIVE = ROOT / "baselines/v15/analysis/flash-candidates/R01/live-validation-20260802.md"
R01B = ROOT / "baselines/v15/analysis/flash-candidates/R01b/app-manifest.json"
R01C = ROOT / "baselines/v15/analysis/flash-candidates/R01c/app-manifest.json"
FACTORY_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/report.md"
FACTORY_EVIDENCE = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/factory_loader_evidence.json"
DECISION_MATRIX = HERE / "decision-matrix.json"
RUNTIME_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md"

APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
LISTING_SHA256 = "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"
RUNTIME_BASE = 0x02000000

ALLOWED_ABSOLUTE_ADDRESSES = {
    "0x01c33260",
    "0x01c34c74",
    "0x0200552e",
    "0x0200558e",
    "0x020055f8",
    "0x0200562c",
    "0x02005660",
    "0x020057de",
    "0x0201c5ec",
    "0x0201c63e",
    "0x0201c67c",
    "0x0201e13e",
    "0x0201e162",
    "0x0201e468",
    "0x0201e49c",
    "0x02048cce",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def app_bytes(app: bytes, address: int, length: int) -> bytes:
    offset = address - RUNTIME_BASE
    require(0 <= offset <= len(app) - length, f"address outside official app: 0x{address:08x}")
    return app[offset : offset + length]


def listing_rows() -> dict[int, str]:
    rows: dict[int, str] = {}
    with gzip.open(LISTING, "rt", errors="replace") as handle:
        for line in handle:
            try:
                address = int(line.split("\t", 1)[0], 16)
            except (ValueError, IndexError):
                continue
            rows[address] = line.rstrip("\n")
    return rows


def manifest_change_addresses(path: Path) -> set[str]:
    data = json.loads(path.read_text())
    return {change["address"].lower() for change in data["changes"]}


def validate_links(text: str) -> None:
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        require((REPORT.parent / target).resolve().is_file(), f"broken local link: {target}")


def main() -> int:
    for path in (
        REPORT, DECISION_MATRIX, APP, LISTING, LIVE, R01B, R01C,
        FACTORY_REPORT, FACTORY_EVIDENCE, RUNTIME_REPORT,
    ):
        require(path.is_file(), f"missing input: {path.relative_to(ROOT)}")

    require(sha256(APP) == APP_SHA256, "official v15 app SHA-256 mismatch")
    require(sha256(LISTING) == LISTING_SHA256, "official v15 exhaustive listing SHA-256 mismatch")

    app = APP.read_bytes()
    require(
        app_bytes(app, 0x0201C63E, 6) == bytes.fromhex("80ff8ac60200"),
        "stock Note Off memcpy call changed",
    )
    require(
        app_bytes(app, 0x0201C67C, 6) == bytes.fromhex("80ff4cc60200"),
        "stock Note On memcpy call changed",
    )
    require(
        app_bytes(app, 0x0201C602, 6) == bytes.fromhex("c8ff744cc301"),
        "stock current-source immediate changed",
    )
    require(
        app_bytes(app, 0x02005660, 12) == bytes.fromhex("780440e0a403c4ff6032c301"),
        "factory loader entry/global-object immediate changed",
    )
    require(
        app_bytes(app, 0x02005694, 12) == bytes.fromhex("10e1144a6a2380ff2e360400"),
        "factory loader destination/length sequence changed",
    )

    rows = listing_rows()
    expected_rows = {
        0x02005666: "mov r4,#0x1c33260",
        0x02005682: "ldw r7,r4,#0x164",
        0x02005694: "add r0,r4,0x1a14",
        0x02005698: "mov r2,#0xa3",
        0x02005768: "add r6,r4,0x1ab0",
        0x0201C5FE: "and r9,r3,#0xffffff0f",
        0x0201C602: "mov r8,#0x1c34c74",
        0x0201C63A: "mov r2,#0x9c",
        0x0201C67A: "mov r1,r8",
    }
    for address, fragment in expected_rows.items():
        require(address in rows, f"listing row missing at 0x{address:08x}")
        require(fragment in rows[address], f"listing evidence mismatch at 0x{address:08x}")

    require(0x01C33260 + 0x1A14 == 0x01C34C74, "current object alias arithmetic failed")

    required_hooks = {"0x0201c63e", "0x0201c67c"}
    for label, path in (("R01b", R01B), ("R01c", R01C)):
        require(
            required_hooks <= manifest_change_addresses(path),
            f"{label} does not contain matched Note On/Off hook changes",
        )

    r01c_data = json.loads(R01C.read_text())
    factory_data = json.loads(FACTORY_EVIDENCE.read_text())
    mooger = factory_data["bank_d_mooger_path"]
    hashes = mooger["hashes"]
    require(
        mooger["static_vs_live_source"]["clean_mooger_first_0x9c_equal"] is True,
        "factory evidence no longer proves clean Mooger first-0x9c equality",
    )
    require(
        hashes["static_128_to_156_sha256"] == hashes["simulated_live_first_0x9c_sha256"],
        "static and simulated-loader first-0x9c hashes differ",
    )
    require(
        r01c_data["voice"]["runtime_sha256"] == hashes["simulated_live_first_0x9c_sha256"],
        "R01c source no longer equals clean simulated-loader first 0x9c",
    )

    live = LIVE.read_text()
    for phrase in (
        "| Ch1/Ch10 branch separation | **PASS** |",
        "| Shared Ch10 source for Note On/Off prevents the R01 stuck note | **PASS in R01b/R01c** |",
        "| Static 156-byte snapshot selects the named factory voice | **FAIL** |",
        "| Ch10 can yet be assigned an intentional known Patch | **NOT ESTABLISHED** |",
    ):
        require(phrase in live, f"live evidence phrase missing: {phrase}")

    runtime_text = RUNTIME_REPORT.read_text()
    require(
        "`0x01c34c74`는 독립 static DX7 blob이 아니라 `0x01c33260 + 0x1a14`" in runtime_text,
        "runtime producer report no longer states the current-object alias",
    )

    matrix = json.loads(DECISION_MATRIX.read_text())
    require(matrix["status"] == "design_ready_not_patch_ready", "decision matrix status changed")
    require([item["id"] for item in matrix["designs"]] == ["A", "B", "C"], "decision matrix must contain A/B/C in order")
    require(matrix["final_decision"]["approved_patch_spec"] is None, "matrix unexpectedly approves a patch spec")
    require(matrix["fixed_evidence"]["clean_mooger_negative_evidence"]["byte_equal"] is True, "matrix lost clean Mooger negative evidence")

    report = REPORT.read_text()
    for heading in (
        "## A. UI Patch/runtime object 완전 clone 후 loader 호출",
        "## B. factory bank entry를 기존 loader로 로드한 별도 RAM object",
        "## C. Note On 시 current object pointer/state 전환",
        "## 5. code cave와 최소 패치 경계",
        "## 6. 조건부 최소 패치 계약",
    ):
        require(heading in report, f"required design section missing: {heading}")

    addresses = {value.lower() for value in re.findall(r"0x[0-9a-fA-F]{8}", report)}
    unexpected = addresses - ALLOWED_ABSOLUTE_ADDRESSES
    require(not unexpected, f"report contains non-allowlisted absolute addresses: {sorted(unexpected)}")
    validate_links(report)

    print("v15 Ch10 A/B/C design validation: PASS")
    print(f"official app:     {APP_SHA256}")
    print(f"official listing: {LISTING_SHA256}")
    print("alias:            0x01c33260 + 0x1a14 == 0x01c34c74")
    print("stock hooks:      Note Off 0x0201c63e, Note On 0x0201c67c")
    print("live gates:       branch PASS, matched On/Off PASS, static snapshot FAIL")
    print("Mooger gate:      R01c source == clean simulated-loader first 0x9c")
    print("patch status:     design-ready, no cave/RAM address approved")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
