#!/usr/bin/env python3
"""Validate the S1-C2 two-slot selector BLOCK evidence package.

This validator is intentionally read-only for S1-C2: a safe result is BLOCK, no
app.bin, no FWSC, no rollback ZIP, and no candidate package manifest.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
THIS = Path(__file__).resolve().parent

EXPECTED = {
    "s1c1_app_sha256": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "s1c1_fwsc_sha256": "ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d",
    "h2_app_sha256": "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    "h2_fwsc_sha256": "c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011",
}

REQUIRED_TEXT = {
    "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/live-validation-20260802.md": [
        "**LIVE PASS**",
        "additional `0xa0` BSS reservation",
        EXPECTED["s1c1_app_sha256"],
        EXPECTED["s1c1_fwsc_sha256"],
    ],
    "baselines/v15/analysis/patch-set-ui/s1c1/code/report.md": [
        "Note Off `r5 = msg[1]`: PASS",
        "Note On `r6 = msg[1]`: PASS",
        "PI32 encoding, placement, and branch reach: PASS",
        "Selector code: `",
        "bytes",
        "H2 producer `0x0201e1a2..0x0201e1ec` remains byte-for-byte unchanged",
    ],
    "baselines/v15/analysis/patch-set-ui/s1c1/ingress/report.md": [
        "**Protocol and two-slot publication design: PASS. Firmware implementation: BLOCK.**",
        "state = ARMED` last",
        "Executable placement and exact code size | **BLOCK**",
        "No verified callable CRC-16 routine is identified",
        "Do not hook the short/direct MIDI call at `0x0202d1fa`",
    ],
    "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/report.md": [
        "Preserves exact H2 code and behavior",
        "H2-to-child changed app bytes: `4`",
        "no per-note selector exists",
    ],
}

FORBIDDEN_CANDIDATE_NAMES = {
    "app.bin",
    "package-manifest.json",
    "SMK37Pro-v15-S1C2-two-slot-selector.fwsc",
    "SMK37Pro-v15-S1C2-two-slot-selector.zip",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def require_text(path: str, needles: list[str]) -> None:
    text = (ROOT / path).read_text(encoding="utf-8")
    for needle in needles:
        require(needle in text, f"missing {needle!r} in {path}")


def main() -> int:
    evidence_path = THIS / "evidence.json"
    report_path = THIS / "report.md"
    require(evidence_path.exists(), "evidence.json exists")
    require(report_path.exists(), "report.md exists")

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    require(evidence["format"] == "smk37-v15-s1c2-two-slot-selector-block-v1", "evidence format")
    require(evidence["decision"] == "BLOCK", "decision is BLOCK")
    require(evidence["candidate_created"] is False, "no candidate created flag")
    require(evidence["device_actions_performed"] is False, "no device actions flag")
    require(evidence["parent_hashes"] == EXPECTED, "parent hashes")
    require(evidence["requested_checkpoint"]["ram_boundary"] == "0x01c46520..0x01c46660", "RAM boundary")
    require(evidence["requested_checkpoint"]["explicit_known_notes"] == [36, 45], "explicit notes")
    require(evidence["candidate_delta"] == {
        "app_bytes_changed": 0,
        "changed_flash_sectors": [],
        "fwsc_bytes_changed": 0,
        "reason": "No flash candidate was created because executable placement for an atomic private host transaction remains unproved.",
    }, "zero S1-C2 delta")

    statuses = {g["gate"]: g["status"] for g in evidence["gate_results"]}
    require(statuses["S1-C1_memory_boundary"] == "PASS", "S1-C1 boundary pass recorded")
    require(statuses["note_register_ABI"] == "PASS static", "note ABI static pass recorded")
    require(statuses["selector_consumer_code_placement"] == "PASS static", "selector placement pass recorded")
    require(statuses["atomic_host_transaction_model"] == "PASS design only", "transaction model design pass recorded")
    require(statuses["atomic_host_transaction_executable_placement"] == "BLOCK", "transaction executable placement block recorded")
    require(statuses["sequential_official_product_packets"] == "BLOCK as implementation route", "sequential official packets blocked")

    for name in FORBIDDEN_CANDIDATE_NAMES:
        require(not (THIS / name).exists(), f"forbidden S1-C2 candidate artifact present: {name}")
    require(not any(p.suffix.lower() == ".fwsc" for p in THIS.iterdir()), "no S1-C2 FWSC in report directory")
    require(not any(p.suffix.lower() == ".zip" for p in THIS.iterdir()), "no S1-C2 rollback ZIP in report directory")

    for path, needles in REQUIRED_TEXT.items():
        require_text(path, needles)

    s1c1_manifest = json.loads((ROOT / "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/app-manifest.json").read_text(encoding="utf-8"))
    require(s1c1_manifest["output_app_sha256"] == EXPECTED["s1c1_app_sha256"], "S1-C1 manifest app hash")
    require(s1c1_manifest["h2_to_child_changed_byte_count"] == 4, "S1-C1 H2-relative byte count")
    require(s1c1_manifest["invariants"]["reserved_end"] == "0x01c46660", "S1-C1 reserved end")
    require(s1c1_manifest["invariants"]["selector_behavior"] is False, "S1-C1 selector absent")

    s1c1_package = json.loads((ROOT / "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/package-manifest.json").read_text(encoding="utf-8"))
    require(s1c1_package["output"]["sha256"] == EXPECTED["s1c1_fwsc_sha256"], "S1-C1 package hash")
    sectors = sorted({f"0x{x['start'] - x['start'] % 0x1000:05x}" for x in s1c1_package["changes"]["flash_ranges"]})
    require(sectors == ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"], "S1-C1 inherited sector set")

    report = report_path.read_text(encoding="utf-8")
    for needle in [
        "Status: **BLOCK, no flash candidate created**",
        "note 36 -> slot 0",
        "note 45 -> slot 1",
        "Sequential official product packets are not an admitted implementation route.",
        "S1-C2 app bytes changed: `0`",
        "S1-C2 changed Flash sectors: none",
    ]:
        require(needle in report, f"report contains {needle!r}")

    for rel in evidence["source_hashes"].keys():
        path = ROOT / rel
        require(path.exists(), f"source hash path exists: {rel}")

    print("S1-C2 two-slot selector checkpoint: BLOCK PASS")
    print(f"parent app {EXPECTED['s1c1_app_sha256']}")
    print(f"parent package {EXPECTED['s1c1_fwsc_sha256']}")
    print("S1-C2 changed bytes: 0; changed sectors: none; no app/FWSC/rollback generated")
    print("hard blocker: no proven executable placement for atomic private host transaction")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
