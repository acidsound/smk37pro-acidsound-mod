#!/usr/bin/env python3
"""Validate the v15 per-note patch-set/UI checkpoint planning package."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
CHECKPOINTS = HERE.parent
REPO = Path(__file__).resolve().parents[6]
MATRIX = CHECKPOINTS / "decision-matrix.json"
REPORT = CHECKPOINTS / "report.md"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    checks: list[str] = []

    require(MATRIX.is_file(), "decision-matrix.json missing")
    require(REPORT.is_file(), "report.md missing")
    data = json.loads(MATRIX.read_text(encoding="utf-8"))
    report = REPORT.read_text(encoding="utf-8")
    checks.append("JSON parses and required report exists")

    require(data["schema"] == "smk37-v15-per-note-patch-set-ui-checkpoints-v1", "unexpected schema")
    scope = data["scope"]
    require(scope["planning_only"] is True, "planning_only must be true")
    for key in (
        "firmware_patched",
        "package_built",
        "device_accessed",
        "flashed_or_ota",
        "persistent_write_performed",
        "authorization_granted",
    ):
        require(scope[key] is False, f"scope.{key} must be false")
    checks.append("non-action scope is explicit")

    baseline = data["baseline"]
    require(
        baseline["app_sha256"]
        == "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
        "H2 app hash mismatch",
    )
    require(
        baseline["package_sha256"]
        == "c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011",
        "H2 package hash mismatch",
    )
    require(
        baseline["rollback_zip_sha256"]
        == "c7e0f92852c78d5864a2d60d2bee86215babe7b810e0e62d3c9f2c7d5e69739c",
        "H2 rollback hash mismatch",
    )
    require(
        baseline["official_v15_changed_sectors"]
        == ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"],
        "H2 sector inventory mismatch",
    )
    checks.append("H2 hashes and five-sector baseline match live evidence")

    expected_names = [
        "host-loaded per-note set",
        "physical control without display",
        "display",
        "persistence",
    ]
    stages = data["stages"]
    require(len(stages) == 4, "exactly four stages required")
    require([s["number"] for s in stages] == [1, 2, 3, 4], "stage numbers/order mismatch")
    require([s["name"] for s in stages] == expected_names, "stage names/order mismatch")
    checks.append("four requested stages are distinct and ordered")

    expected_integrations = [
        {"ui_event": False, "renderer": False, "persistence": False},
        {"ui_event": True, "renderer": False, "persistence": False},
        {"ui_event": True, "renderer": True, "persistence": False},
        {"ui_event": True, "renderer": True, "persistence": True},
    ]
    require([s["integrations"] for s in stages] == expected_integrations, "integration entry stage mismatch")
    entry = data["integration_entry"]
    require(entry["ui_event_trace"].startswith("S2-C1"), "event trace must enter at S2-C1")
    require(entry["ui_event_code"].startswith("S2-C2"), "event code must enter at S2-C2")
    require(entry["renderer_trace"].startswith("S3-C1"), "renderer trace must enter at S3-C1")
    require(entry["renderer_code"].startswith("S3-C2"), "renderer code must enter at S3-C2")
    require(entry["persistence_core"].startswith("S4-C1"), "persistence must enter at S4-C1")
    require(entry["ui_save_saved"].startswith("S4-C4"), "SAVE/SAVED must enter at S4-C4")
    require(entry["custom_lcd_graphics"] == "not in this sequence", "custom LCD must remain excluded")
    checks.append("event, renderer, persistence, and SAVE/SAVED entry gates are correct")

    checkpoints = [cp for stage in stages for cp in stage["checkpoints"]]
    require(len(checkpoints) == 15, "expected 15 checkpoints")
    ids = [cp["id"] for cp in checkpoints]
    require(len(ids) == len(set(ids)), "checkpoint IDs must be unique")
    for cp in checkpoints:
        require("single_uncertainty" in cp and cp["single_uncertainty"], f"{cp['id']} missing single uncertainty")
        require("discriminator" in cp and isinstance(cp["discriminator"], dict), f"{cp['id']} missing singular discriminator")
        require(set(cp["discriminator"]) == {"question", "pass", "fail"}, f"{cp['id']} discriminator shape mismatch")
        require(all(cp["discriminator"].values()), f"{cp['id']} discriminator fields must be nonempty")
        require(cp.get("live_observations"), f"{cp['id']} missing live observations")
        require(cp.get("stop_conditions"), f"{cp['id']} missing stop conditions")
        require(cp.get("rollback"), f"{cp['id']} missing rollback")
        require("discriminators" not in cp, f"{cp['id']} must not contain multiple discriminators")
    checks.append("all 15 checkpoints have one discriminator, observations, stops, and rollback")

    for stage in stages[:3]:
        for cp in stage["checkpoints"]:
            if cp["kind"].startswith("candidate"):
                require("no data sectors" in cp["rollback"], f"{cp['id']} must forbid data-sector rollback/write domain")
    for cp in stages[3]["checkpoints"]:
        require("data" in cp["rollback"], f"{cp['id']} must include data rollback")
    checks.append("rollback domains separate volatile stages from Stage 4 data writes")

    record = stages[3]["record_contract"]
    require(record["separate_from_stock_patch"] is True, "Stage 4 record must be separate from stock Patch")
    require(record["automatic_rewrite_on_invalid"] is False, "invalid record must not auto-rewrite")
    required_fields = set(record["required_fields"])
    require({"magic", "format_version", "total_length", "sequence", "CRC", "commit marker written last"} <= required_fields, "record fields incomplete")
    checks.append("Stage 4 separate versioned committed-record contract is present")

    source_count = 0
    for source in data["sources"]:
        path = (REPO / source["path"]).resolve()
        require(REPO == path or REPO in path.parents, f"source escapes repository: {source['path']}")
        require(path.is_file(), f"source missing: {source['path']}")
        require(sha256(path) == source["sha256"], f"source hash mismatch: {source['path']}")
        source_count += 1
    require(source_count == 7, "expected seven source provenance entries")
    checks.append("all seven source files exist and match recorded SHA-256")

    for heading in (
        "# Stage 1: host-loaded per-note set",
        "# Stage 2: physical control without display",
        "# Stage 3: display",
        "# Stage 4: persistence",
    ):
        require(heading in report, f"report missing heading: {heading}")
    for phrase in (
        "No device was accessed",
        "Every checkpoint changes one runtime uncertainty",
        "The stock 163-byte (`0xa3`) Patch record is never expanded",
        "SAVE/SAVED is a Stage 4 truth indicator",
    ):
        require(phrase in report, f"report missing required statement: {phrase}")
    checks.append("report contains stage distinctions and hard safety statements")

    require(data["global_stop_conditions"], "global stop conditions missing")
    require(data["rollback_policy"]["sector_size"] == 4096, "rollback sector size must be 4096")
    require(data["rollback_policy"]["stages_1_to_3"]["data_sectors"] == "zero writes allowed", "Stages 1-3 data write ban missing")
    checks.append("global stops and exact 4 KiB rollback discipline are present")

    for i, message in enumerate(checks, 1):
        print(f"PASS {i:02d}: {message}")
    print(f"PASS SUMMARY: {len(stages)} stages, {len(checkpoints)} checkpoints, {source_count} hashed sources")
    print("NON-ACTION: no patch, package, flash, device access, or persistent write was performed")


if __name__ == "__main__":
    main()
