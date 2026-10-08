#!/usr/bin/env python3
"""Validate the v15 patch-set UI integration evidence package offline."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = Path(__file__).resolve().parents[5]
EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"
SUMS = HERE / "SHA256SUMS"

EXPECTED_SCHEMA = "smk37-v15-patch-set-ui-integration-evidence-v1"
EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
EXPECTED_H2_APP_SHA256 = "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59"
RUNTIME_BASE = 0x02000000
FLASH_DELTA = 0x4120
ALLOWED_CLASSES = {"proven_fact", "constrained_inference", "blocker"}
EXPECTED_PACKAGE_FILES = {"report.md", "evidence.json", "validate.py", "validation.txt", "SHA256SUMS"}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_hex(value: str, label: str) -> int:
    require(isinstance(value, str) and re.fullmatch(r"0x[0-9a-f]+", value) is not None,
            f"{label} is not normalized lowercase hex: {value!r}")
    return int(value, 16)


def validate_sources(data: dict) -> int:
    sources = data.get("source_registry")
    require(isinstance(sources, dict) and sources, "source_registry missing or empty")
    for name, item in sources.items():
        require(set(item) == {"path", "sha256"}, f"source {name} has unexpected keys")
        path = ROOT / item["path"]
        require(path.is_file(), f"source missing: {item['path']}")
        actual = digest(path)
        require(actual == item["sha256"],
                f"source hash mismatch for {item['path']}: {actual} != {item['sha256']}")
    require(sources["official_app"]["sha256"] == EXPECTED_APP_SHA256,
            "official app source hash is not exact v15")
    return len(sources)


def validate_findings(data: dict) -> tuple[int, int, int, int]:
    findings = data.get("findings")
    require(isinstance(findings, list) and findings, "findings missing or empty")
    source_names = set(data["source_registry"])
    ids: set[str] = set()
    app_addresses = 0
    counts = {name: 0 for name in ALLOWED_CLASSES}

    for finding in findings:
        finding_id = finding.get("id")
        require(isinstance(finding_id, str) and finding_id, "finding without id")
        require(finding_id not in ids, f"duplicate finding id {finding_id}")
        ids.add(finding_id)
        classification = finding.get("classification")
        require(classification in ALLOWED_CLASSES,
                f"finding {finding_id} has invalid classification {classification!r}")
        counts[classification] += 1
        require(isinstance(finding.get("domain"), str) and finding["domain"],
                f"finding {finding_id} lacks domain")
        require(isinstance(finding.get("statement"), str) and len(finding["statement"]) >= 20,
                f"finding {finding_id} has inadequate statement")
        sources = finding.get("sources")
        require(isinstance(sources, list) and sources, f"finding {finding_id} lacks sources")
        for source in sources:
            require(source.get("ref") in source_names,
                    f"finding {finding_id} references unknown source {source.get('ref')!r}")
            require(isinstance(source.get("locator"), str) and source["locator"],
                    f"finding {finding_id} has empty source locator")

        addresses = finding.get("addresses")
        require(isinstance(addresses, list), f"finding {finding_id} addresses is not a list")
        for index, address in enumerate(addresses):
            kind = address.get("kind")
            label = f"{finding_id}.addresses[{index}]"
            require(isinstance(address.get("role"), str) and address["role"],
                    f"{label} lacks role")
            if kind == "app":
                va = parse_hex(address.get("runtime_va"), f"{label}.runtime_va")
                file_offset = parse_hex(address.get("file_offset"), f"{label}.file_offset")
                flash_offset = parse_hex(address.get("flash_offset"), f"{label}.flash_offset")
                require(va == RUNTIME_BASE + file_offset,
                        f"{label} VA/file formula mismatch")
                require(flash_offset == file_offset + FLASH_DELTA,
                        f"{label} flash/file formula mismatch")
                require(0 <= file_offset < 617012, f"{label} outside official app")
                app_addresses += 1
            elif kind == "ram":
                parse_hex(address.get("address"), f"{label}.address")
            elif kind == "ram_range":
                start = parse_hex(address.get("start"), f"{label}.start")
                end = parse_hex(address.get("end_inclusive"), f"{label}.end_inclusive")
                require(start <= end, f"{label} reversed RAM range")
            else:
                fail(f"{label} has invalid kind {kind!r}")

    required_ids = {
        "PF-002", "PF-003", "PF-004", "PF-005", "PF-008", "PF-010",
        "PF-013", "PF-015", "PF-016", "PF-017", "PF-018",
        "CI-001", "BL-001", "BL-002", "BL-003", "BL-004",
    }
    require(required_ids <= ids, f"required findings missing: {sorted(required_ids - ids)}")
    require(counts["proven_fact"] >= 12, "too few proven facts")
    require(counts["constrained_inference"] >= 2, "too few constrained inferences")
    require(counts["blocker"] >= 6, "too few blockers")
    return len(findings), app_addresses, counts["proven_fact"], counts["blocker"]


def validate_cross_evidence(data: dict) -> None:
    require(data.get("schema") == EXPECTED_SCHEMA, "schema mismatch")
    scope = data.get("scope", {})
    require(scope.get("official_app_sha256") == EXPECTED_APP_SHA256, "scope official hash mismatch")
    require(scope.get("h2_app_sha256") == EXPECTED_H2_APP_SHA256, "scope H2 hash mismatch")
    require(scope.get("runtime_base") == "0x02000000", "runtime base mismatch")
    require(scope.get("app_to_flash_delta") == "0x00004120", "flash delta mismatch")
    require(scope.get("h2_live_verdict") == "PASS", "H2 live verdict is not PASS")
    forbidden_actions = set(scope.get("actions_not_performed", []))
    require({"firmware patch", "flash", "device access"} <= forbidden_actions,
            "non-action scope is incomplete")

    by_id = {item["id"]: item for item in data["findings"]}
    require(by_id["PF-017"].get("machine_values") == {
        "sdk_exact_accepted_count": 0,
        "sdk_relocation_aware_accepted_count": 0,
    }, "LED zero-match evidence changed")
    memory = by_id["BL-002"].get("machine_values", {})
    require(memory.get("single_snapshot_bytes") == 0x9C, "single snapshot size mismatch")
    require(memory.get("sixteen_snapshot_bytes") == 16 * 0x9C, "16-snapshot size mismatch")
    require(memory.get("sixteen_snapshot_hex") == "0x09c0", "16-snapshot hex mismatch")

    h2_manifest = json.loads((ROOT / data["source_registry"]["h2_manifest"]["path"]).read_text())
    policy = h2_manifest["h2_policy"]
    require(policy["consumer_source_when_valid"] == "0x01c46520", "H2 source changed")
    require(policy["copy_size"] == 156, "H2 copy size changed")
    require(policy["valid"] == "0x01c465bc", "H2 valid address changed")
    require(policy["lock"] == "0x01c465bd", "H2 lock address changed")
    require(policy["save_policy"].startswith("blocked before first persistent write"),
            "H2 SAVE policy changed")

    sdk = json.loads((ROOT / data["source_registry"]["sdk_json"]["path"]).read_text())
    require(sdk["summary"]["exact_accepted_count"] == 0, "SDK exact accepted count changed")
    require(sdk["summary"]["relocation_aware_accepted_count"] == 0,
            "SDK relocation-aware accepted count changed")
    live_text = (ROOT / data["source_registry"]["h2_live"]["path"]).read_text()
    require("H2 LIVE PASS" in live_text, "H2 live PASS marker missing")

    decision = data.get("design_decision", {})
    require(decision.get("status") == "design_only_blocked_for_implementation",
            "design status overclaims implementation readiness")
    require(decision.get("recommended_first_mutating_checkpoint") ==
            "U1 visual-only volatile selector after U0 runtime mapping",
            "first checkpoint decision changed")
    forbidden = set(decision.get("forbidden_in_U1", []))
    require({"per-note audio routing", "SAVE or any persistence", "LED writes", "custom LCD path"} <= forbidden,
            "U1 forbidden list is incomplete")


def validate_report(data: dict) -> None:
    require(REPORT.is_file(), "report.md missing")
    text = REPORT.read_text()
    required_phrases = [
        "## Proven facts",
        "## Constrained inferences",
        "## Hard blockers",
        "U0: read-only runtime mapping",
        "U1: safest first mutating UI checkpoint",
        "No product LED address is proven",
        "MIDI note identity is not proven",
        "No firmware was patched",
        "No device was accessed",
    ]
    for phrase in required_phrases:
        require(phrase in text, f"report missing required phrase: {phrase}")
    for finding_id in ("PF-004", "PF-010", "PF-013", "PF-017", "BL-001", "BL-002", "BL-003", "BL-004"):
        require(finding_id in text, f"report does not cite {finding_id}")
    require("0x01c33569..0x01c3356f" in text, "pending watch range missing")
    require("0x0201c67c" in text and "0x0201c63e" in text,
            "Note On/Off observation points missing")
    require("0x01c46520..0x01c465bd" in text, "U1 H2 invariant range missing")


def validate_package_scope(check_sums: bool) -> None:
    files = {path.name for path in HERE.iterdir() if path.is_file()}
    allowed_during_build = EXPECTED_PACKAGE_FILES | {"__pycache__"}
    require(files <= allowed_during_build, f"unexpected output files: {sorted(files - allowed_during_build)}")
    require({"report.md", "evidence.json", "validate.py"} <= files, "core package files missing")
    if check_sums:
        require(EXPECTED_PACKAGE_FILES <= files, "final package files missing")
        validate_sums()


def validate_sums() -> None:
    require(SUMS.is_file(), "SHA256SUMS missing")
    entries: dict[str, str] = {}
    for line_number, raw in enumerate(SUMS.read_text().splitlines(), 1):
        if not raw.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", raw)
        require(match is not None, f"invalid SHA256SUMS line {line_number}")
        sha, name = match.groups()
        require(name not in entries, f"duplicate SHA256SUMS entry {name}")
        entries[name] = sha
    expected = EXPECTED_PACKAGE_FILES - {"SHA256SUMS"}
    require(set(entries) == expected,
            f"SHA256SUMS entries mismatch: {sorted(entries)} != {sorted(expected)}")
    for name, expected_sha in entries.items():
        actual = digest(HERE / name)
        require(actual == expected_sha, f"checksum mismatch for {name}: {actual} != {expected_sha}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-sums", action="store_true", help="also verify final SHA256SUMS")
    args = parser.parse_args()

    require(EVIDENCE.is_file(), "evidence.json missing")
    data = json.loads(EVIDENCE.read_text())
    validate_package_scope(args.check_sums)
    validate_cross_evidence(data)
    source_count = validate_sources(data)
    finding_count, address_count, proven_count, blocker_count = validate_findings(data)
    validate_report(data)

    print("status: PASS")
    print(f"schema: {data['schema']}")
    print(f"official_app_sha256: {EXPECTED_APP_SHA256}")
    print(f"h2_app_sha256: {EXPECTED_H2_APP_SHA256}")
    print(f"sources_verified: {source_count}")
    print(f"findings_verified: {finding_count}")
    print(f"proven_facts: {proven_count}")
    print(f"blockers: {blocker_count}")
    print(f"app_addresses_formula_checked: {address_count}")
    print("led_product_addresses_promoted: 0")
    print("first_live_checkpoint: U0 read-only runtime mapping")
    print("first_mutating_checkpoint: U1 visual-only volatile selector")
    print("firmware_patch_flash_device_access: none")
    print(f"sha256sums_checked: {'yes' if args.check_sums else 'no (run --check-sums after generation)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
