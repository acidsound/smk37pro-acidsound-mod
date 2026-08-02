#!/usr/bin/env python3
"""Read-only validator for the S1-C2 fixed selector checkpoint.

Validates the analysis objects and refuses any app/FWSC candidate artifact in this
checkpoint directory. It does not build, patch, flash, or contact a device.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence.json"
REPORT = ROOT / "report.md"
OBJECTS_JSON = ROOT / "objects" / "objects.json"

FORBIDDEN_NAMES = {
    "app.bin",
    "candidate-app.bin",
    "SMK37Pro-v15-S1C2-fixed-selector.fwsc",
    "SMK37Pro-v15-S1C2-fixed-selector.zip",
    "package-manifest.json",
    "app-manifest.json",
}
FORBIDDEN_SUFFIXES = {".fwsc", ".ufw", ".zip"}

REQUIRED_REPORT_STRINGS = [
    "Status: **BLOCK for flash candidate",
    "No device, flash, OTA, reset, app candidate, or FWSC candidate was created",
    "Channel 10 notes `36` and `45`",
    "Note Off hook",
    "Note On hook",
    "Selector code total** | **58",
    "Selector + objects, no H2 producer** | **370",
    "Selector + objects + H2 producer** | **444",
    "OBJ0_ADDR` and `OBJ1_ADDR` are intentionally unassigned",
    "No runtime upload parser",
    "JLFS names it `cfg_tool.bin`",
    "Required validator assertions",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if not EVIDENCE.exists():
        fail("missing evidence.json")
    if not REPORT.exists():
        fail("missing report.md")
    if not OBJECTS_JSON.exists():
        fail("missing objects/objects.json")

    for path in ROOT.rglob("*"):
        rel = path.relative_to(ROOT)
        if path.name in FORBIDDEN_NAMES:
            fail(f"forbidden candidate artifact present: {rel}")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES:
            fail(f"forbidden firmware/package suffix present: {rel}")

    evidence = json.loads(EVIDENCE.read_text())
    objects_manifest = json.loads(OBJECTS_JSON.read_text())
    report = REPORT.read_text()

    if evidence["placement_decision"]["current"] != "BLOCK":
        fail("placement decision must remain BLOCK")
    if evidence["placement_decision"].get("candidate_built") is not False:
        fail("candidate_built must be false")
    if evidence["notes"] != {
        "note0": 36,
        "note1": 45,
        "midi_channel": 10,
        "channel_nibble": 9,
        "physical_pad_order_assumption": False,
    }:
        fail("unexpected note mapping")
    if evidence["notes"]["note0"] == evidence["notes"]["note1"]:
        fail("notes must be distinct")

    budget = evidence["pi32_budget"]
    expected_budget = {
        "selector_code_bytes": 58,
        "object0_bytes": 156,
        "object1_bytes": 156,
        "selector_plus_objects_bytes": 370,
        "h2_producer_preserve_bytes": 74,
        "selector_plus_objects_plus_h2_producer_bytes": 444,
    }
    if budget != expected_budget:
        fail(f"unexpected budget: {budget}")

    if len(evidence["objects"]) != 2:
        fail("expected exactly two objects")
    manifest_by_suffix = {o["object_path"]: o for o in objects_manifest["objects"]}
    for obj in evidence["objects"]:
        path = ROOT / obj["path"]
        if not path.exists():
            fail(f"missing object file: {obj['path']}")
        if path.stat().st_size != 156:
            fail(f"object is not 156 bytes: {obj['path']}")
        actual = sha256(path)
        if actual != obj["sha256"]:
            fail(f"object hash mismatch for {obj['path']}: {actual}")
        manifest_obj = next((m for p, m in manifest_by_suffix.items() if p.endswith(obj["path"])), None)
        if manifest_obj is None:
            fail(f"object missing from objects.json: {obj['path']}")
        if manifest_obj["runtime_sha256"] != obj["sha256"]:
            fail(f"objects.json hash mismatch for {obj['path']}")

    hooks = evidence["hooks"]
    if hooks["note_off"]["callsite"] != "0x0201c63e" or "r5" not in hooks["note_off"]["note_register"]:
        fail("Note Off hook ABI not asserted")
    if hooks["note_on"]["callsite"] != "0x0201c67c" or "r6" not in hooks["note_on"]["note_register"]:
        fail("Note On hook ABI not asserted")

    for needle in REQUIRED_REPORT_STRINGS:
        if needle not in report:
            fail(f"report missing required assertion: {needle}")

    print("PASS fixed-selector checkpoint validation")
    print("Validated: 2 offline objects, exact notes 36/45, PI32 budget, hook ABIs, BLOCK placement, no candidate artifacts")


if __name__ == "__main__":
    main()
