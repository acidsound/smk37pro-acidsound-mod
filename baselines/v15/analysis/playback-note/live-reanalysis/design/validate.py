#!/usr/bin/env python3
"""Validate the S1-C4 withdrawal / S1-C5 successor design report.

Offline-only checks. This script reads existing evidence and the design report.
It does not build firmware, create binaries, open USB/MIDI, reset, flash, or send.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
HERE = Path(__file__).resolve().parent
REPORT = HERE / "report.md"

EXPECTED_HASHES = {
    "build/v15-official-app.bin": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/app.bin": "7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b",
    "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/selector.bin": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/producer.bin": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
}

REQUIRED_PATHS = [
    "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md",
    "baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/live-validation-20260803.md",
    "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/report.md",
    "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/producer/report.md",
    "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/evidence.json",
    "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv",
    "baselines/v15/analysis/playback-note/segmented-abi/report.md",
    "baselines/v15/analysis/playback-note/v3-segmented-review/review.md",
]

REQUIRED_TEXT = [
    "S1-C4 must be withdrawn",
    "DESIGN ONLY, NO FIRMWARE CANDIDATE",
    "wire byte `161 == trigger note 36..51`",
    "wire byte `161 == 60` repeated",
    "Physical Trigger Note / slot publication identity",
    "Playback Note metadata",
    "allowed to duplicate arbitrarily",
    "including all slots equal to `60`",
    "existing 16 resident patch slots",
    "No use outside `0x01c46520..0x01c46fb0`",
    "`0x0201e13e..0x0201e254`",
    "Note On and Note Off return the same effective Playback Note",
    "Rollback sector scope",
    "Live test matrix",
    "`L1 all C4 arm`",
    "no firmware candidate",
]

FORBIDDEN_SUFFIXES = {
    ".bin",
    ".hex",
    ".fwsc",
    ".zip",
    ".dmg",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg: str) -> None:
    print(f"FAIL\t{msg}")
    sys.exit(1)


def main() -> None:
    if not REPORT.is_file():
        fail("report.md missing")
    text = REPORT.read_text(encoding="utf-8")

    for needle in REQUIRED_TEXT:
        if needle not in text:
            fail(f"required text missing: {needle}")
        print(f"PASS\trequired-text\t{needle}")

    for rel in REQUIRED_PATHS:
        path = ROOT / rel
        if not path.is_file():
            fail(f"required evidence path missing: {rel}")
        print(f"PASS\tevidence-path\t{rel}")

    for rel, expected in EXPECTED_HASHES.items():
        path = ROOT / rel
        if not path.is_file():
            fail(f"hash input missing: {rel}")
        actual = sha256_file(path)
        if actual != expected:
            fail(f"hash mismatch for {rel}: {actual} != {expected}")
        print(f"PASS\tsha256\t{rel}\t{actual}")

    evidence = json.loads((ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/evidence.json").read_text())
    if evidence["selector"]["start"] != "0x0201e13e" or evidence["producer"]["end_exclusive"] != "0x0201e252":
        fail("unexpected S1-C4 code-cave basis")
    if not evidence["selector"].get("source_invariant", "").startswith("source slot = trigger_note"):
        fail("source invariant evidence missing")
    print("PASS\ts1c4-code-cave-basis\tselector 0x0201e13e, producer end 0x0201e252")

    generated = []
    for p in HERE.iterdir():
        if p.name in {"report.md", "validate.py", "validation.txt", "SHA256SUMS"}:
            continue
        if p.suffix.lower() in FORBIDDEN_SUFFIXES:
            generated.append(str(p.relative_to(ROOT)))
    if generated:
        fail("forbidden firmware-like artifact in design dir: " + ", ".join(generated))
    print("PASS\tno-firmware-artifacts-in-design-dir")

    print("S1-C4 withdrawal successor design validation PASS")


if __name__ == "__main__":
    main()
