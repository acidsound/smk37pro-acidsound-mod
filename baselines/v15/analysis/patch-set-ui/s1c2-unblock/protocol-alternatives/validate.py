#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
HERE = Path(__file__).resolve().parent

EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"

REQUIRED_REPORT_MARKERS = [
    "Status: **BLOCK for a no-new-parser S1-C2 candidate**",
    "S1-C2 **cannot safely avoid a new parser entirely**",
    "0x0202d202",
    "0x0201e468",
    "0x0201e49c",
    "0x0201e1a2..0x0201e1ec",
    "STATE = ARMED",
    "Sequential official product packets",
    "Smallest discriminator",
    "No S1-C2 firmware candidate should be built",
]

REQUIRED_EVIDENCE = {
    "decision": "BLOCK",
    "format": "smk37-v15-s1c2-protocol-alternatives-v1",
}

EXPECTED_HASHES = {
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/report.md": "e06dc98dc0495b154ec50ec25b848b6a00a6a1e314117562ba8577e5d6997481",
    "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/evidence.json": "b0e60b37e05ffa8075aaa9b39acf0149f1cd5b822579d2e3535e6f217da1af60",
    "baselines/v15/analysis/patch-set-ui/s1c1/ingress/report.md": "c6b5e86fc1a0e66912c54aa361f8309ba6e918914ac5ed254b094935ed64b76c",
    "baselines/v15/analysis/patch-set-ui/architecture.md": "049732dc4eccc0b1e99fb7f1a6390a1e1bd774f560f461fd08cb4ccd3cd00993",
    "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md": "cafbbf22c4f9751a0134ecb0ab9734d6c62be4e5f06cbcb34448e70d8c308932",
    "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md": "cfabba55680bbee2f699316547ef28ec496434d886a3b2edf4d7e3a421c8d6f8",
    "baselines/v15/analysis/channel-separation-reanalysis/r02-review/report.md": "7efe6912d854b356c64daee4758b5442a07175b4a0c6d215f5fe4f9e4bae50f0",
    "baselines/v15/analysis/flash-candidates/H1-producer-unconsumed/live-validation-20260802.md": "852cdc5287ae631a0d97d3e8a930696f3f9a34ad26b6cea4de0e4ff7f6c0e2dc",
    "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md": "b2aca5903390cffe573f42c89aa6407a52c28f967124a07b407887959d1c8fd7",
    "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/review/jcode-pass-review-75e7180-20260802T2154Z.md": "95e8100ca529a2af7868ddef43f549d2868c824550261cc8323946874d3b29d2",
    "baselines/v15/analysis/patch-set-ui/s1c1/code/report.md": "a326c3ec72273530239b7c87963141f89ddde2879fba9eddeca4689c63786aa3",
    "baselines/v15/analysis/patch-set-ui/s1c1/ram/report.md": "52a71a8b84f8d497586cf21668a3e44d391337fb6758e34f9c615d35505e0943",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"FAIL: {msg}")


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report = REPORT.read_text(encoding="utf-8")

    for key, value in REQUIRED_EVIDENCE.items():
        require(evidence.get(key) == value, f"evidence {key}")

    require(evidence["scope"].startswith("read-only analysis"), "non-action scope")
    require("No S1-C2 firmware candidate" in report, "firmware no-build blocker")

    for marker in REQUIRED_REPORT_MARKERS:
        require(marker in report, f"report marker {marker!r}")

    source_hashes = evidence.get("source_hashes", {})
    require(source_hashes == EXPECTED_HASHES, "source hash table is exact")
    for rel, expected in EXPECTED_HASHES.items():
        require(sha256(ROOT / rel) == expected, f"source hash {rel}")

    alternatives = {entry["id"]: entry for entry in evidence["alternatives"]}
    require(alternatives["A"]["status"] == "BLOCK", "direct product packet alternative blocked")
    require(alternatives["B"]["status"] == "BLOCK pending discriminator", "segmented-only alternative gated")
    require(alternatives["C"]["status"].startswith("PARTIAL PASS"), "shadow activation partial pass")
    require(alternatives["D"]["status"].startswith("BLOCK"), "generation counters blocked")
    require(alternatives["E"]["status"] == "BLOCK", "double buffering blocked")

    invariants = "\n".join(evidence["strict_invariants_required_if_unblocked"])
    for phrase in ["Before ARMED", "valid1", "STATE", "firmware", "same note-to-slot"]:
        require(phrase in invariants, f"invariant phrase {phrase}")

    print("S1-C2 protocol alternatives validation: PASS")
    print(f"report {sha256(REPORT)}")
    print(f"evidence {sha256(EVIDENCE)}")


if __name__ == "__main__":
    main()
