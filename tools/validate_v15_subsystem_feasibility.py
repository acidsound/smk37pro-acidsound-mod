#!/usr/bin/env python3
"""Validate the v15 subsystem feasibility dossier and top-level matrix."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "baselines/v15/analysis/subsystem-feasibility"
FILES = {
    "matrix": DIR / "matrix.md",
    "ui": DIR / "ui.md",
    "midi": DIR / "midi.md",
    "fm": DIR / "fm.md",
    "pcm": DIR / "pcm-realtime-synth.md",
    "lineage": DIR / "smk-docs-lineage.md",
    "r02_live": ROOT / "baselines/v15/analysis/flash-candidates/R02/live-validation-20260802.md",
}
PINS = {
    "smk_docs": "8f1bf1115cc8fe874bbac326d4f1f1513d743844",
    "ac79_sdk": "e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d",
    "quarkslab": "e1bd0707874b77b759401555d24839ad43af1267",
}
REQUIRED_FIELDS = ("| UI |", "| MIDI |", "| FM |", "| PCM |", "| 실시간 synthesis |")
REQUIRED_MATRIX_WORDS = ("V15", "SDK", "DOC", "BUILD", "LIVE", "[~]")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def validate_links(path: Path, text: str) -> None:
    for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        require((path.parent / target).resolve().is_file(), f"broken link in {path.name}: {target}")


def main() -> int:
    for name, path in FILES.items():
        require(path.is_file(), f"missing dossier file: {name} ({path})")
        require(path.stat().st_size > 500, f"dossier file is unexpectedly small: {path.name}")

    texts = {name: path.read_text() for name, path in FILES.items()}
    combined = "\n".join(texts.values())
    matrix = texts["matrix"]

    for pin_name, pin in PINS.items():
        require(pin in combined, f"missing pinned revision: {pin_name} {pin}")
    for field in REQUIRED_FIELDS:
        require(field in matrix, f"missing subsystem matrix rows: {field}")
    for word in REQUIRED_MATRIX_WORDS:
        require(word in matrix, f"matrix is missing evidence/status marker: {word}")

    require("Mooger #1" in matrix, "R02 named-timbre success is not explicit")
    require("transient" in matrix, "R02 transient-RAM limitation is not explicit")
    require("Ch10 전용 RAM" in matrix, "next owned-RAM checkpoint is missing")
    require("PASS as a controlled checkpoint" in texts["r02_live"], "R02 live result is missing")
    require("byte-identical" in texts["r02_live"], "R02 post-test official restore proof is missing")
    require("v15 addresses" in texts["pcm"], "PCM document does not preserve product-address uncertainty")
    require("57" in texts["pcm"] and "match" in texts["pcm"].lower(), "PCM document omits negative SDK match evidence")
    require("0x0201c5ec" in texts["midi"], "MIDI dispatcher evidence missing")
    require("0x0201c67c" in texts["midi"], "MIDI Note On evidence missing")
    require("0x000f7580" in texts["fm"], "FM HAND DRUM source evidence missing")
    require("156" in texts["fm"], "FM runtime voice size missing")
    require("0x5d8f5" in texts["ui"], "UI Firmware string offset missing")
    require("fork" in texts["lineage"].lower(), "lineage fork investigation missing")
    require("124" in texts["lineage"], "lineage commit-history count missing")

    for name, path in FILES.items():
        validate_links(path, texts[name])

    matrix_rows = [line for line in matrix.splitlines() if line.startswith("| ")]
    subsystem_rows = [row for row in matrix_rows if any(row.startswith(field) for field in REQUIRED_FIELDS)]
    require(len(subsystem_rows) >= 20, f"expected at least 20 subsystem rows, found {len(subsystem_rows)}")

    print("v15 subsystem feasibility dossier: PASS")
    print("documents: " + ", ".join(path.name for path in FILES.values()))
    print("pinned smk docs: " + PINS["smk_docs"])
    print("pinned AC79 SDK: " + PINS["ac79_sdk"])
    print(f"matrix subsystem rows: {len(subsystem_rows)}")
    print("R02 Ch10 Mooger #1 routing/Note Off: live-verified under transient-RAM constraints")
    print("PCM and new software synthesis remain live-unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
