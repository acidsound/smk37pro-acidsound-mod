#!/usr/bin/env python3
"""Reproduce and validate the official-v15 UI preflash evidence package."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "baselines/v15/analysis/ui-preflash"
APP = ROOT / "build/v15-official-app.bin"
APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
SCRIPTS = [
    BASE / "renderer/analyze_renderer.py",
    BASE / "events/analyze_ui_events.py",
    BASE / "state-persistence/analyze_state_persistence.py",
]
JSON_FILES = [
    BASE / "renderer/evidence.json",
    BASE / "events/ui_events.json",
    BASE / "state-persistence/state_persistence_evidence.json",
]
REPORTS = [
    BASE / "README.md",
    BASE / "renderer/evidence-report.md",
    BASE / "events/report.md",
    BASE / "state-persistence/report.md",
    BASE / "review/requirements.md",
]
REQUIRED = {
    "0x01c33260",
    "0x02005660",
    "0x02029290",
    "0x02029528",
    "0x0202439e",
    "0x02058248",
    "0x0201a67c",
    "0x0200ea9a",
    "0x0200f74c",
    "0x02026d6c",
    "0x02004b02",
}


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    require(APP.is_file(), "official v15 app missing")
    require(hashlib.sha256(APP.read_bytes()).hexdigest() == APP_SHA, "official app SHA mismatch")

    for script in SCRIPTS:
        require(script.is_file(), f"missing analysis script: {script.relative_to(ROOT)}")
        subprocess.run(["python3", str(script)], cwd=ROOT, check=True)

    for path in JSON_FILES:
        require(path.is_file(), f"missing JSON evidence: {path.relative_to(ROOT)}")
        json.loads(path.read_text())

    for path in REPORTS:
        require(path.is_file() and path.stat().st_size > 500, f"missing/short report: {path.relative_to(ROOT)}")

    combined = "\n".join(path.read_text() for path in REPORTS)
    for address in REQUIRED:
        require(address in combined, f"required address absent from reports: {address}")

    require("renderer/LCD/button/persistence ABI" in (BASE / "README.md").read_text(), "checkpoint limitation missing")
    require("미확정" in (BASE / "renderer/evidence-report.md").read_text(), "renderer unresolved state missing")
    require("caller remains unresolved" in (BASE / "events/report.md").read_text(), "event-vector limitation missing")
    require("exact-storage-primitive-direction" in (BASE / "state-persistence/report.md").read_text(), "storage direction limitation missing")
    require("REQ-10" in (BASE / "review/requirements.md").read_text(), "evidence requirements incomplete")

    print("v15 UI preflash evidence: PASS")
    print(f"official app: {APP_SHA}")
    print("reproduced: renderer, events, state-persistence")
    print("confirmed Patch selection fields: bank +0x3a4, preset +0x3a0+bank")
    print("UI patch remains blocked on renderer, event caller, storage direction, and RAM ownership")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
