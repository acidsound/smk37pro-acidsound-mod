#!/usr/bin/env python3
"""Validate the S1-C3 16-slot functional offline skeleton without device access."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDER = HERE / "build_s1c3_16slot_functional.py"
EVIDENCE = HERE / "evidence.json"
BLOCK = HERE / "BLOCK.md"
SHA256SUMS = HERE / "SHA256SUMS"
FORBIDDEN_WHILE_BLOCKED = [
    "app.bin",
    "SMK37Pro-v15-S1C3-16slot-functional.fwsc",
    "app-manifest.json",
    "package-manifest.json",
    "exact_ota.c",
    "guarded_sender.py",
    "rollback",
]
EXPECTED_BLOCKERS = {
    "BLOCK_COMPACT_PRODUCER_PASS_INPUT_UNAVAILABLE",
    "BLOCK_16_PACKET_SET_PASS_INPUT_UNAVAILABLE",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    result = subprocess.run([sys.executable, str(BUILDER), "check-inputs"], cwd=HERE, text=True, capture_output=True, check=False)
    req(result.returncode == 0, "builder check-inputs exited nonzero\n" + result.stdout + result.stderr)
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    req(evidence["format"] == "smk37-v15-s1c3-16slot-functional-offline-skeleton-v1", "evidence format")
    req(evidence["decision"] == "BLOCK", "current decision is BLOCK until missing inputs PASS")
    req(evidence["candidate_built"] is False, "candidate not built while blocked")
    req(evidence["device_accessed"] is False and evidence["midi_transport_opened"] is False and evidence["flash_performed"] is False, "offline-only scope")

    gates = {gate["name"]: gate for gate in evidence["input_gates"]}
    req(gates["exact-live-pass-s1c3-boundary-app"]["status"] == "PASS", "boundary gate PASS")
    req(gates["reviewed-96-byte-16-note-selector"]["status"] == "PASS", "selector gate PASS")
    req(gates["reviewed-96-byte-16-note-selector"]["selector_size"] == 96, "selector is 96 bytes")
    blocker_codes = {blocker["code"] for blocker in evidence["blockers"]}
    req(blocker_codes == EXPECTED_BLOCKERS, f"exact blocker set {blocker_codes}")
    req(BLOCK.exists() and "No missing bytes were invented" in BLOCK.read_text(encoding="utf-8"), "BLOCK.md exact scope")

    for rel in FORBIDDEN_WHILE_BLOCKED:
        req(not (HERE / rel).exists(), f"forbidden blocked output exists: {rel}")

    for line in SHA256SUMS.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        req(sha256(HERE / rel) == digest, f"SHA256SUMS mismatch: {rel}")

    print("S1-C3 16-slot functional offline skeleton validation PASS (blocked on exact missing inputs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
