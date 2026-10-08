#!/usr/bin/env python3
"""Offline validator for S2 persistent-default BLOCK evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWED = {"README.md", "SHA256SUMS", "analyze.py", "evidence.json", "report.md", "validate.py", "validation.txt"}
FORBIDDEN_SUFFIXES = {".fwsc"}
FORBIDDEN_NAMES = {"app.bin", "exact_ota", "exact_ota.c", "rollback", "rollback-manifest.json"}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def shaf(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args: list[str | Path]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run([str(x) for x in args], cwd=HERE, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise SystemExit(
            "FAIL: command returned %d: %s\nstdout:\n%s\nstderr:\n%s"
            % (result.returncode, " ".join(map(str, args)), result.stdout, result.stderr)
        )
    return result


def main() -> None:
    analysis = run([sys.executable, "analyze.py", "--check"])
    req("BLOCK persistent-default candidate" in analysis.stdout, "analysis reaches BLOCK")

    ev = json.loads((HERE / "evidence.json").read_text())
    req(ev["decision"] == "BLOCK" and ev["candidate_built"] is False, "BLOCK decision")
    req(ev["scope"] == {
        "custom_persistent_write_designed": False,
        "device_accessed": False,
        "flash_performed": False,
        "midi_transport_opened": False,
        "offline_only": True,
        "ota_performed": False,
        "reset_performed": False,
    }, "offline scope exact")
    req(ev["packet_and_table_evidence"]["packet_count"] == 16, "16 packet set")
    req(ev["packet_and_table_evidence"]["playback_notes"]["value"] == 60, "all-C4 playback map")
    req(ev["packet_and_table_evidence"]["all_packets_match_proven_runtime_table"] is True, "Bank D runtime identity")
    req(ev["packet_and_table_evidence"]["exact_expanded_table_present_in_target_inputs"] is False, "no exact target table")
    req(all(x["decision"] == "BLOCK" for x in ev["source_matrix"]), "all source routes blocked")
    req(all(x["decision"] == "BLOCK" for x in ev["fit_evidence"]["fit_attempts"]), "all fit routes blocked")
    req(ev["fit_evidence"]["owned_executable_window"]["bytes"] == 278, "owned code window")
    req(ev["fit_evidence"]["official_factory_expansion_spans"]["pure_128_to_156_conversion_core"]["bytes"] == 178, "conversion core span")
    req(ev["fit_evidence"]["fit_attempts"][0]["remaining_bytes"] == 12, "core-only remaining bytes")
    req(ev["fit_evidence"]["fit_attempts"][1]["overrun_bytes"] == 38, "full official path overrun")
    req(all(v is False for k, v in ev["emitted_artifacts"].items() if k != "reason"), "no release artifacts emitted")

    actual = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "__pycache__"}
    req(actual == ALLOWED, f"BLOCK-only file set: {sorted(actual)}")
    req(not any(p.is_dir() and p.name != "__pycache__" for p in HERE.iterdir()), "no rollback or artifact directories")
    for p in HERE.iterdir():
        req(p.suffix not in FORBIDDEN_SUFFIXES, f"forbidden package artifact {p.name}")
        req(p.name not in FORBIDDEN_NAMES, f"forbidden release artifact {p.name}")

    sums = {}
    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        sums[name] = digest
    req(set(sums) == ALLOWED - {"SHA256SUMS"}, "SHA256SUMS exact inventory")
    for name, digest in sums.items():
        req(shaf(HERE / name) == digest, f"SHA256SUMS {name}")

    report = (HERE / "report.md").read_text()
    for phrase in [
        "S2 persistent-default fit-first result: BLOCK",
        "No firmware candidate, FWSC, rollback bundle, or exact OTA executable is emitted",
        "No device, MIDI transport, OTA, reset, or flash operation was performed",
    ]:
        req(phrase in report, "report phrase: " + phrase)

    print(analysis.stdout, end="")
    print("PASS BLOCK-only artifact inventory")
    print("PASS no app/FWSC/rollback/exact OTA artifacts")
    print("PASS SHA256SUMS")
    print("BLOCK S2 persistent default candidate")


if __name__ == "__main__":
    main()
