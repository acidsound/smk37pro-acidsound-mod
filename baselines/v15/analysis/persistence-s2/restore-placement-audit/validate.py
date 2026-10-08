#!/usr/bin/env python3
"""Offline validator for S2 restore placement audit BLOCK evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWED = {"README.md", "SHA256SUMS", "analyze_restore_placement.py", "evidence.json", "report.md", "validate.py", "validation.txt"}
FORBIDDEN_SUFFIXES = {".fwsc"}
FORBIDDEN_NAMES = {"app.bin", "exact_ota", "exact_ota.c", "rollback", "rollback-manifest.json", "host_sender.py"}


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
    analysis = run([sys.executable, "analyze_restore_placement.py", "--check"])
    req("BLOCK no defensible" in analysis.stdout, "analysis reaches BLOCK")

    ev = json.loads((HERE / "evidence.json").read_text())
    req(ev["format"] == "smk37-v15-s2-restore-placement-audit-v1", "format")
    req(ev["architecture_decision"]["decision"] == "BLOCK", "BLOCK decision")
    req(ev["architecture_decision"]["candidate_built"] is False, "no candidate")
    req(ev["scope"] == {
        "device_accessed": False,
        "flash_performed": False,
        "fwsc_emitted": False,
        "midi_transport_opened": False,
        "offline_only": True,
        "ota_performed": False,
    }, "offline scope exact")
    req(ev["s1c5_identity"]["selector"]["bytes"] == 88, "selector bytes")
    req(ev["s1c5_identity"]["producer"]["bytes"] == 188, "producer bytes")
    req(ev["s1c5_identity"]["owned_window"]["free_bytes_preserving_exact_selector_and_producer"] == 2, "2-byte tail")
    regions = ev["dead_region_audit"]["audited_regions"]
    req(regions[0]["bytes"] == 44 and regions[1]["bytes"] == 84 and regions[3]["bytes"] == 383, "dead/cave byte counts")
    gap_scan = ev["dead_region_audit"]["listing_gap_scan"]
    req(gap_scan["gap_count"] == 5735 and gap_scan["total_gap_bytes"] == 31342, "listing gap scan quantified")
    req(gap_scan["largest_gaps"][0] == {"bytes": 602, "end_exclusive": "0x02016ce2", "start": "0x02016a88"}, "largest listing gap")
    req(gap_scan["decision"].startswith("NOT PROMOTED"), "listing gaps not promoted")
    req(all("S1C7" in x["name"] or "S1C7" in x["blocker"] for x in [ev["architecture_decision"]["rejected_split_call_architectures"][-1]]), "S1C7 rejected")
    helpers = {h["name"]: h for h in ev["helper_audit"]["callable_helpers"]}
    req(helpers["read wrapper"]["bytes"] == 20 and helpers["write wrapper"]["bytes"] == 20, "read/write wrappers")
    req(ev["helper_audit"]["missing_helpers"]["listing_text_search_counts"] == {"crc": 0, "memcmp": 0, "strcmp": 0, "strncmp": 0, "compare": 0}, "no CRC/compare label hits")
    req(any("0x02005f9c" == c["site"] and c["decision"].startswith("REJECT") for c in ev["cross_cave_and_cold_paths"]["cold_ui_paths"]), "revoked boot hook rejected")
    req(any("0x02005fa4" == c["site"] and c["decision"].startswith("BLOCK") for c in ev["cross_cave_and_cold_paths"]["cold_ui_paths"]), "post-storage hook blocked")
    req("84-byte quarantined SAVE leaf" in ev["architecture_decision"]["next_discriminator"], "next discriminator precise")

    actual = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "__pycache__"}
    req(actual == ALLOWED, f"BLOCK-only file set: {sorted(actual)}")
    req(not any(p.is_dir() and p.name != "__pycache__" for p in HERE.iterdir()), "no artifact directories")
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
        "S2 restore placement audit: BLOCK",
        "No firmware candidate, FWSC, rollback bundle, exact OTA executable, or host/device writer is emitted",
        "S1C7 trusted full-length unseeded reads",
        "Next discriminator",
    ]:
        req(phrase in report, "report phrase: " + phrase)

    print(analysis.stdout, end="")
    print("PASS BLOCK-only artifact inventory")
    print("PASS no app/FWSC/rollback/exact OTA artifacts")
    print("PASS SHA256SUMS")
    print("BLOCK S2 restore placement audit")


if __name__ == "__main__":
    main()
