#!/usr/bin/env python3
"""Offline validator for S1C6 raw17 persistence BLOCK evidence."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ALLOWED = {"README.md", "SHA256SUMS", "analyze.py", "evidence.json", "persistence_writer.py", "report.md", "validate.py", "validation.txt"}
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
    req("BLOCK app/FWSC/exact OTA/rollback emission" in analysis.stdout, "analysis reaches BLOCK")
    writer = run([sys.executable, "persistence_writer.py", "--json"])
    encoded = json.loads(writer.stdout)
    req(encoded["record_count"] == 17 and encoded["payload_record_count"] == 16, "offline writer encodes 17 raw prefixes")
    req(encoded["writer_scope"] == {
        "device_accessed": False,
        "flash_performed": False,
        "midi_transport_opened": False,
        "offline_encoder_only": True,
        "persistent_storage_write_performed": False,
    }, "writer offline scope")

    ev = json.loads((HERE / "evidence.json").read_text())
    req(ev["decision"] == "BLOCK" and ev["candidate_built"] is False, "BLOCK decision")
    req(ev["scope"] == {
        "device_accessed": False,
        "flash_performed": False,
        "fwsc_emitted": False,
        "midi_transport_opened": False,
        "offline_only": True,
        "ota_performed": False,
        "reset_performed": False,
    }, "offline scope exact")
    req(ev["storage_plan"]["payload_records"] == 16 and ev["storage_plan"]["manifest_records"] == 1, "17-record storage plan")
    req(ev["offline_persistence_writer"]["status"] == "PASS_OFFLINE_ENCODER_ONLY", "offline writer evidence")
    fit = ev["fit_evidence"]
    req(fit["available_windows"]["save_no_write_dead_slice"]["bytes"] == 44, "SAVE dead slice size")
    req(fit["raw_payload_fallback_helper_lower_bound"]["decision_vs_save_dead_slice"] == "BLOCK", "raw fallback standalone block")
    req(fit["manifest_variant_helper_lower_bound"]["decision_vs_save_dead_slice"] == "BLOCK", "manifest fallback standalone block")
    compact = fit["compact_successor_fit_after_boar_dm"]
    req(compact["fits_if_direct_only_no_reset_no_manifest_no_readback"] is True, "compact direct-only fit acknowledged")
    req(compact["direct_only_no_reset_no_manifest_no_readback_bytes"] == 276, "compact direct-only byte count")
    req(compact["overrun_with_segmented_stub"] == 2, "segmented overrun")
    req(compact["overrun_with_slot0_reset_floor"] == 28, "reset overrun")
    req(compact["overrun_with_defensible_readback_floor"] > 0, "readback overrun")
    req(compact["decision"] == "BLOCK_AS_DEFENSIBLE_SUCCESSOR", "compact path not promoted")
    req(all(v is False for k, v in ev["emitted_artifacts"].items() if k in {"app_bin", "fwsc", "exact_ota", "rollback_bundle"}), "no release artifacts emitted")

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
        "S1C6 raw17 persistence successor fit-first result: BLOCK",
        "Compact direct-only raw16/no-readback variant",
        "No app, FWSC, exact OTA, or rollback bundle is emitted",
    ]:
        req(phrase in report, "report phrase: " + phrase)

    print(analysis.stdout, end="")
    print("PASS offline 17-prefix encoder")
    print("PASS compact-producer fit path evaluated and blocked for defensibility")
    print("PASS BLOCK-only artifact inventory")
    print("PASS SHA256SUMS")
    print("BLOCK S1C6 raw17 persistence successor")


if __name__ == "__main__":
    main()
