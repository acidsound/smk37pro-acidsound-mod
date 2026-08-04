#!/usr/bin/env python3
"""Validator for the S1C7 live-failure root-cause package."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    subprocess.run([sys.executable, str(HERE / "analyze.py"), "--check"], check=True)
    ev = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
    req(ev["decision"] == "ROOT_CAUSE_CONFIRMED_SAFE_FWSC_BLOCKED", "decision")
    req(ev["scope"] == {
        "offline_only": True,
        "device_accessed": False,
        "midi_transport_opened": False,
        "flash_performed": False,
        "ota_performed": False,
        "reset_performed": False,
        "fwsc_emitted": False,
    }, "offline/no-firmware scope")
    req(ev["binaries"]["s1c5_to_s1c7_app_diff"]["producer_preserved_byte_for_byte"] is True, "producer preservation evidence")
    req(ev["live_dumps"]["preseed_dual_dump"]["byte_identical"] is True, "dual dumps identical")
    records = ev["live_dumps"]["raw_records_96_111_before_seed"]
    req(len(records) == 16, "sixteen records")
    req(all(r["prefix_all_zero"] and r["tail_hex"] == "64000000000000" for r in records), "all raw prefixes zero with expected tails")
    contract = "\n".join(ev["successor_design"]["minimum_contract"])
    req("S1C5 RAM is ARMED" in contract, "ARMED priority in contract")
    req("no positive persistent seed" in contract, "no-seed fallback in contract")
    req("magic" in contract and "CRC" in contract, "magic/CRC gate in contract")
    expected = {}
    for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        expected[name] = digest
    for name, digest in expected.items():
        req(shaf(HERE / name) == digest, f"sha inventory {name}")
    print("validation PASS: S1C7 root cause confirmed; safe FWSC blocked")


if __name__ == "__main__":
    main()
