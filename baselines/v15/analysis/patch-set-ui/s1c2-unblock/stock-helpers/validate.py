#!/usr/bin/env python3
"""Validate the S1-C2 stock-helper unblock BLOCK evidence package.

Read-only: hashes exact inputs, checks selected decoder rows and negative scans,
and rejects candidate/device/flash-like artifacts in this analysis directory.
"""

from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require(condition: bool, msg: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {msg}")
    print(f"PASS\t{msg}")


def listing_rows(path: Path) -> dict[str, str]:
    rows: dict[str, str] = {}
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", errors="replace") as f:
        header = next(f)
        require(header.startswith("address\tbytes\tlength\tmnemonic\ttext"), f"listing header {path.name}")
        for line in f:
            addr = line.split("\t", 1)[0]
            rows[addr] = line.rstrip("\n")
    return rows


def main() -> None:
    evidence = json.loads(EVIDENCE.read_text())
    report = REPORT.read_text()

    require(evidence["decision"] == "BLOCK", "evidence decision BLOCK")
    require("Decision: **BLOCK**" in report, "report decision BLOCK")
    require("Tiny trampoline plus stock helpers | **BLOCK**" in report, "tiny trampoline BLOCK gate")
    require("No candidate, device access, OTA, flash" in report, "no candidate/device/flash statement")

    for rel, expected in evidence["input_hashes"].items():
        p = ROOT / rel
        require(p.is_file(), f"input exists {rel}")
        require(sha256(p) == expected, f"sha256 {rel}")

    forbidden_names = {
        "app.bin",
        "flash.bin",
        "package-manifest.json",
        "app-manifest.json",
        "rollback-manifest.json",
    }
    forbidden_suffixes = {".bin", ".fwsc", ".zip", ".ufw"}
    allowed = {"report.md", "evidence.json", "validate.py", "validation.txt", "SHA256SUMS"}
    for p in HERE.iterdir():
        if p.name in allowed:
            continue
        require(p.is_dir() is False, f"no unexpected subdirectory {p.name}")
        require(p.name not in forbidden_names and p.suffix not in forbidden_suffixes, f"no candidate artifact {p.name}")

    q_path = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
    k_path = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"
    q = listing_rows(q_path)
    k = listing_rows(k_path)

    expected_quarkslab = {
        "0202d182": ["jb", "0xfe"],
        "0202d200": ["mov", "r0,r6"],
        "0202d202": ["call", "0x0201e254"],
        "0201e254": ["push"],
        "0201e256": ["mov", "r4,r0"],
        "0201e258": ["mov", "r9,r1"],
        "0201e410": ["jne", "#0xf0"],
        "0201e416": ["jne", "#0x43"],
        "0201e44e": ["r9,#-0x6"],
        "0201e456": ["call", "0x02048cce"],
        "0201e462": ["jne", "#0xf7"],
        "0201e468": ["call", "0x0201e13e"],
        "0201e46c": ["call", "0x02005660"],
        "0201e484": ["jne", "#0x9e"],
        "0201e494": ["call", "0x02048cce"],
        "0201e49c": ["call", "0x0201e13e"],
        "0201e4a0": ["call", "0x02005660"],
        "0201e626": ["r4 + 0x3"],
        "0201e62a": ["lsl", "0x7"],
        "0201e630": ["uxtb"],
        "02005660": ["push"],
        "02005670": ["ja", "0x3"],
        "0200567e": ["ja", "0x1f"],
        "02005694": ["0x1a14"],
        "02005698": ["#0xa3"],
        "0200569a": ["call", "0x02048cce"],
        "02048cce": ["push"],
        "0201c63e": ["call", "0x02048cce"],
        "0201c67c": ["call", "0x02048cce"],
    }
    for addr, needles in expected_quarkslab.items():
        row = q.get(addr, "")
        require(row != "", f"quarkslab row {addr}")
        for needle in needles:
            require(needle in row, f"quarkslab row {addr} contains {needle}")

    expected_kagaimiq = {
        "0202d202": ["call", "0x0201e254"],
        "0201e254": ["push"],
        "0201e256": ["mov", "r4,r0"],
        "0201e258": ["mov", "r9,r1"],
        "0201e456": ["call", "0x02048cce"],
        "0201e468": ["call", "0x0201e13e"],
        "0201e46c": ["call", "0x02005660"],
        "0200569a": ["call", "0x02048cce"],
        "02048cce": ["push"],
        "0201c63e": ["call", "0x02048cce"],
        "0201c67c": ["call", "0x02048cce"],
    }
    for addr, needles in expected_kagaimiq.items():
        row = k.get(addr, "")
        require(row != "", f"kagaimiq row {addr}")
        for needle in needles:
            require(needle in row, f"kagaimiq row {addr} contains {needle}")

    for const in evidence["negative_scans"]["listing_constants_absent"]:
        q_hits = [row for row in q.values() if const in row]
        k_hits = [row for row in k.values() if const in row]
        require(not q_hits, f"quarkslab lacks CRC constant {const}")
        require(not k_hits, f"kagaimiq lacks CRC constant {const}")

    statuses = {item["capability"]: item["status"] for item in evidence["required_capability_results"]}
    require(statuses["bulk copy"] == "PASS", "bulk copy PASS")
    require(statuses["CRC-16 or packet checksum"] == "BLOCK", "CRC helper BLOCK")
    require(statuses["atomic publication, lock, state"] == "BLOCK for two slots", "two-slot atomic publication BLOCK")
    require(statuses["unchanged delegation to stock product SysEx"].startswith("PASS"), "delegation PASS")

    print("S1-C2 stock-helper unblock investigation: BLOCK PASS")


if __name__ == "__main__":
    main()
