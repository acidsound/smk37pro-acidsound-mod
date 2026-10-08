#!/usr/bin/env python3
"""Validate the extended (v2) memory map and its README.

Checks:
  1. row schema, unique ids, allowed confidence values
  2. numeric rows satisfy size == end_exclusive - start
  3. every source_artifacts entry exists in the repository
  4. the flash_physical confirmed rows tile 0x0..0x100000 exactly, with no gap
     and no overlap (the chip bound must be closed)
  5. coverage.json is internally consistent with the map's coverage row
  6. README.md still carries the required headings/claims
  7. every row that mentions 0x04000000 is marked BLOCKED unless it is
     explicitly an evidence-of-failure row

Offline only.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[4]
HERE = pathlib.Path(__file__).resolve().parent
MAP = HERE / "memory-map-v2.json"
COV = HERE / "coverage.json"
README = HERE / "README.md"

REQUIRED = {"id", "address_space", "section", "start", "end_exclusive", "size",
            "type_owner", "evidence_confidence", "mutability_patch_policy",
            "source_artifacts", "notes"}
CONF = {"PROVEN", "OBSERVED", "INFERRED", "BLOCKED", "REFUTED"}
FLASH_END = 0x00100000


def is_hex(value) -> bool:
    return isinstance(value, str) and value.startswith("0x")


def main() -> int:
    obj = json.loads(MAP.read_text())
    assert obj["format"] == "smk37-v15-memory-map-v2", obj["format"]
    assert obj["extends"].endswith("memory-map/memory-map.json")
    rows = obj["rows"]
    ids = set()
    for row in rows:
        missing = REQUIRED - set(row)
        assert not missing, (row.get("id"), missing)
        assert row["id"] not in ids, row["id"]
        ids.add(row["id"])
        assert row["evidence_confidence"] in CONF, row
        if is_hex(row["start"]) and is_hex(row["end_exclusive"]):
            assert row["size"] == int(row["end_exclusive"], 16) - int(row["start"], 16), row["id"]
            assert row["size"] >= 0, row["id"]
        assert row["source_artifacts"], row["id"]
        for src in row["source_artifacts"]:
            assert (ROOT / src).exists(), f"{row['id']}: missing source {src}"

    # 4. flash tiling
    flash = sorted((int(r["start"], 16), int(r["end_exclusive"], 16), r["id"])
                   for r in rows if r["address_space"] == "flash_physical"
                   and r["section"] == "confirmed")
    assert flash, "no flash_physical confirmed rows"
    cursor = 0
    for start, end, rid in flash:
        assert start == cursor, f"flash gap/overlap before {rid}: expected 0x{cursor:x} got 0x{start:x}"
        assert end > start, rid
        cursor = end
    assert cursor == FLASH_END, f"flash tiling ends at 0x{cursor:x}, expected 0x{FLASH_END:x}"

    # 5. coverage consistency
    cov = json.loads(COV.read_text())
    summary = cov["summary"]
    assert summary["recursive_decoded_bytes"] == 149332, summary
    assert summary["exhaustive_decoded_bytes"] == 325010, summary
    assert summary["pages"] == 151, summary
    assert summary["pages_without_recursive_decode"] == 67, summary
    cv = next(r for r in rows if r["id"] == "v2-cv-004")
    assert cv["size"] == cov["inputs"]["app_image_size"], (cv, cov["inputs"])
    assert int(cv["end_exclusive"], 16) == int(cov["inputs"]["runtime_end_exclusive"], 16), cv

    # 7. SDRAM rows must be BLOCKED or evidence rows
    for row in rows:
        if is_hex(row["start"]) and row["address_space"] == "sdram_window":
            if row["section"] == "evidence":
                continue
            assert row["evidence_confidence"] == "BLOCKED", row["id"]

    # 6. README claims
    text = README.read_text()
    for phrase in [
        "CONFIG_NO_SDRAM_ENABLE",
        "0x04000000",
        "Jieli Forced Upgrade Tool 4.0",
        "5caaaf32d214e04617ff03e3dd4a40221a578e01be06e4188316bc0568ee8daa",
        "673da1d518eff494d0cf63c549d0ccffd63f5a8764f49ffa60d0d4d283af33bb",
        "Offline only",
        "not evidence of free space",
    ]:
        assert phrase in text, f"README missing: {phrase}"

    # 8b. the USB identity block must sit inside the measured undecoded data run
    usb = next(r for r in rows if r["id"] == "v2-usb-001")
    assert 0x02057000 <= int(usb["start"], 16) and int(usb["end_exclusive"], 16) <= 0x02097000, usb

    # 8. every relative markdown link in the report resolves
    links = sorted(set(re.findall(r"\]\(([^)]+)\)", text)))
    broken = [l for l in links
              if not l.startswith("http") and not (HERE / l).resolve().exists()]
    assert not broken, f"broken links in README.md: {broken}"

    print(f"PASS rows={len(rows)} links={len(links)} "
          f"sha256={hashlib.sha256(MAP.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
