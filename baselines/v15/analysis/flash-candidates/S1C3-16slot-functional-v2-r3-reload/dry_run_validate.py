#!/usr/bin/env python3
"""Dry-run validator for the S1-C3 exact 16-packet host plan.

This tool never opens USB/MIDI. It verifies the self-contained packet manifest,
packet bytes, note-order invariant, and UI-only physical Pad permutation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKET_DIR = HERE / "inputs" / "packets"
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
EXPECTED_PAD_TO_SLOT = [4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()
    manifest = json.loads((PACKET_DIR / "packet-manifest.json").read_text(encoding="utf-8"))
    permutation = json.loads((PACKET_DIR / "physical-pad-permutation.json").read_text(encoding="utf-8"))
    req(manifest["status"] == "PASS", "packet manifest PASS")
    req(manifest["order_basis"] == "note_order_36_51", "packet manifest note order")
    req(manifest["physical_pad_permutation"]["ui_only"] is True, "manifest Pad permutation UI-only")
    req(permutation["ui_only"] is True, "Pad permutation file UI-only")
    req(permutation["pad_1_to_16_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "Pad permutation value")
    rows = []
    for index, item in enumerate(manifest["packets"]):
        req(item["slot"] == index and item["order"] == index + 1 and item["note"] == 36 + index, f"note order item {index}")
        packet = (PACKET_DIR / item["file"]).read_bytes()
        digest = sha256(packet)
        req(len(packet) == 163, f"packet length item {index}")
        req(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing item {index}")
        req(digest == item["sha256"], f"packet hash item {index}")
        rows.append({
            "order": item["order"],
            "slot": item["slot"],
            "note": item["note"],
            "name": item["name"],
            "file": item["file"],
            "packet_sha256": digest,
        })
    output = {
        "status": "DRY_RUN_PASS",
        "send_enabled": False,
        "device_accessed": False,
        "packet_order_basis": "note_order_36_51",
        "physical_pad_permutation_scope": "UI_ONLY",
        "packets_in_order": rows,
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("S1-C3 16-slot dry-run validator PASS")
        print("Producer/selector/sender order: note-order slots 0..15 -> notes 36..51")
        print("Physical Pad permutation is UI-only metadata and is not used for send order")
        for row in rows:
            print(f"{row['order']:02d}. slot{row['slot']:02d} note {row['note']}: {row['name']} sha256={row['packet_sha256']}")
        print("No USB/MIDI device is opened by this dry-run tool.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
