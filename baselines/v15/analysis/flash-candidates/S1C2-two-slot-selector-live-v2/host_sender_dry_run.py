#!/usr/bin/env python3
"""Dry-run host packet plan for S1-C2 v2.

This tool never opens MIDI devices. It verifies the two exact committed 163-byte
packet files and prints the fixed send order using the current evidence schema.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence.json"
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rows = []
    for item in evidence["host_packets"]["packets_in_order"]:
        packet_path = HERE / item["packet_file"]
        packet = packet_path.read_bytes()
        if len(packet) != item["packet_length"] or not packet.startswith(HEADER) or not packet.endswith(TERM):
            raise SystemExit(f"packet framing/length mismatch: {packet_path}")
        digest = sha256(packet)
        if digest != item["packet_sha256"]:
            raise SystemExit(f"packet hash mismatch: {packet_path}")
        rows.append({
            "order": item["order"],
            "slot": item["slot"],
            "fixed_note": item["fixed_note"],
            "factory_bank_letter": item["factory_bank_letter"],
            "factory_patch_1_based": item["factory_patch_1_based"],
            "factory_name": item["factory_name"],
            "packet_file": item["packet_file"],
            "packet_length": len(packet),
            "packet_sha256": digest,
        })
    output = {"status": "DRY_RUN_PASS", "send_enabled": False, "packets_in_order": rows}
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("S1-C2 v2 host sender dry-run PASS")
        for row in rows:
            print(f"{row['order']}. slot{row['slot']} note {row['fixed_note']}: {row['factory_name']} {row['packet_length']} bytes sha256={row['packet_sha256']}")
        print("No MIDI device is opened by this dry-run tool.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
