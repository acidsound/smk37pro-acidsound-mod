#!/usr/bin/env python3
"""Blocked dry-run host packet plan for S1-C2.

This tool never opens MIDI devices and has no send implementation. It only
recomputes the two exact 163-byte direct product packet hashes recorded in
`evidence.json` so reviewers can verify the pinned packet order.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
EVIDENCE = HERE / "evidence.json"
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
TOKEN = "SEND-SMK37-V15-S1C2-TWO-PACKETS-6A9B-C4E8"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_packet(payload_path: Path) -> bytes:
    payload = payload_path.read_bytes()
    if len(payload) != 0x9C:
        raise SystemExit(f"payload is not 156 bytes: {payload_path}")
    return HEADER + payload + TERM


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--token", help="Must equal the blocked review token. It still will not enable sending.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()

    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    if args.token and args.token != TOKEN:
        raise SystemExit("confirmation token mismatch")

    rows = []
    for item in evidence["host_packets"]["packets_in_order"]:
        path = ROOT / item["runtime_object_path"]
        packet = build_packet(path)
        actual = {
            "order": len(rows) + 1,
            "slot": item["slot"],
            "fixed_note": item["fixed_note"],
            "factory_bank_letter": item["factory_bank_letter"],
            "factory_bank_1_based": ord(item["factory_bank_letter"]) - ord("A") + 1,
            "factory_patch_1_based": item["factory_patch_1_based"],
            "factory_name": item["factory_name"],
            "packet_length": len(packet),
            "packet_sha256": sha256(packet),
            "runtime_object_sha256": sha256(path.read_bytes()),
        }
        if actual["packet_sha256"] != item["packet_sha256"]:
            raise SystemExit(f"packet hash mismatch for {path}")
        rows.append(actual)

    output = {
        "status": "DRY_RUN_PASS",
        "send_enabled": False,
        "reason": "This Python helper is dry-run only; the separately compiled exact C sender performs the authorized live transfer.",
        "confirmation_token": TOKEN,
        "packets_in_order": rows,
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("S1-C2 host sender dry-run: PASS")
        print(f"confirmation token: {TOKEN}")
        for row in rows:
            print(
                f"{row['order']}. slot{row['slot']} note {row['fixed_note']}: "
                f"Bank {row['factory_bank_letter']} ({row['factory_bank_1_based']}), "
                f"patch {row['factory_patch_1_based']}, {row['factory_name']}, "
                f"packet {row['packet_length']} bytes sha256={row['packet_sha256']}"
            )
        print("No MIDI device was opened by this dry-run helper.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
