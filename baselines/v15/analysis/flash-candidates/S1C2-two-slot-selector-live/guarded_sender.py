#!/usr/bin/env python3
"""Guarded S1-C2 packet sender plan.

Default mode is dry-run only and opens no MIDI ports. Live sending is refused
unless this file is intentionally extended with a project-approved transport.
"""
from __future__ import annotations
import argparse, hashlib
from pathlib import Path
ROOT = Path(__file__).resolve().parents[5]
HEADER = bytes.fromhex("f0430000011b")
TERM = bytes([0xf7])
OBJECTS = [
    ("Mooger #1", 0, 36, ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note45-bankD14-Mooger_1.runtime156.bin", "e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275", "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27"),
    ("HAND DRUM", 1, 45, ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note36-bankD12-HAND_DRUM.runtime156.bin", "98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf", "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d"),
]
def h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dry-run", action="store_true", default=True)
    p.add_argument("--live-send", action="store_true", help="refused by this guarded artifact")
    args = p.parse_args()
    for name, slot, note, path, object_sha, packet_sha in OBJECTS:
        payload = path.read_bytes()
        packet = HEADER + payload + TERM
        if len(payload) != 0x9c or h(payload) != object_sha or len(packet) != 0xa3 or h(packet) != packet_sha:
            raise SystemExit(f"packet invariant failed: {name}")
        print(f"{slot+1}: slot={slot} note={note} name={name} bytes={len(packet)} sha256={h(packet)}")
    if args.live_send:
        raise SystemExit("refusing live MIDI send: no device/OTA/flash/reset permitted by this package")
    print("dry-run only: no MIDI/device transport opened")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
