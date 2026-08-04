#!/usr/bin/env python3
"""Offline self-check for the S1-C4 Playback Note v2 safety review plan."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
README = ROOT / "README.md"
text = README.read_text(encoding="utf-8")
required = [
    "Fail-closed fallback instruction ordering",
    "Trigger Note source invariance",
    "Symmetric Note On/Off metadata and Note On velocity",
    "ARMED and valid ordering",
    "`0x9b` restoration and voice copy boundary",
    "Producer reset and later packet behavior",
    "Code window and branch target gates",
    "Rollback gates",
    "OTA and sender gates",
    "device_accessed=false",
    "midi_transport_opened=false",
    "flash_performed=false",
    "0x0201e1a2..0x0201e254",
    "slot = note - 36",
    "`state=ARMED` is the final publication action",
]
missing = [item for item in required if item not in text]
if missing:
    for item in missing:
        print(f"missing: {item}", file=sys.stderr)
    sys.exit(1)
for forbidden in ("/dev/", "ioreg", "system_profiler", "dfu"):
    if forbidden in text.lower():
        print(f"forbidden device/live token present: {forbidden}", file=sys.stderr)
        sys.exit(1)
print("PASS: review plan contains all required safety checklist topics")
