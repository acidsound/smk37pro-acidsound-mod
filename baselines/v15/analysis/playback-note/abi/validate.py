#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[4]
BASE = 0x02000000
APP = REPO / "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/app.bin"
SYSEX = REPO / "apps/smk37-patch-set-editor/public/sysex.mjs"
APPJS = REPO / "apps/smk37-patch-set-editor/public/app.js"
EVIDENCE = HERE / "evidence.json"


def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def off(address: int) -> int:
    value = address - BASE
    req(value >= 0, f"address below base 0x{address:08x}")
    return value


def call32_target(address: int, blob: bytes) -> int:
    req(len(blob) == 6 and blob[:2] == b"\x80\xff", f"not call32 at 0x{address:08x}")
    return address + 6 + struct.unpack("<i", blob[2:6])[0]


def short_call_target(address: int, blob: bytes) -> int:
    req(len(blob) == 4 and blob[:2] == b"\xbf\xea", f"not short call at 0x{address:08x}")
    half = struct.unpack("<H", blob[2:4])[0]
    return ((address + 4 + half * 2) & 0xFFFF) | (address & 0xFFFF0000)


def hx(app: bytes, address: int, size: int) -> str:
    return app[off(address):off(address) + size].hex()


def main() -> int:
    evidence = json.loads(EVIDENCE.read_text())
    app = APP.read_bytes()

    req(evidence["format"] == "smk37-v15-s1c3-r3-reload-playback-note-abi-evidence-v1", "evidence format")
    req(evidence["trace_status"] == "PASS", "trace status")
    scope = evidence["scope"]
    for key in ["offline_only"]:
        req(scope[key] is True, f"scope {key}")
    for key in ["device_accessed", "flash_performed", "ota_performed", "reset_performed", "midi_transport_opened", "v12_assumptions_used"]:
        req(scope[key] is False, f"scope {key}")

    req(sha(app) == evidence["candidate"]["sha256"], "candidate app sha256")
    req(sha(app[off(0x0201e13e):off(0x0201e19e)]) == evidence["candidate"]["selector"]["sha256"], "selector slice sha256")
    req(sha(app[off(0x0201e1a2):off(0x0201e250)]) == evidence["candidate"]["producer"]["sha256"], "producer slice sha256")

    calls = evidence["exact_candidate_calls"]
    for key in ["note_off_hook", "note_on_hook"]:
        item = calls[key]
        address = int(item["address"], 16)
        blob = app[off(address):off(address) + 6]
        req(blob.hex() == item["bytes"], f"{key} bytes")
        req(call32_target(address, blob) == int(item["call32_target"], 16), f"{key} target")
    for key in ["direct_product_reset_wrapper_call", "direct_reload_preserved", "segmented_product_stub_call", "segmented_reload_preserved"]:
        item = calls[key]
        address = int(item["address"], 16)
        blob = app[off(address):off(address) + 4]
        req(blob.hex() == item["bytes"], f"{key} bytes")
        req(short_call_target(address, blob) == int(item["short_call_target"], 16), f"{key} target")

    selector = evidence["current_selector_abi"]
    req(hx(app, 0x0201e13e, 2) == selector["note_off_entry"]["bytes"], "Note Off adapter mov r3,r5")
    req(hx(app, 0x0201e140, 2) == selector["note_off_goto_core"]["bytes"], "Note Off adapter goto")
    req(hx(app, 0x0201e142, 2) == selector["note_on_entry"]["bytes"], "Note On adapter mov r3,r6")
    req(hx(app, 0x0201e144, 2) == selector["core_push"]["bytes"], "selector push saves native note regs")
    req(hx(app, 0x0201e19c, 2) == selector["core_pop"]["bytes"], "selector pop restores native note regs")

    req("playbackNotes" in SYSEX.read_text(), "UI document has playbackNotes field")
    appjs = APPJS.read_text()
    req("transmissionOrder(slots, playbackNotes)" in appjs, "current sender passes playbackNotes to queue")
    req("대응 펌웨어 protocol" in appjs, "current sender warns firmware protocol is absent")

    req(len(evidence["blockers"]) == 3, "expected blocker count")
    req(evidence["repeated_hit_polyphony_assessment"]["note_off_requirement"].startswith("For every Note On"), "Note Off symmetry assessment")
    print("playback-note ABI validation PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
