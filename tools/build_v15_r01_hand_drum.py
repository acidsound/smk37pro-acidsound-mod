#!/usr/bin/env python3
"""Build a v15-only Channel-10 HAND DRUM checkpoint from proven addresses.

Evidence basis:
- runtime base 0x02000000 from v15 internal pointers;
- MIDI dispatcher 0x0201c5ec from Quarkslab pi32v2 disassembly;
- Note On memcpy call 0x0201c67c, channel nibble in r9;
- v15 factory loader 0x02005660 expansion semantics;
- packed factory voice bank 3 preset 11 at full-flash offset 0xf7580.

No v12 address, layout, or firmware artifact is consumed.
"""
from __future__ import annotations

import argparse, hashlib, json, struct
from pathlib import Path

APP_SIZE = 617_012
APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
DUMP_SIZE = 1_048_576
DUMP_SHA256 = "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b"
RUNTIME_BASE = 0x02000000
NOTE_ON_MEMCPY_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")
MEMCPY = 0x02048CCE
CODE_CAVE = 0x0201E13E
CODE_CAVE_END = 0x0201E254
SYSEX_CALLS = (
    (0x0201E468, bytes.fromhex("bfea69fe")),
    (0x0201E49C, bytes.fromhex("bfea4ffe")),
)
HAND_DRUM_OFFSET = 0xF7580
VOICE_SIZE = 156
CHANNEL_10 = 9


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def off(address: int) -> int:
    value = address - RUNTIME_BASE
    if not 0 <= value < APP_SIZE:
        raise ValueError(f"address outside app: 0x{address:08x}")
    return value


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def mov_reg(dst: int, src: int) -> bytes:
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def call32(at: int, target: int) -> bytes:
    return b"\x80\xff" + struct.pack("<i", target - (at + 6))


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    if displacement & 1:
        raise ValueError("unaligned branch")
    halfwords = displacement // 2
    if not -256 <= halfwords <= 255:
        raise ValueError("branch out of range")
    return word(0xF880 | register) + word((immediate << 9) | (halfwords & 0x1FF))


def replace_exact(output: bytearray, original: bytes, address: int,
                  expected: bytes, replacement: bytes) -> dict[str, object]:
    if len(expected) != len(replacement):
        raise ValueError("replacement size differs")
    start = off(address)
    if original[start:start + len(expected)] != expected:
        raise ValueError(f"stock bytes differ at 0x{address:08x}")
    output[start:start + len(replacement)] = replacement
    return {"address": f"0x{address:08x}", "file_offset": start,
            "old_hex": expected.hex(), "new_hex": replacement.hex()}


def expand_v15_factory_voice(packed: bytes) -> bytes:
    """Reproduce the 0x02005660 packed-voice expansion into bytes 0..155."""
    if len(packed) != 128:
        raise ValueError("packed voice must be 128 bytes")
    out = bytearray(VOICE_SIZE)
    for operator in range(6):
        src = operator * 17
        dst = operator * 21
        out[dst:dst + 11] = packed[src:src + 11]
        curves = packed[src + 11]
        out[dst + 11] = curves & 3
        out[dst + 12] = (curves >> 2) & 3
        detune_rate = packed[src + 12]
        out[dst + 13] = detune_rate & 7
        velocity_amp = packed[src + 13]
        out[dst + 14] = velocity_amp & 3
        out[dst + 15] = (velocity_amp >> 2) & 7
        out[dst + 16] = packed[src + 14]
        coarse_mode = packed[src + 15]
        out[dst + 17] = coarse_mode & 1
        out[dst + 18] = (coarse_mode >> 1) & 0x1F
        out[dst + 19] = packed[src + 16]
        out[dst + 20] = (detune_rate >> 3) & 0x0F
    out[126:135] = packed[102:111]
    feedback_sync = packed[111]
    out[135] = feedback_sync & 7
    out[136] = (feedback_sync >> 3) & 1
    out[137:141] = packed[112:116]
    lfo = packed[116]
    out[141] = lfo & 1
    out[142] = (lfo >> 1) & 7
    out[143] = (lfo >> 4) & 7
    out[144] = packed[117]
    out[145:155] = packed[118:128]
    out[155] = 0x3F
    return bytes(out)


def build_wrapper(snapshot: bytes) -> tuple[bytes, dict[str, int]]:
    block = bytearray()
    entry = CODE_CAVE
    block += word(0x0479)                 # push {rets,r9..r4}
    block += mov_reg(3, 9)                # r9 = MIDI channel nibble
    branch_at = CODE_CAVE + len(block)
    block += b"\0" * 4

    special = CODE_CAVE + len(block)
    block += mov_reg(4, 0)                # preserve per-voice destination
    pointer_at = CODE_CAVE + len(block)
    block += b"\0" * 6
    block += mov_reg(0, 4)
    block += word(0x3C62)                 # r2 = 0x9c
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)                 # pop {pc,r9..r4}

    stock = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)

    snapshot_address = (CODE_CAVE + len(block) + 1) & ~1
    block += b"\0" * (snapshot_address - (CODE_CAVE + len(block)))
    block += snapshot
    block[branch_at-CODE_CAVE:branch_at-CODE_CAVE+4] = jne_imm7(
        branch_at, 3, CHANNEL_10, stock)
    block[pointer_at-CODE_CAVE:pointer_at-CODE_CAVE+6] = mov_imm32(1, snapshot_address)
    return bytes(block), {"entry": entry, "special": special, "stock": stock,
                          "snapshot": snapshot_address, "end": CODE_CAVE + len(block)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("app", type=Path)
    ap.add_argument("clean_dump", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--manifest", type=Path, required=True)
    args = ap.parse_args()
    app = args.app.read_bytes(); dump = args.clean_dump.read_bytes()
    if len(app) != APP_SIZE or sha256(app) != APP_SHA256:
        raise SystemExit("refusing non-official v15 app")
    if len(dump) != DUMP_SIZE or sha256(dump) != DUMP_SHA256:
        raise SystemExit("refusing non-baseline v15 full flash dump")
    packed = dump[HAND_DRUM_OFFSET:HAND_DRUM_OFFSET + 128]
    if packed[118:128] != b"HAND DRUM ":
        raise SystemExit("factory voice identity mismatch")
    snapshot = expand_v15_factory_voice(packed)
    wrapper, layout = build_wrapper(snapshot)
    if layout["end"] > CODE_CAVE_END:
        raise SystemExit("wrapper exceeds audited replaced function")
    out = bytearray(app); changes = []
    cave_old = app[off(CODE_CAVE):off(CODE_CAVE)+len(wrapper)]
    changes.append(replace_exact(out, app, CODE_CAVE, cave_old, wrapper))
    changes.append(replace_exact(out, app, NOTE_ON_MEMCPY_CALL, NOTE_ON_STOCK,
                                 call32(NOTE_ON_MEMCPY_CALL, CODE_CAVE)))
    for address, expected in SYSEX_CALLS:
        changes.append(replace_exact(out, app, address, expected, b"\0"*4))
    args.output.write_bytes(out)
    manifest = {
        "format": "smk37-v15-r01-channel10-factory-hand-drum-v1",
        "input_app_sha256": sha256(app), "output_app_sha256": sha256(out),
        "source_dump_sha256": sha256(dump), "runtime_base": "0x02000000",
        "evidence": {
            "dispatcher": "0x0201c5ec", "note_on_memcpy": "0x0201c67c",
            "note_off_memcpy_unchanged": "0x0201c63e", "factory_loader": "0x02005660",
            "memcpy": "0x02048cce", "channel_register": "r9",
        },
        "voice": {"bank": 3, "preset": 11, "name": "HAND DRUM ",
                  "packed_flash_offset": "0x000f7580",
                  "packed_sha256": sha256(packed), "runtime_sha256": sha256(snapshot)},
        "layout": {k: f"0x{v:08x}" for k,v in layout.items()}, "changes": changes,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True)+"\n")
    print("output app", sha256(out)); print("voice", packed[118:128].decode(), sha256(snapshot))
    return 0

if __name__ == "__main__": raise SystemExit(main())
