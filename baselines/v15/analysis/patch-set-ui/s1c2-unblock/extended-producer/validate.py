#!/usr/bin/env python3
"""Independently decode and validate the S1-C2 extended producer bytes."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]

FORMAT = "smk37-v15-s1c2-extended-producer-candidate-v1"
PRODUCER_START = 0x0201E1A2
PRODUCER_END_LIMIT = 0x0201E254
MAX_BYTES = PRODUCER_END_LIMIT - PRODUCER_START
SELECTOR_END = 0x0201E19E
GAP_END = 0x0201E1A2
OFFICIAL_HANDLER = 0x0201E254
MEMCPY = 0x02048CCE
LOCK = 0x01C465BD
SLOT0 = 0x01C46520
VALID0 = 0x01C465BC
STATE_OFF = 3
NOTE0_OFF = 2
SLOT1 = 0x01C465C0
VALID1_DELTA = 0xA0
NOTE1_OFF = 2
VOICE_SIZE = 0x9C
FIXED_NOTE0 = 36
FIXED_NOTE1 = 45
EMPTY = 0
LOADING = 1
ARMED = 2

FORBIDDEN_NAMES = {"app.bin", "package-manifest.json"}
FORBIDDEN_SUFFIXES = {".fwsc", ".zip"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode(data: bytes) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = PRODUCER_START + i
        remaining = len(data) - i
        w = int.from_bytes(data[i:i + 2], "little") if remaining >= 2 else 0

        if remaining >= 4 and data[i:i + 4] == bytes.fromhex("2000b000"):
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "trylock", "asm": "csync; testset b[r0]"})
            i += 4
            continue
        if remaining >= 6 and data[i:i + 2] == b"\x80\xff":
            disp = struct.unpack("<i", data[i + 2:i + 6])[0]
            target = at + 6 + disp
            out.append({"address": at, "size": 6, "bytes": data[i:i+6].hex(), "op": "call32", "target": target, "asm": f"call 0x{target:08x}"})
            i += 6
            continue
        if remaining >= 4 and data[i:i + 2] == b"\x40\xe8":
            half = struct.unpack("<h", data[i + 2:i + 4])[0]
            target = at + 4 + half * 2
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "ifeq", "target": target, "reach": target - (at + 4), "asm": f"ifeq goto 0x{target:08x}"})
            i += 4
            continue
        if remaining >= 6 and (w & 0xFFC0) == 0xFFC0:
            dst = w & 0xF
            imm = int.from_bytes(data[i + 2:i + 6], "little")
            out.append({"address": at, "size": 6, "bytes": data[i:i+6].hex(), "op": "mov_imm32", "dst": dst, "imm": imm, "asm": f"mov r{dst},#0x{imm:08x}"})
            i += 6
            continue
        if remaining >= 4 and (w & 0xF887) == 0xF880:
            reg = w & 0x7
            w2 = int.from_bytes(data[i + 2:i + 4], "little")
            imm = (w2 >> 9) & 0x7F
            half = sx(w2 & 0x1FF, 9)
            target = at + 4 + half * 2
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "jne_imm7", "reg": reg, "imm": imm, "target": target, "reach": target - (at + 4), "asm": f"jne r{reg},#0x{imm:x},0x{target:08x}"})
            i += 4
            continue
        if remaining >= 2 and (w & 0x80FF) == 0x8004:
            half = (w >> 8) & 0x1F
            target = at + 2 + half * 2
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "goto", "target": target, "reach": target - (at + 2), "asm": f"goto 0x{target:08x}"})
            i += 2
            continue
        if remaining >= 4 and data[i + 1] == 0xE1:
            dst = data[i]
            imm = data[i + 2] | ((data[i + 3] & 0xF) << 8)
            src = data[i + 3] >> 4
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "add_imm12", "dst": dst, "src": src, "imm": imm, "asm": f"add r{dst},r{src},#0x{imm:x}"})
            i += 4
            continue
        if remaining >= 2 and (w & 0xE088) == 0x4008:
            dst = w & 0x7
            base = (w >> 4) & 0x7
            off = sx((w >> 8) & 0x1F, 5)
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "load_byte", "dst": dst, "base": base, "offset": off, "asm": f"lb.z r{dst},[r{base}{off:+d}]"})
            i += 2
            continue
        if remaining >= 2 and (w & 0xE088) == 0x4088:
            src = w & 0x7
            base = (w >> 4) & 0x7
            off = sx((w >> 8) & 0x1F, 5)
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "store_byte", "src": src, "base": base, "offset": off, "asm": f"sb r{src},[r{base}{off:+d}]"})
            i += 2
            continue
        if remaining >= 2 and (w & 0xE0C0) == 0x2040:
            reg = w & 0x7
            imm = ((w >> 8) & 0x1F) | (((w >> 3) & 0x7) << 5)
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "mov_imm8", "dst": reg, "imm": imm, "asm": f"mov r{reg},#0x{imm:x}"})
            i += 2
            continue
        if remaining >= 2 and (w & 0xFF00) == 0x1600:
            dst = w & 0xF
            src = (w >> 4) & 0xF
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "mov_reg", "dst": dst, "src": src, "asm": f"mov r{dst},r{src}"})
            i += 2
            continue
        if remaining >= 2 and w == 0x0479:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "push", "asm": "push {rets,r9..r4}"})
            i += 2
            continue
        if remaining >= 2 and w == 0x0459:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "pop_pc", "asm": "pop {pc,r9..r4}"})
            i += 2
            continue
        if remaining >= 2 and w == 0x0020:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "csync", "asm": "csync"})
            i += 2
            continue
        raise SystemExit(f"FAIL: undecoded bytes at 0x{at:08x}: {data[i:i+8].hex()}")
    return out


def line_table(insns: list[dict[str, Any]]) -> str:
    lines = ["address\tsize\tbytes\top\tasm"]
    for insn in insns:
        lines.append(f"0x{insn['address']:08x}\t{insn['size']}\t{insn['bytes']}\t{insn['op']}\t{insn['asm']}")
    return "\n".join(lines) + "\n"


def find_seq(insns: list[dict[str, Any]], seq: list[tuple[str, dict[str, int]]]) -> int:
    for i in range(0, len(insns) - len(seq) + 1):
        ok = True
        for j, (op, fields) in enumerate(seq):
            item = insns[i + j]
            if item["op"] != op:
                ok = False
                break
            for key, value in fields.items():
                if item.get(key) != value:
                    ok = False
                    break
            if not ok:
                break
        if ok:
            return i
    return -1


def main() -> int:
    evidence_path = HERE / "evidence.json"
    producer_path = HERE / "producer.bin"
    hex_path = HERE / "producer.hex"
    require(evidence_path.exists(), "evidence.json exists")
    require(producer_path.exists(), "producer.bin exists")
    require(hex_path.exists(), "producer.hex exists")

    for child in HERE.iterdir():
        require(child.name not in FORBIDDEN_NAMES, f"forbidden firmware-like artifact: {child.name}")
        require(child.suffix.lower() not in FORBIDDEN_SUFFIXES, f"forbidden package artifact: {child.name}")

    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    data = producer_path.read_bytes()
    require(evidence["format"] == FORMAT, "evidence format")
    require(evidence["decision"] == "CANDIDATE", "candidate decision")
    require(evidence["artifact_scope"].startswith("analysis-only"), "analysis-only scope")
    require(bytes.fromhex(hex_path.read_text(encoding="utf-8").strip()) == data, "producer.hex matches producer.bin")
    require(evidence["candidate_sha256"] == sha256(data), "candidate sha256")
    require(len(data) == evidence["candidate_size"], "candidate size evidence")
    require(len(data) <= MAX_BYTES, "candidate <= 178 bytes")
    end = PRODUCER_START + len(data)
    require(evidence["candidate_start"] == f"0x{PRODUCER_START:08x}", "candidate start")
    require(evidence["candidate_end_exclusive"] == f"0x{end:08x}", "candidate end evidence")
    require(PRODUCER_START >= SELECTOR_END and PRODUCER_START >= GAP_END, "selector/gap not touched")
    require(end <= OFFICIAL_HANDLER, "official handler not touched")
    require(evidence["producer_abi"]["entry_length_register"] == "not proven at producer entry", "length ABI absence recorded")
    require(evidence["producer_abi"]["entry_route_state"] == "not proven at producer entry", "route ABI absence recorded")
    require("omitted" in evidence["producer_abi"]["packet_route_length_gate"], "length/route gate omitted by ABI evidence")
    require(evidence["producer_abi"]["h2_accepted_packet_ingress_preserved"] is True, "H2 ingress preservation recorded")
    require(evidence["producer_abi"]["trylock_fail_unlocks"] is False, "trylock fail does not unlock")
    require(evidence["producer_abi"]["all_acquired_exits_unlock"] is True, "acquired exits unlock recorded")

    insns = decode(data)
    (HERE / "independent-decode.tsv").write_text(line_table(insns), encoding="utf-8")
    require(sum(x["size"] for x in insns) == len(data), "decode covers all bytes")
    require(insns[0]["op"] == "push", "starts with push")
    require(insns[1]["op"] == "mov_reg" and insns[1]["dst"] == 4 and insns[1]["src"] == 0, "r4 saves producer r0")
    require(insns[-1]["op"] == "pop_pc", "ends with pop pc")

    branch_targets = [x for x in insns if x["op"] in {"ifeq", "jne_imm7", "goto"}]
    for branch in branch_targets:
        require(PRODUCER_START <= branch["target"] < end, f"branch target inside candidate at 0x{branch['address']:08x}")
        if branch["op"] == "jne_imm7":
            require(-512 <= branch["reach"] <= 510, f"jne reach at 0x{branch['address']:08x}")
        if branch["op"] == "ifeq":
            require(-0x10000 <= branch["reach"] <= 0xFFFE, f"ifeq reach at 0x{branch['address']:08x}")
        if branch["op"] == "goto":
            require(0 <= branch["reach"] <= 62, f"forward goto reach at 0x{branch['address']:08x}")

    ret_addr = insns[-1]["address"]
    unlock_store = [x for x in insns if x["op"] == "store_byte" and x.get("src") == 1 and x.get("base") == 0 and x.get("offset") == 0]
    require(len(unlock_store) == 1, "exactly one lock-clear store")
    unlock_addr = max(
        x["address"] for x in insns
        if x["op"] == "mov_imm32" and x.get("imm") == LOCK and x["address"] < unlock_store[0]["address"]
    )
    for branch in branch_targets:
        if branch["op"] == "ifeq":
            require(branch["target"] == ret_addr, "trylock-fail returns without unlocking")
        elif branch["op"] == "jne_imm7" and branch.get("imm") == EMPTY:
            require(branch["target"] > branch["address"], "state non-empty branch is forward")
        else:
            require(branch["target"] == unlock_addr, f"acquired reject/done branch unlocks at 0x{branch['address']:08x}")

    require(find_seq(insns, [("mov_imm32", {"dst": 0, "imm": LOCK}), ("trylock", {})]) >= 0, "lock pointer precedes trylock")
    require(find_seq(insns, [("mov_imm32", {"dst": 5, "imm": VALID0}), ("load_byte", {"dst": 0, "base": 5, "offset": STATE_OFF})]) >= 0, "state loaded from valid0+3")
    loading_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": LOADING}), ("store_byte", {"src": 0, "base": 5, "offset": STATE_OFF})])
    require(loading_idx >= 0, "state=LOADING store present")
    note0_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": FIXED_NOTE0}), ("store_byte", {"src": 0, "base": 5, "offset": NOTE0_OFF})])
    require(note0_idx > loading_idx, "note0=36 after LOADING")
    slot0_idx = find_seq(insns, [("mov_imm32", {"dst": 0, "imm": SLOT0}), ("mov_reg", {"dst": 1, "src": 4}), ("mov_imm8", {"dst": 2, "imm": VOICE_SIZE}), ("call32", {"target": MEMCPY})])
    require(slot0_idx > note0_idx, "slot0 memcpy sequence")
    valid0_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": 1}), ("store_byte", {"src": 0, "base": 5, "offset": 0})])
    require(valid0_idx > slot0_idx, "valid0 stored after slot0 memcpy")

    require(find_seq(insns, [("jne_imm7", {"reg": 0, "imm": LOADING})]) >= 0, "second path requires LOADING")
    require(find_seq(insns, [("load_byte", {"dst": 0, "base": 5, "offset": 0}), ("jne_imm7", {"reg": 0, "imm": 1})]) >= 0, "second path requires valid0=1")
    require(find_seq(insns, [("add_imm12", {"dst": 6, "src": 5, "imm": VALID1_DELTA}), ("load_byte", {"dst": 0, "base": 6, "offset": 0}), ("jne_imm7", {"reg": 0, "imm": 0})]) >= 0, "second path requires valid1=0")
    note1_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": FIXED_NOTE1}), ("store_byte", {"src": 0, "base": 6, "offset": NOTE1_OFF})])
    require(note1_idx > slot0_idx, "note1=45 in second path")
    slot1_idx = find_seq(insns, [("mov_imm32", {"dst": 0, "imm": SLOT1}), ("mov_reg", {"dst": 1, "src": 4}), ("mov_imm8", {"dst": 2, "imm": VOICE_SIZE}), ("call32", {"target": MEMCPY})])
    require(slot1_idx > note1_idx, "slot1 memcpy sequence")
    valid1_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": 1}), ("store_byte", {"src": 0, "base": 6, "offset": 0})])
    require(valid1_idx > slot1_idx, "valid1 stored after slot1 memcpy")
    armed_idx = find_seq(insns, [("mov_imm8", {"dst": 0, "imm": ARMED}), ("store_byte", {"src": 0, "base": 5, "offset": STATE_OFF})])
    require(armed_idx > valid1_idx, "ARMED stored last")

    calls = [x for x in insns if x["op"] == "call32"]
    require(len(calls) == 2 and all(x["target"] == MEMCPY for x in calls), "exactly two memcpy calls")

    print(f"extended producer candidate: PASS ({len(data)} / {MAX_BYTES} bytes)")
    print(f"range 0x{PRODUCER_START:08x}..0x{end:08x}; handler 0x{OFFICIAL_HANDLER:08x} untouched")
    print("independent decode: PASS")
    print("branch reach: PASS")
    print("packet/route length gate: omitted, no producer ABI evidence for length/route")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
