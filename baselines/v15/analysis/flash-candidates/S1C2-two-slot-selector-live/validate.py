#!/usr/bin/env python3
"""Validate the S1-C2 two-slot selector live BLOCK package.

This is deliberately a BLOCK validator. It proves that no firmware candidate,
FWSC, rollback bundle, uploader, or live sender exists here, then checks the
exact evidence that forced the block: the required LR/rets direct-route gate is
not implemented by the existing extended producer evidence.
"""
from __future__ import annotations

import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]

EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"
SENDER = HERE / "host_sender_dry_run.py"

OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
S1C1_APP = ROOT / "build/SMK37Pro-v15-S1C1-boundary-only/app.bin"
SELECTOR_HEX = ROOT / "baselines/v15/analysis/patch-set-ui/s1c1/code/wrapper-bytes.hex"
PRODUCER_BIN = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/producer.bin"
ABI_EVIDENCE = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/producer-abi/evidence.json"
MOOGER = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note45-bankD14-Mooger_1.runtime156.bin"
HAND = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note36-bankD12-HAND_DRUM.runtime156.bin"

OFFICIAL_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
S1C1_APP_SHA256 = "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e"
SELECTOR_SHA256 = "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35"
PRODUCER_SHA256 = "d989d7e852102126ae8dc2e4025b2717808e4f808bc2bf7885cb9c77ddeb05f7"

RUNTIME_BASE = 0x02000000
SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
PRODUCER_START = 0x0201E1A2
PRODUCER_END_LIMIT = 0x0201E254
DIRECT_LR = 0x0201E46C
SEGMENTED_LR = 0x0201E4A0
DIRECT_LEN = 0xA3
LOCK = 0x01C465BD
SLOT0 = 0x01C46520
VALID0 = 0x01C465BC
STATE_OFF = 3
SLOT1 = 0x01C465C0
VALID1_DELTA = 0xA0
VOICE_SIZE = 0x9C
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"

FORBIDDEN_NAMES = {
    "app.bin",
    "candidate-app.bin",
    "package-manifest.json",
    "app-manifest.json",
    "rollback-manifest.json",
}
FORBIDDEN_SUFFIXES = {".fwsc", ".ufw", ".zip"}


def fail(message: str) -> None:
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def selector_bytes() -> bytes:
    for line in SELECTOR_HEX.read_text(encoding="utf-8").splitlines():
        if line.startswith("hex="):
            return bytes.fromhex(line.split("=", 1)[1].strip())
    fail("selector hex line missing")


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def decode_subset(data: bytes, start: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = start + i
        rem = len(data) - i
        w = int.from_bytes(data[i:i + 2], "little") if rem >= 2 else 0
        if rem >= 4 and data[i:i + 4] == bytes.fromhex("2000b000"):
            out.append({"address": at, "size": 4, "op": "trylock", "asm": "csync; testset b[r0]"})
            i += 4
        elif rem >= 6 and data[i:i + 2] == b"\x80\xff":
            disp = struct.unpack("<i", data[i + 2:i + 6])[0]
            out.append({"address": at, "size": 6, "op": "call32", "target": at + 6 + disp})
            i += 6
        elif rem >= 4 and data[i:i + 2] == b"\x40\xe8":
            half = struct.unpack("<h", data[i + 2:i + 4])[0]
            out.append({"address": at, "size": 4, "op": "ifeq", "target": at + 4 + half * 2})
            i += 4
        elif rem >= 6 and (w & 0xFFC0) == 0xFFC0:
            out.append({"address": at, "size": 6, "op": "mov_imm32", "dst": w & 0xF, "imm": int.from_bytes(data[i + 2:i + 6], "little")})
            i += 6
        elif rem >= 4 and (w & 0xF880) == 0xF880:
            w2 = int.from_bytes(data[i + 2:i + 4], "little")
            out.append({"address": at, "size": 4, "op": "jne_imm7", "reg": w & 0x7, "imm": (w2 >> 9) & 0x7F, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2})
            i += 4
        elif rem >= 2 and (w & 0xFF8F) == 0x1908:
            out.append({"address": at, "size": 2, "op": "xor_r0", "src": (w >> 4) & 0x7})
            i += 2
        elif rem >= 2 and (w & 0x80FF) == 0x8004:
            out.append({"address": at, "size": 2, "op": "goto", "target": at + 2 + ((w >> 8) & 0x1F) * 2})
            i += 2
        elif rem >= 4 and data[i + 1] == 0xE1:
            out.append({"address": at, "size": 4, "op": "add_imm12", "dst": data[i], "src": data[i + 3] >> 4, "imm": data[i + 2] | ((data[i + 3] & 0xF) << 8)})
            i += 4
        elif rem >= 2 and (w & 0xE088) == 0x4008:
            out.append({"address": at, "size": 2, "op": "load_byte", "dst": w & 0x7, "base": (w >> 4) & 0x7, "offset": sx((w >> 8) & 0x1F, 5)})
            i += 2
        elif rem >= 2 and (w & 0xE088) == 0x4088:
            out.append({"address": at, "size": 2, "op": "store_byte", "src": w & 0x7, "base": (w >> 4) & 0x7, "offset": sx((w >> 8) & 0x1F, 5)})
            i += 2
        elif rem >= 2 and (w & 0xE0C0) == 0x2040:
            out.append({"address": at, "size": 2, "op": "mov_imm8", "dst": w & 0x7, "imm": ((w >> 8) & 0x1F) | (((w >> 3) & 0x7) << 5)})
            i += 2
        elif rem >= 2 and (w & 0xFF00) == 0x1600:
            out.append({"address": at, "size": 2, "op": "mov_reg", "dst": w & 0xF, "src": (w >> 4) & 0xF})
            i += 2
        elif rem >= 2 and w in {0x0479, 0x0459, 0x0020}:
            op = {0x0479: "push", 0x0459: "pop_pc", 0x0020: "csync"}[w]
            out.append({"address": at, "size": 2, "op": op})
            i += 2
        else:
            fail(f"undecoded PI32 subset bytes at 0x{at:08x}: {data[i:i+8].hex()}")
    return out


@dataclass
class ModelState:
    state: int = 0
    valid0: int = 0
    valid1: int = 0
    note0: int | None = None
    note1: int | None = None
    slot0: bytes | None = None
    slot1: bytes | None = None

    def snapshot(self) -> tuple[Any, ...]:
        return (self.state, self.valid0, self.valid1, self.note0, self.note1, self.slot0, self.slot1)


def desired_publish_model(s: ModelState, *, lr: int, r9: int, packet: bytes) -> bool:
    before = s.snapshot()
    if not (lr == DIRECT_LR and r9 == DIRECT_LEN):
        require(s.snapshot() == before, "reject path mutated state")
        return False
    payload = packet[len(HEADER):-1]
    if s.state == 0 and s.valid0 == 0:
        s.state = 1
        s.note0 = 36
        s.slot0 = payload
        s.valid0 = 1
        return True
    if s.state == 1 and s.valid0 == 1 and s.valid1 == 0:
        s.note1 = 45
        s.slot1 = payload
        s.valid1 = 1
        s.state = 2
        return True
    require(s.snapshot() == before, "later exact reject mutated state")
    return False


def main() -> int:
    require(EVIDENCE.exists(), "evidence.json exists")
    require(REPORT.exists(), "report.md exists")
    require(SENDER.exists(), "dry-run host sender exists")

    for path in HERE.rglob("*"):
        if path.name in FORBIDDEN_NAMES:
            fail(f"forbidden candidate artifact present: {path.relative_to(HERE)}")
        if path.is_file() and path.suffix.lower() in FORBIDDEN_SUFFIXES:
            fail(f"forbidden package artifact present: {path.relative_to(HERE)}")

    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report = REPORT.read_text(encoding="utf-8")
    require(evidence["format"] == "smk37-v15-s1c2-two-slot-selector-live-block-v1", "evidence format")
    require(evidence["decision"] == "BLOCK" and evidence["candidate_built"] is False, "BLOCK decision")
    require("LR/rets == 0x0201e46c AND r9 == 0xa3" in evidence["blocking_gate"]["requirement"], "critical LR/r9 gate recorded")
    require("no exact validated encoding" in evidence["blocking_gate"]["reason"], "exact PI32 rets blocker recorded")
    require("no candidate built" in report and "No device access" in report, "report non-action scope")

    require(sha256_path(OFFICIAL_APP) == OFFICIAL_APP_SHA256, "official app hash")
    require(sha256_path(S1C1_APP) == S1C1_APP_SHA256, "S1-C1 parent app hash")
    abi = json.loads(ABI_EVIDENCE.read_text(encoding="utf-8"))
    require(abi["direct_product_producer_entry"]["route_identity"]["caller_return_address_rets_lr"] == "0x0201e46c", "ABI direct LR proof imported")
    require(abi["constants"]["segmented_return_lr"] == "0x0201e4a0", "ABI segmented LR proof imported")

    selector = selector_bytes()
    require(len(selector) == 96 and sha256_bytes(selector) == SELECTOR_SHA256, "selector is exact 96-byte design")
    selector_insns = decode_subset(selector, SELECTOR_START)
    require(selector_insns[0]["op"] == "mov_reg" and selector_insns[-1]["op"] == "pop_pc", "selector decode boundary")
    require(SELECTOR_START + len(selector) == SELECTOR_END, "selector range exact")
    require(any(x["op"] == "load_byte" and x.get("offset") == 0 for x in selector_insns), "selector valid-byte rechecks present")

    producer = PRODUCER_BIN.read_bytes()
    require(len(producer) == 134 and sha256_bytes(producer) == PRODUCER_SHA256, "extended producer hash and size")
    require(len(producer) <= PRODUCER_END_LIMIT - PRODUCER_START, "producer <= 178 bytes")
    producer_insns = decode_subset(producer, PRODUCER_START)
    trylock = next(x for x in producer_insns if x["op"] == "trylock")
    require(trylock["address"] < PRODUCER_END_LIMIT, "trylock before official handler")
    pre_trylock = [x for x in producer_insns if x["address"] < trylock["address"]]
    require(any(x["op"] == "mov_imm32" and x.get("imm") == LOCK for x in pre_trylock), "producer prepares lock before trylock")
    require(not any(x["op"] == "mov_imm32" and x.get("imm") in {DIRECT_LR, SEGMENTED_LR} for x in pre_trylock), "existing producer has no LR route gate before mutation")
    require(not any(x["op"] == "jne_imm7" and x.get("imm") == DIRECT_LEN for x in pre_trylock), "existing producer has no r9 exact-length gate before mutation")

    packets = []
    for item, path in [(evidence["host_sender_dry_run"]["packets_in_order"][0], MOOGER), (evidence["host_sender_dry_run"]["packets_in_order"][1], HAND)]:
        payload = path.read_bytes()
        require(len(payload) == VOICE_SIZE and sha256_path(path) == item["runtime_object_sha256"], f"runtime object {path.name}")
        packet = HEADER + payload + TERM
        require(len(packet) == 163 and sha256_bytes(packet) == item["packet_sha256"], f"packet hash {path.name}")
        packets.append(packet)
    require(evidence["host_sender_dry_run"]["confirmation_token"] == "BLOCKED-S1C2-LR-GATE-NOT-PROVEN", "blocked confirmation token")

    s = ModelState()
    before = s.snapshot()
    require(desired_publish_model(s, lr=SEGMENTED_LR, r9=0x9E, packet=packets[0]) is False and s.snapshot() == before, "segmented route rejects without mutation")
    require(desired_publish_model(s, lr=DIRECT_LR, r9=DIRECT_LEN, packet=packets[0]) is True, "first exact direct publishes slot0")
    after_first = s.snapshot()
    require(s.state == 1 and s.valid0 == 1 and s.note0 == 36 and s.slot0 == packets[0][len(HEADER):-1], "first exact state")
    require(desired_publish_model(s, lr=0x0201E538, r9=DIRECT_LEN, packet=packets[1]) is False and s.snapshot() == after_first, "other caller rejects without mutation")
    require(desired_publish_model(s, lr=DIRECT_LR, r9=DIRECT_LEN, packet=packets[1]) is True, "second exact direct arms")
    after_second = s.snapshot()
    require(s.state == 2 and s.valid1 == 1 and s.note1 == 45 and s.slot1 == packets[1][len(HEADER):-1], "second exact state ARMED last")
    require(desired_publish_model(s, lr=DIRECT_LR, r9=DIRECT_LEN, packet=packets[0]) is False and s.snapshot() == after_second, "later exact rejects without mutation")

    print("S1-C2 two-slot selector live BLOCK validation: PASS")
    print("Validated exact S1-C1 parent, 96-byte selector, 134-byte producer evidence, dry-run packet hashes, and required state-machine tests.")
    print("Candidate remains BLOCKED because exact PI32 LR/rets gate is not implemented/proven before producer mutation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
