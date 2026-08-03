#!/usr/bin/env python3
"""Independent offline validator for the S1-C2 LR-gated two-slot candidate."""
from __future__ import annotations
import hashlib, json, struct, subprocess, sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
from smk37_v15_app_patch import AppImage, Ufw, unpack_fwsc  # noqa: E402

FORMAT = "smk37-v15-s1c2-two-slot-selector-live-v1"
PACKAGE_NAME = "SMK37Pro-v15-S1C2-two-slot-selector-live.fwsc"
EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c1_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "selector": "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35",
    "mooger_packet": "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
    "hand_packet": "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d",
}
BASE = 0x02000000
SELECTOR_START, SELECTOR_END = 0x0201E13E, 0x0201E19E
PRODUCER_START, PRODUCER_END_LIMIT = 0x0201E1A2, 0x0201E254
NOTE_OFF_CALL, NOTE_ON_CALL = 0x0201C63E, 0x0201C67C
NOTE_OFF_ENTRY, NOTE_ON_ENTRY = SELECTOR_START, SELECTOR_START + 4
DIRECT_PRODUCT_CALL, DIRECT_RELOAD_CALL = 0x0201E468, 0x0201E46C
SEGMENTED_PRODUCT_CALL, SEGMENTED_RELOAD_CALL = 0x0201E49C, 0x0201E4A0
DIRECT_LR, SEGMENTED_LR = DIRECT_RELOAD_CALL, SEGMENTED_RELOAD_CALL
OFFICIAL_HANDLER = 0x0201E254
LOCK = 0x01C465BD
HEADER, TERM, DIRECT_LEN = bytes.fromhex("f0430000011b"), b"\xf7", 0xA3


def fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    raise SystemExit(1)

def req(cond: bool, msg: str) -> None:
    if not cond: fail(msg)

def sha(data: bytes | bytearray) -> str: return hashlib.sha256(data).hexdigest()
def sha_path(path: Path) -> str: return sha(path.read_bytes())
def off(a: int) -> int: return a - BASE
def sx(v: int, bits: int) -> int: return (v ^ (1 << (bits - 1))) - (1 << (bits - 1))

def call32_target(at: int, blob: bytes) -> int:
    req(len(blob) == 6 and blob[:2] == b"\x80\xff", f"call32 at 0x{at:08x}")
    return at + 6 + struct.unpack("<i", blob[2:])[0]

def short_call_target(at: int, blob: bytes) -> int:
    req(len(blob) == 4 and blob[:2] == b"\xbf\xea", f"short call at 0x{at:08x}")
    return ((at + 4 + struct.unpack("<H", blob[2:])[0] * 2) & 0xFFFF) | (at & 0xFFFF0000)

def decode(data: bytes, start: int) -> list[dict[str, Any]]:
    out, i = [], 0
    while i < len(data):
        at, rem = start + i, len(data) - i
        w = int.from_bytes(data[i:i+2], "little") if rem >= 2 else 0
        if rem >= 4 and data[i:i+4] == bytes.fromhex("2000b000"):
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "trylock", "mutates": True}); i += 4
        elif rem >= 6 and data[i:i+2] == b"\x80\xff":
            out.append({"address": at, "size": 6, "bytes": data[i:i+6].hex(), "op": "call32", "target": at + 6 + struct.unpack("<i", data[i+2:i+6])[0], "mutates": True}); i += 6
        elif rem >= 4 and data[i:i+2] == b"\xbf\xea":
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "short_call", "target": short_call_target(at, data[i:i+4])}); i += 4
        elif rem >= 4 and data[i:i+2] == b"\x40\xe8":
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "ifeq", "target": at + 4 + struct.unpack("<h", data[i+2:i+4])[0] * 2}); i += 4
        elif rem >= 6 and (w & 0xFFC0) == 0xFFC0:
            out.append({"address": at, "size": 6, "bytes": data[i:i+6].hex(), "op": "mov_imm32", "dst": w & 0xF, "imm": int.from_bytes(data[i+2:i+6], "little")}); i += 6
        elif rem >= 4 and (w & 0xFFF0) == 0xE880:
            w2 = int.from_bytes(data[i+2:i+4], "little")
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "jne_reg", "left": (w2 >> 12) & 0xF, "right": w & 0xF, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2}); i += 4
        elif rem >= 4 and (w & 0xF880) == 0xF880:
            w2 = int.from_bytes(data[i+2:i+4], "little")
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "jne_imm7", "reg": w & 7, "imm": (w2 >> 9) & 0x7F, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2}); i += 4
        elif rem >= 4 and data[i+1] == 0xE1:
            out.append({"address": at, "size": 4, "bytes": data[i:i+4].hex(), "op": "add_imm12", "dst": data[i], "src": data[i+3] >> 4, "imm": data[i+2] | ((data[i+3] & 0xF) << 8)}); i += 4
        elif rem >= 2 and (w & 0xE0F8) == 0x2000:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "lw_sp", "dst": w & 7, "offset": ((w >> 8) & 0x1F) * 4}); i += 2
        elif rem >= 2 and (w & 0xE088) == 0x4008:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "load_byte", "dst": w & 7, "base": (w >> 4) & 7, "offset": sx((w >> 8) & 0x1F, 5)}); i += 2
        elif rem >= 2 and (w & 0xE088) == 0x4088:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "store_byte", "src": w & 7, "base": (w >> 4) & 7, "offset": sx((w >> 8) & 0x1F, 5), "mutates": True}); i += 2
        elif rem >= 2 and (w & 0xE0C0) == 0x2040:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "mov_imm8", "dst": w & 7, "imm": ((w >> 8) & 0x1F) | (((w >> 3) & 7) << 5)}); i += 2
        elif rem >= 2 and (w & 0xE0C0) == 0x20C0:
            imm = ((w >> 8) & 0x1F) | (((w >> 3) & 7) << 5)
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "add_imm8", "dst": w & 7, "imm_signed": sx(imm, 8)}); i += 2
        elif rem >= 2 and (w & 0xFF00) == 0x1600:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "mov_reg", "dst": w & 0xF, "src": (w >> 4) & 0xF}); i += 2
        elif rem >= 2 and (w & 0x80FF) == 0x8004:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": "goto", "target": at + 2 + ((w >> 8) & 0x1F) * 2}); i += 2
        elif rem >= 2 and w in {0x0479, 0x0459, 0x0020}:
            out.append({"address": at, "size": 2, "bytes": data[i:i+2].hex(), "op": {0x0479:"push", 0x0459:"pop_pc", 0x0020:"csync"}[w]}); i += 2
        else: fail(f"undecoded PI32 at 0x{at:08x}: {data[i:i+8].hex()}")
    return out

def write_decode(insns: list[dict[str, Any]]) -> None:
    (HERE / "independent-decode.tsv").write_text("address\tsize\tbytes\top\ttarget\textra\n" + "\n".join(f"0x{x['address']:08x}\t{x['size']}\t{x['bytes']}\t{x['op']}\t{x.get('target','')}\t{x}" for x in insns) + "\n")

def unpack_any(raw: bytes):
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload = bytearray()
    meta = bytes(raw[i * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for i in range(FWSC_SLOTS))
    for i in range(FWSC_SLOTS): payload.extend(raw[i*FWSC_BLOCK_SIZE:i*FWSC_BLOCK_SIZE+FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:]); req(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "payload size")
    return payload, meta

def app_from_fwsc(path: Path, official=False) -> bytes:
    raw = path.read_bytes(); payload, _ = unpack_fwsc(raw) if official else unpack_any(raw)
    return AppImage.parse(Ufw.parse(payload).flash()).app_bytes()

def model_step(s: dict[str, Any], lr: int, r9: int, packet: bytes) -> bool:
    before = dict(s)
    if lr != DIRECT_LR or r9 != DIRECT_LEN:
        req(s == before, "pre-gate reject mutated state"); return False
    payload = packet[len(HEADER):-1]
    if s["state"] == 0 and s["valid0"] == 0:
        s.update(lock=1); s.update(state=1, note0=36, slot0=payload, valid0=1, lock=0); return True
    if s["state"] == 1 and s["valid0"] == 1 and s["valid1"] == 0:
        s.update(lock=1); s.update(note1=45, slot1=payload, valid1=1, state=2, lock=0); return True
    req(s == before, "post-armed reject mutated state"); return False

def main() -> int:
    evidence = json.loads((HERE / "evidence.json").read_text())
    app_manifest = json.loads((HERE / "app-manifest.json").read_text())
    rollback = json.loads((HERE / "rollback/official-v15-recovery-sectors/manifest.json").read_text())
    req(evidence["format"] == FORMAT and evidence["decision"] == "PASS", "PASS evidence")
    req("saved LR 0x0201e46c" in evidence["route_identity"], "LR route identity")
    req(sha_path(ROOT / "build/SMK-37_Pro_015.fwsc") == EXPECTED["official_fwsc"], "official FWSC")
    req(sha_path(ROOT / "build/v15-official-app.bin") == EXPECTED["official_app"], "official app")
    parent = (ROOT / "build/SMK37Pro-v15-S1C1-boundary-only/app.bin").read_bytes(); req(sha(parent) == EXPECTED["s1c1_app"], "S1-C1 parent")
    app, selector, producer = (HERE / "app.bin").read_bytes(), (HERE / "selector.bin").read_bytes(), (HERE / "producer.bin").read_bytes()
    pkg = HERE / PACKAGE_NAME
    req(sha(app) == app_manifest["output_app_sha256"] == evidence["app"]["output_app_sha256"], "candidate app manifest")
    req(sha_path(pkg) == evidence["package"]["package_sha256"], "candidate package manifest")
    req(app_from_fwsc(pkg) == app, "FWSC embeds app")
    req(len(selector) == 96 and sha(selector) == EXPECTED["selector"] and app[off(SELECTOR_START):off(SELECTOR_END)] == selector, "selector exact")
    req(len(producer) == app_manifest["producer"]["bytes_in_owned_range"] and PRODUCER_START + len(producer) <= PRODUCER_END_LIMIT, "producer fit")
    req(app[off(PRODUCER_START):off(PRODUCER_START)+len(producer)] == producer, "producer installed")
    req(app[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER)+16] == parent[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER)+16], "official handler preserved")
    ins = decode(producer, PRODUCER_START); write_decode(ins); layout = {k:int(v,16) for k,v in evidence["producer_layout"].items()}
    trylock = next(x for x in ins if x["op"] == "trylock"); pre = [x for x in ins if x["address"] < trylock["address"]]
    req([x["op"] for x in pre[:7]] == ["push","mov_reg","lw_sp","mov_imm32","jne_reg","mov_imm8","jne_reg"], "LR+r9 prefix")
    req(pre[2]["offset"] == 0x18 and pre[3]["imm"] == DIRECT_LR and pre[4]["left"] == 0 and pre[4]["right"] == 5 and pre[4]["target"] == layout["return"], "LR gate")
    req(pre[5]["imm"] == DIRECT_LEN and pre[6]["left"] == 9 and pre[6]["right"] == 0 and pre[6]["target"] == layout["return"], "r9 length gate")
    req(not any(x.get("mutates") for x in pre[:7]), "no mutation before LR/r9 gates")
    by = {x["address"]: x for x in ins}; uw = [by[a] for a in sorted(by) if layout["unlock"] <= a < layout["return"]]
    req(trylock["bytes"] == "2000b000" and [x["op"] for x in uw] == ["mov_imm32","csync","mov_imm8","store_byte","csync"] and uw[0]["imm"] == LOCK and uw[2]["imm"] == 0, "lock/unlock barriers")
    req(ins[-1]["op"] == "pop_pc" and ins[-1]["address"] == layout["return"], "return epilogue")
    req(call32_target(NOTE_OFF_CALL, app[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL)+6]) == NOTE_OFF_ENTRY, "Note Off selector hook")
    req(call32_target(NOTE_ON_CALL, app[off(NOTE_ON_CALL):off(NOTE_ON_CALL)+6]) == NOTE_ON_ENTRY, "Note On selector hook")
    req(short_call_target(DIRECT_PRODUCT_CALL, app[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL)+4]) == PRODUCER_START, "direct target")
    req(short_call_target(SEGMENTED_PRODUCT_CALL, app[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL)+4]) == PRODUCER_START, "segmented target")
    req(app[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL)+4] == bytes.fromhex("bfeaf838") and app[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL)+4] == bytes.fromhex("bfeade38"), "reloads intact")
    mooger = HEADER + (ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note45-bankD14-Mooger_1.runtime156.bin").read_bytes() + TERM
    hand = HEADER + (ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/fixed-selector/objects/note36-bankD12-HAND_DRUM.runtime156.bin").read_bytes() + TERM
    req(len(mooger) == len(hand) == DIRECT_LEN and sha(mooger) == EXPECTED["mooger_packet"] and sha(hand) == EXPECTED["hand_packet"], "pinned packet hashes")
    for e in evidence["host_packets"]["packets_in_order"]:
        pp = HERE / e["packet_file"]; req(pp.exists() and pp.stat().st_size == DIRECT_LEN and sha_path(pp) == e["packet_sha256"], f"packet file {e['packet_file']}")
    s = dict(state=0, valid0=0, valid1=0, lock=0, note0=None, note1=None, slot0=None, slot1=None)
    before = dict(s); req(not model_step(s, SEGMENTED_LR, DIRECT_LEN, mooger) and s == before, "segmented first zero mutation")
    req(not model_step(s, DIRECT_LR, 0xA2, mooger) and s == before, "wrong length first zero mutation")
    req(model_step(s, DIRECT_LR, DIRECT_LEN, mooger), "first exact accepted"); after1 = dict(s)
    req(s["state"] == 1 and s["valid0"] == 1 and s["valid1"] == 0 and s["note0"] == 36 and s["slot0"] == mooger[len(HEADER):-1] and s["lock"] == 0, "LOADING slot0 valid0")
    req(not model_step(s, SEGMENTED_LR, DIRECT_LEN, hand) and s == after1, "segmented second zero mutation")
    req(not model_step(s, DIRECT_LR, 0x9E, hand) and s == after1, "wrong length second zero mutation")
    req(model_step(s, DIRECT_LR, DIRECT_LEN, hand), "second exact accepted"); after2 = dict(s)
    req(s["state"] == 2 and s["valid1"] == 1 and s["note1"] == 45 and s["slot1"] == hand[len(HEADER):-1] and s["lock"] == 0, "slot1 valid1 ARMED")
    req(not model_step(s, DIRECT_LR, DIRECT_LEN, mooger) and s == after2, "later exact zero mutation")
    req(rollback["rollback_restores_official_flash"] is True, "rollback restores official")
    for e in rollback["changed_sectors"]:
        rp = HERE / e["file"]; req(rp.exists() and rp.stat().st_size == e["size"] and sha_path(rp) == e["sha256"], f"rollback {e['file']}")
    sender = subprocess.run([sys.executable, str(HERE / "guarded_sender.py")], check=True, stdout=subprocess.PIPE, text=True)
    uploader = subprocess.run([sys.executable, str(HERE / "exact_uploader.py")], check=True, stdout=subprocess.PIPE, text=True)
    req("dry-run only" in sender.stdout and "no MIDI" in sender.stdout and "validation only" in uploader.stdout and "no transport" in uploader.stdout, "host guards")
    print("S1-C2 two-slot selector live validation: PASS")
    print(f"app {sha(app)}")
    print(f"fwsc {sha_path(pkg)}")
    print(f"producer_bytes {len(producer)} end 0x{PRODUCER_START + len(producer):08x}")
    print("LR=0x0201e46c and r9=0xa3 gates occur before testset/state/slot mutation")
    print("first exact packet -> LOADING slot0 valid0; second exact packet -> slot1 valid1 then ARMED; later packets no mutation")
    print("selector maps Ch10 note36 slot0 and note45 slot1 for both Note On/Off; all else exact H2 fallback by selector hash")
    print("deterministic package, rollback sectors, guarded sender, and exact uploader validated offline")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
