#!/usr/bin/env python3
"""Build S1-C6 Reset Signature Isolation offline candidate (display marker S16).

Root-cause fix for the 2026-08-14 FM Drum load failure: the S1-C5 reset
wrapper detects a reset on `stage[0..1] == 0x62 0x63` (wire bytes 6..7) and
then *still* loads the packet as a voice.  Any real voice whose first two
payload bytes happen to be `62 63` (HITUN RIMS, BUZZ BASS) triggers a
mid-transaction reset and clears the loaded count, so ARMED is never reached
and the device silently reverts to the default state.

S1-C6 replaces that check with a **structurally impossible signature**:
`stage[0..1] == 0x64 0x65`.  Payload bytes 0..1 are OP1 EG rates 1..2, whose
DX7 value range is 0..99 (0x00..0x63), so `0x64`/`0x65` cannot occur in any
valid DX7 voice (this is a hard format limit, not an empirical scan).  On a
signature match the wrapper clears lock/count/state and **returns without
calling the producer** -- the reset packet is not a voice and does not
consume a slot.  Hosts therefore send 1 explicit reset packet followed by
16 voice packets (17 total).  Because the signature is structurally
impossible, no voice packet -- at any slot position -- can ever trigger a
reset, and re-loading over an armed kit works without a power cycle.

The new wrapper fits in the existing 44-byte owned tail
`0x0201e228..0x0201e254` (40 instruction bytes + 4 pad bytes), so **no
callsite changes are needed**: the direct callsite `0x0201e468` and the
segmented-final callsite `0x0201e49c` still target `0x0201e228`, and the
selector/producer-core bytes `0x0201e13e..0x0201e228` are preserved
byte-for-byte.  Only the reset wrapper tail and the display marker
(`S1C5` -> `S16`) change vs the S1-C5 marked parent.

Offline only: no device, USB, MIDI, OTA upload, flash, reset, or live send.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
FLASH = HERE.parent
ANALYSIS = HERE.parents[1]
ROOT = HERE.parents[4]
PARENT = FLASH / "S1C5-playback-register-return-S1C5-marked"
PARENT_PACKAGE = "SMK37Pro-v15-S1C5-playback-register-return-S1C5-marked.fwsc"
BOUNDARY = FLASH / "S1C3-16slot-boundary-only"
OFFICIAL_FWSC = FLASH / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
SAMPLES = ROOT / "apps" / "smk37-patch-set-editor" / "public" / "samples"
CODEDIR = HERE / "code-evidence"

sys.path.insert(0, str(BOUNDARY))
from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_OFFSET,
    APP_DATA_SIZE,
    AppImage,
    Ufw,
    compact_ranges,
    difference_offsets,
    protected_hashes,
    unpack_fwsc,
)

FORMAT = "smk37-v15-s1c6-reset-signature-isolation"
PACKAGE_NAME = "SMK37Pro-v15-S1C6-reset-signature-isolation-S16-marked.fwsc"
BASE = 0x02000000
SECTOR = 0x2000
PROTECTED_PREFIX_END = 0x4000
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
WIRE_PLAYBACK_OFFSET = 161

SEL_START, OWNED_END = 0x0201E13E, 0x0201E254
SELECTOR_END = 0x0201E196
PRODUCER = 0x0201E196
RESET_ENTRY = 0x0201E228
DIRECT_CALL, SEG_CALL = 0x0201E468, 0x0201E49C
DISPLAY_VERSION_ADDRESS = 0x020572A2

LOCK, COUNT, STATE = 0x01C465BD, 0x01C465BE, 0x01C465BF
RESET_SIG = (0x64, 0x65)          # both > 0x63: impossible in DX7 EG-rate bytes
RESET_PACKET_BYTE_161 = 0x00      # producer never reads it; fixed for determinism

S1C5_DISPLAY = b"S1C5\x00"
S16_DISPLAY = b"S16\x00\x00"

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "parent_app": "c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5",
    "parent_fwsc": "cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480",
    "selector": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "producer_core": "b740203d7c709aaa74dd506cc39739191caac790890056e2aee6ad627377baa5",
    "core_combined": "1f5ac42f0fd34c725193d308e2a608e1a0f8a9c70c60c29f58d38bcd68804744",
    "wrapper_old": "79040416494081f80bc4494181f808c6c5ffbd65c4014020d840d841d8422000401680ff46ffffff59040016",
    "direct_call": "bfeadefe",
    "seg_call": "bfeac4fe",
    "display_old": "5331433500",
}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def wjson(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def hx(value: int) -> str:
    return f"0x{value:08x}"


def off(address: int) -> int:
    o = address - BASE
    req(0 <= o < APP_DATA_SIZE, f"address outside app {hx(address)}")
    return o


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def sx(value: int, bits: int) -> int:
    s = 1 << (bits - 1)
    return (value ^ s) - s


def mov(dst: int, src: int) -> bytes:
    return word(0x1600 | (src << 4) | dst)


def mov8(r: int, imm: int) -> bytes:
    return word(0x2040 | r | ((imm >> 5) << 3) | ((imm & 0x1F) << 8))


def mov32(dst: int, val: int) -> bytes:
    return word(0xFFC0 | dst) + struct.pack("<I", val)


def lb(dst: int, base: int, ofs: int = 0) -> bytes:
    return word(0x4008 | dst | (base << 4) | ((ofs & 0x1F) << 8))


def sb(src: int, base: int, ofs: int = 0) -> bytes:
    return word(0x4088 | src | (base << 4) | ((ofs & 0x1F) << 8))


def call32(at: int, target: int) -> bytes:
    return b"\x80\xff" + struct.pack("<i", target - (at + 6))


def short_target(at: int, data: bytes) -> int:
    return ((at + 4 + struct.unpack("<H", data[2:4])[0] * 2) & 0xFFFF) | (at & 0xFFFF0000)


def br(base: int, at: int, r: int, imm: int, target: int) -> bytes:
    return word(base | r) + word((imm << 9) | (((target - (at + 4)) // 2) & 0x1FF))


def jne(at: int, r: int, imm: int, target: int) -> bytes:
    return br(0xF880, at, r, imm, target)


def call32_target(at: int, data: bytes) -> int:
    return at + 6 + struct.unpack("<i", data[2:6])[0]


@dataclass
class Fix:
    off: int
    label: str
    enc: Callable[[int, int], bytes]


class R:
    def __init__(self, start: int, prefix: str) -> None:
        self.start = start
        self.prefix = prefix
        self.data = bytearray()
        self.labels = {"entry": start}
        self.fix: list[Fix] = []
        self.rows: list[dict[str, Any]] = []

    @property
    def pc(self) -> int:
        return self.start + len(self.data)

    def label(self, n: str) -> None:
        self.labels[n] = self.pc

    def emit(self, n: str, asm: str, b: bytes, meaning: str) -> None:
        self.rows.append({"address": hx(self.pc), "size": len(b), "bytes": b.hex(), "name": self.prefix + "." + n, "asm": asm, "meaning": meaning})
        self.data += b

    def branch(self, n: str, asm: str, size: int, label: str, enc: Callable[[int, int], bytes], meaning: str) -> None:
        self.rows.append({"address": hx(self.pc), "size": size, "bytes": "pending", "name": self.prefix + "." + n, "asm": asm, "meaning": meaning})
        self.fix.append(Fix(len(self.data), label, enc))
        self.data += b"\0" * size

    def finish(self) -> bytes:
        for f in self.fix:
            at = self.start + f.off
            b = f.enc(at, self.labels[f.label])
            self.data[f.off:f.off + len(b)] = b
            for row in self.rows:
                if int(row["address"], 16) == at:
                    row["bytes"] = b.hex()
                    row["target"] = hx(self.labels[f.label])
                    break
        return bytes(self.data)


def build_reset_wrapper() -> tuple[bytes, bytes, list[dict[str, Any]], dict[str, int]]:
    r = R(RESET_ENTRY, "reset")
    r.emit("push_saved", "push {rets,r9..r4}", word(0x0479), "preserve r4..r9 for segmented caller r7 contract")
    r.emit("sig0_load", "lb.z r1,[r0]", lb(1, 0), "wire byte 6 = payload byte 0 (OP1 EG rate 1); r0 = stage from callsite")
    r.branch("sig0_mismatch", "jne r1,#0x64,skip", 4, "skip", lambda a, t: jne(a, 1, RESET_SIG[0], t), "not reset packet -> producer")
    r.emit("sig1_load", "lb.z r1,[r0+1]", lb(1, 0, 1), "wire byte 7 = payload byte 1 (OP1 EG rate 2)")
    r.branch("sig1_mismatch", "jne r1,#0x65,skip", 4, "skip", lambda a, t: jne(a, 1, RESET_SIG[1], t), "not reset packet -> producer")
    r.emit("control_pointer", f"mov r5,#{LOCK:#x}", mov32(5, LOCK), "control base")
    r.emit("zero", "mov r0,#0", mov8(0, 0), "zero")
    r.emit("lock_store", "sb [r5],r0", sb(0, 5), "clear lock")
    r.emit("count_store", "sb [r5+1],r0", sb(0, 5, 1), "clear count")
    r.emit("state_store", "sb [r5+2],r0", sb(0, 5, 2), "state EMPTY hides stale map until ARMED")
    r.emit("reset_csync", "csync", word(0x0020), "publish reset")
    r.emit("return_reset", "pop {pc,r9..r4}", word(0x0459), "reset packet is not a voice: return without calling producer")
    r.label("skip")
    r.emit("call_producer", f"call {PRODUCER:#x}", call32(r.pc, PRODUCER), "r0 = stage preserved on skip path; sequential producer")
    r.emit("return_voice", "pop {pc,r9..r4}", word(0x0459), "return")
    code = r.finish()
    req(RESET_ENTRY + len(code) <= OWNED_END, f"reset wrapper fits owned tail ({len(code)} bytes)")
    tail = mov(0, 0) * ((OWNED_END - (RESET_ENTRY + len(code))) // 2)
    req(RESET_ENTRY + len(code) + len(tail) == OWNED_END, "wrapper + tail exactly fills owned tail")
    return code, tail, r.rows, dict(r.labels)


def decode(data: bytes, start: int) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = start + i
        rem = len(data) - i
        w = int.from_bytes(data[i:i + 2], "little")
        if rem >= 6 and data[i:i + 2] == b"\x80\xff":
            size = 6
            row = {"op": "call32", "target": call32_target(at, data[i:i + 6])}
        elif rem >= 6 and (w & 0xFFC0) == 0xFFC0:
            size = 6
            row = {"op": "mov_imm32", "dst": w & 0xF, "imm": int.from_bytes(data[i + 2:i + 6], "little")}
        elif rem >= 4 and (w & 0xFF80) == 0xF880:
            size = 4
            w2 = int.from_bytes(data[i + 2:i + 4], "little")
            row = {"op": "jne_imm7", "reg": w & 7, "imm": (w2 >> 9) & 0x7F, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2}
        elif rem >= 2 and (w & 0xE088) == 0x4008:
            size = 2
            row = {"op": "load_byte", "dst": w & 7, "base": (w >> 4) & 7, "ofs": (w >> 8) & 0x1F}
        elif rem >= 2 and (w & 0xE088) == 0x4088:
            size = 2
            row = {"op": "store_byte", "src": w & 7, "base": (w >> 4) & 7, "ofs": (w >> 8) & 0x1F}
        elif rem >= 2 and (w & 0xE0C0) == 0x2040:
            size = 2
            row = {"op": "mov_imm8", "r": w & 7, "imm": ((w >> 3) & 7) << 5 | (w >> 8) & 0x1F}
        elif rem >= 2 and (w & 0xFF00) == 0x1600:
            size = 2
            row = {"op": "mov_reg", "dst": w & 0xF, "src": (w >> 4) & 0xF}
        elif rem >= 2 and w == 0x0020:
            size = 2
            row = {"op": "csync"}
        elif rem >= 2 and w in {0x0479, 0x0459}:
            size = 2
            row = {"op": {0x0479: "push", 0x0459: "pop_pc"}[w]}
        else:
            raise SystemExit(f"FAIL: undecoded at {hx(at)} {data[i:i + 8].hex()}")
        row.update({"address": hx(at), "size": size, "bytes": data[i:i + size].hex()})
        out.append(row)
        i += size
    return out


def unpack_any(raw: bytes) -> bytearray:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload = bytearray()
    for i in range(FWSC_SLOTS):
        payload.extend(raw[i * FWSC_BLOCK_SIZE:i * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    req(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "payload size")
    return payload


def app_from_fwsc(path: Path, official: bool = False) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    payload = unpack_fwsc(raw)[0] if official else unpack_any(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def gate_basis() -> tuple[bytes, list[dict[str, Any]]]:
    gates: list[dict[str, Any]] = []
    raw, _, official_app = app_from_fwsc(OFFICIAL_FWSC, True)
    req(sha(raw) == EXPECTED["official_fwsc"], "official FWSC hash")
    req(sha(official_app) == EXPECTED["official_app"], "official app hash")

    parent_app = (PARENT / "app.bin").read_bytes()
    req(sha(parent_app) == EXPECTED["parent_app"], "exact S1-C5 marked parent app hash")
    req(shaf(PARENT / PARENT_PACKAGE) == EXPECTED["parent_fwsc"], "exact S1-C5 marked parent package hash")
    parent_ev = json.loads((PARENT / "evidence.json").read_text())
    req(parent_ev["decision"] == "PASS", "parent evidence PASS")

    req(sha(parent_app[off(SEL_START):off(SELECTOR_END)]) == EXPECTED["selector"], "selector bytes")
    req(sha(parent_app[off(PRODUCER):off(RESET_ENTRY)]) == EXPECTED["producer_core"], "producer core bytes")
    req(sha(parent_app[off(SEL_START):off(RESET_ENTRY)]) == EXPECTED["core_combined"], "selector+producer core combined bytes")
    req(parent_app[off(RESET_ENTRY):off(OWNED_END)].hex() == EXPECTED["wrapper_old"], "S1-C5 reset wrapper bytes")
    req(parent_app[off(DIRECT_CALL):off(DIRECT_CALL) + 4].hex() == EXPECTED["direct_call"], "direct callsite bytes")
    req(parent_app[off(SEG_CALL):off(SEG_CALL) + 4].hex() == EXPECTED["seg_call"], "segmented callsite bytes")
    req(short_target(DIRECT_CALL, parent_app[off(DIRECT_CALL):off(DIRECT_CALL) + 4]) == RESET_ENTRY, "direct call target")
    req(short_target(SEG_CALL, parent_app[off(SEG_CALL):off(SEG_CALL) + 4]) == RESET_ENTRY, "segmented call target")
    req(bytes(parent_app[off(DISPLAY_VERSION_ADDRESS):off(DISPLAY_VERSION_ADDRESS) + len(S1C5_DISPLAY)]).hex() == EXPECTED["display_old"], "S1-C5 display marker")

    gates.append({"name": "official-v15-basis", "status": "PASS", "official_fwsc_sha256": EXPECTED["official_fwsc"], "official_app_sha256": EXPECTED["official_app"]})
    gates.append({"name": "exact-s1c5-marked-parent", "status": "PASS", "parent_app_sha256": EXPECTED["parent_app"], "parent_fwsc_sha256": EXPECTED["parent_fwsc"], "parent_candidate": str(PARENT.relative_to(ROOT))})
    gates.append({"name": "s1c5-core-preserved", "status": "PASS", "selector_sha256": EXPECTED["selector"], "producer_core_sha256": EXPECTED["producer_core"], "core_combined_sha256": EXPECTED["core_combined"], "core_range": f"{hx(SEL_START)}..{hx(RESET_ENTRY)}", "reset_wrapper_old_hex": EXPECTED["wrapper_old"]})
    gates.append({"name": "callsites-unchanged", "status": "PASS", "direct_call": EXPECTED["direct_call"], "direct_target": hx(RESET_ENTRY), "segmented_call": EXPECTED["seg_call"], "segmented_target": hx(RESET_ENTRY)})
    gates.append({"name": "offline-scope", "status": "PASS", "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False})
    return parent_app, gates


def verify_wrapper(code: bytes, tail: bytes, rows: list[dict[str, Any]], labels: dict[str, int]) -> list[str]:
    checks: list[str] = []
    req(labels["skip"] == RESET_ENTRY + 0x20, "skip label position")
    dec = decode(code, RESET_ENTRY)
    req(len(dec) == len(rows), "independent decode covers intended bytes")
    for d, r in zip(dec, rows):
        req(d["bytes"] == r["bytes"], f"decode/rows byte mismatch at {d['address']}")
    req(tail == mov(0, 0) * (len(tail) // 2), "tail is inert mov r0,r0 padding")
    names = [r["op"] for r in dec]
    req(names == ["push", "load_byte", "jne_imm7", "load_byte", "jne_imm7", "mov_imm32", "mov_imm8", "store_byte", "store_byte", "store_byte", "csync", "pop_pc", "call32", "pop_pc"], "exact instruction sequence")
    req(dec[2]["imm"] == RESET_SIG[0] and dec[4]["imm"] == RESET_SIG[1], "reset signature immediates")
    req(dec[2]["target"] == RESET_ENTRY + 0x20 and dec[4]["target"] == RESET_ENTRY + 0x20, "both mismatches jump to skip/call producer")
    req(dec[5]["imm"] == LOCK, "control pointer")
    req(dec[12]["op"] == "call32" and dec[12]["target"] == PRODUCER, "skip path calls producer")
    req(dec[0]["bytes"] == "7904" and dec[11]["bytes"] == "5904" and dec[13]["bytes"] == "5904", "push/pop frame balance")
    req(dec[10]["bytes"] == "2000", "csync before reset return")
    checks.append(f"PASS\treset-wrapper\t{hx(RESET_ENTRY)}..{hx(OWNED_END)}\t2-byte impossible signature {RESET_SIG[0]:#x} {RESET_SIG[1]:#x}; reset returns without producer; voice path calls {hx(PRODUCER)}")
    checks.append("PASS\treset-semantics\treset packet clears lock/count/state and is NOT loaded as a voice; no slot consumed")
    checks.append("PASS\tcallsites\tunchanged direct/segmented callsites still target reset entry")
    checks.append("PASS\tframe\tr4..r9 preserved by push/pop (segmented caller r7 contract); r0/r1 scratch as in S1-C5")
    return checks


def collision_scan() -> dict[str, Any]:
    hits: list[dict[str, Any]] = []
    scanned = 0
    for p in sorted(SAMPLES.rglob("*.smkpatchset.json")):
        doc = json.loads(p.read_text())
        for patch in doc.get("patches", []):
            b64 = patch.get("syxBase64")
            if not b64:
                continue
            data = base64.b64decode(b64)
            scanned += 1
            if data[6:8] == bytes(RESET_SIG):
                hits.append({"file": str(p.relative_to(ROOT)), "name": patch.get("name"), "bytes_6_7": data[6:8].hex()})
    req(not hits, f"signature collision in bundled voices: {hits}")
    res = {"status": "PASS", "scanned_voices": scanned, "collisions": 0, "signature": list(RESET_SIG), "structural_argument": "payload bytes 0..1 are OP1 EG rates 1..2 with DX7 value range 0..99 (0x00..0x63); 0x64/0x65 cannot occur in any valid DX7 voice"}
    return res


def patch(app: bytearray, address: int, new: bytes, purpose: str) -> dict[str, Any]:
    old = bytes(app[off(address):off(address) + len(new)])
    app[off(address):off(address) + len(new)] = new
    return {"address": hx(address), "end_exclusive": hx(address + len(new)), "byte_count": len(new), "old_hex": old.hex(), "new_hex": new.hex(), "old_sha256": sha(old), "new_sha256": sha(new), "purpose": purpose}


def build_app(parent: bytes, gates: list[dict[str, Any]], wrapper_checks: list[str]) -> tuple[bytes, dict[str, Any], list[str]]:
    app = bytearray(parent)
    req(bytes(app[off(DISPLAY_VERSION_ADDRESS):off(DISPLAY_VERSION_ADDRESS) + len(S1C5_DISPLAY)]) == S1C5_DISPLAY, "parent S1-C5 display marker")
    code, tail, rows, labels = build_reset_wrapper()
    checks = verify_wrapper(code, tail, rows, labels) + wrapper_checks
    new_region = code + tail
    req(len(new_region) == OWNED_END - RESET_ENTRY, "new region fills owned tail")
    patches = [
        patch(app, RESET_ENTRY, new_region, "replace S1-C5 reset wrapper (0x62 0x63 + load-as-voice) with impossible-signature reset wrapper (0x64 0x65, reset packet not a voice)"),
        patch(app, DISPLAY_VERSION_ADDRESS, S16_DISPLAY, "Visible 3-character firmware marker S16 per versioning rule"),
    ]
    appb = bytes(app)
    req(sha(appb[off(SEL_START):off(RESET_ENTRY)]) == EXPECTED["core_combined"], "selector+producer core preserved byte-for-byte")
    req(appb[off(DIRECT_CALL):off(DIRECT_CALL) + 4].hex() == EXPECTED["direct_call"], "direct callsite unchanged")
    req(appb[off(SEG_CALL):off(SEG_CALL) + 4].hex() == EXPECTED["seg_call"], "segmented callsite unchanged")
    req(bytes(appb[off(DISPLAY_VERSION_ADDRESS):off(DISPLAY_VERSION_ADDRESS) + len(S16_DISPLAY)]) == S16_DISPLAY, "S16 marker")
    diffs = difference_offsets(parent, appb)
    expected_offsets = set(range(off(RESET_ENTRY), off(OWNED_END))) | set(range(off(DISPLAY_VERSION_ADDRESS), off(DISPLAY_VERSION_ADDRESS) + len(S16_DISPLAY)))
    req(set(diffs).issubset(expected_offsets), "no app diffs outside reset wrapper tail and display marker")
    manifest = {
        "format": FORMAT + ".app-manifest-v1",
        "basis_app": "S1C5-playback-register-return-S1C5-marked/app.bin",
        "basis_app_sha256": EXPECTED["parent_app"],
        "output_app_sha256": sha(appb),
        "runtime_base": hx(BASE),
        "patches": patches,
        "parent_relative_changed_byte_count": len(diffs),
        "parent_relative_changed_ranges": compact_ranges(diffs),
        "input_gates": gates,
        "reset_contract": {
            "entry": hx(RESET_ENTRY),
            "signature": {"wire_bytes_6_7": list(RESET_SIG), "structural_impossibility": "payload bytes 0..1 = OP1 EG rates 1..2, DX7 range 0..99 (0x00..0x63); 0x64/0x65 impossible in any valid voice"},
            "on_match": "clear lock/count/state, csync, return without calling producer (reset packet is not a voice)",
            "on_mismatch": "r0 = stage preserved, call producer 0x0201e196",
            "callsites": {"direct": {"address": hx(DIRECT_CALL), "bytes": EXPECTED["direct_call"], "status": "unchanged"}, "segmented": {"address": hx(SEG_CALL), "bytes": EXPECTED["seg_call"], "status": "unchanged"}},
            "preserved_core": {"range": f"{hx(SEL_START)}..{hx(RESET_ENTRY)}", "sha256": EXPECTED["core_combined"], "status": "byte-for-byte"},
        },
        "display_version": {"address": hx(DISPLAY_VERSION_ADDRESS), "old": S1C5_DISPLAY.decode("ascii").rstrip("\x00"), "new": S16_DISPLAY.decode("ascii").rstrip("\x00"), "byte_count": len(S16_DISPLAY), "status": "same-length visible 3-char marker"},
    }
    return appb, manifest, checks


def repack(app_path: Path, pkg_path: Path, manifest_path: Path) -> None:
    subprocess.run([sys.executable, str(BOUNDARY / "smk37_v15_app_patch.py"), "repack-app", str(OFFICIAL_FWSC), str(app_path), str(pkg_path), "--manifest", str(manifest_path)], check=True)


def rollback_info(app: bytes, pkg: Path) -> dict[str, Any]:
    oraw, oflash, oapp = app_from_fwsc(OFFICIAL_FWSC, True)
    craw, cflash, capp = app_from_fwsc(pkg, False)
    praw, pflash, papp = app_from_fwsc(PARENT / PARENT_PACKAGE, False)
    req(capp == app, "package embeds candidate app")
    req(sha(oraw) == EXPECTED["official_fwsc"] and sha(oapp) == EXPECTED["official_app"], "official hashes during rollback")
    req(sha(praw) == EXPECTED["parent_fwsc"] and sha(papp) == EXPECTED["parent_app"], "parent hashes during rollback")
    app_diffs = difference_offsets(oapp, app)
    flash_diffs = difference_offsets(oflash, cflash)
    package_diffs = difference_offsets(oraw, craw)
    parent_diffs = difference_offsets(papp, app)
    req(not (set(APP_DATA_OFFSET + x for x in app_diffs) - set(flash_diffs)), "flash contains app diffs")
    req(not any(x < PROTECTED_PREFIX_END for x in flash_diffs), "protected prefix unchanged")
    sectors = sorted({x - (x % SECTOR) for x in flash_diffs})
    rdir = HERE / "rollback" / "official-v15-recovery-sectors"
    if rdir.exists():
        shutil.rmtree(rdir)
    rdir.mkdir(parents=True, exist_ok=True)
    entries = []
    for base in sectors:
        data = bytes(oflash[base:base + SECTOR])
        name = f"official-v15-sector-{base:05x}.bin"
        (rdir / name).write_bytes(data)
        entries.append({"sector_base": f"0x{base:05x}", "size": len(data), "sha256": sha(data), "file": f"rollback/official-v15-recovery-sectors/{name}"})
    recon = bytearray(cflash)
    for base in sectors:
        recon[base:base + SECTOR] = oflash[base:base + SECTOR]
    req(bytes(recon) == bytes(oflash), "rollback reconstructs official flash")
    wjson(rdir / "manifest.json", {"format": FORMAT + ".official-v15-sector-rollback-v1", "sector_size": SECTOR, "changed_sectors": entries, "official_flash_sha256": sha(oflash), "candidate_flash_sha256": sha(cflash), "rollback_restores_official_flash": True})
    return {
        "package_sha256": sha(craw),
        "package_size": len(craw),
        "payload_sha256": sha(unpack_any(craw)),
        "candidate_flash_sha256": sha(cflash),
        "official_flash_sha256": sha(oflash),
        "parent_flash_sha256": sha(pflash),
        "changed_app_byte_count_vs_official": len(app_diffs),
        "changed_app_ranges_vs_official": compact_ranges(app_diffs),
        "changed_app_byte_count_vs_parent": len(parent_diffs),
        "changed_app_ranges_vs_parent": compact_ranges(parent_diffs),
        "changed_flash_sectors_vs_official": [f"0x{x:05x}" for x in sectors],
        "changed_package_byte_count_vs_official": len(package_diffs),
        "changed_package_ranges_vs_official": compact_ranges(package_diffs),
        "protected_hashes_official": protected_hashes(bytearray(oflash)),
        "protected_hashes_candidate": protected_hashes(bytearray(cflash)),
        "rollback_manifest": "rollback/official-v15-recovery-sectors/manifest.json",
        "rollback_restores_official_flash": True,
    }


def reset_packet() -> dict[str, Any]:
    data = HEADER + bytes(RESET_SIG) + bytes(0x9C - 2) + TERM
    req(len(data) == 163 and data[6:8] == bytes(RESET_SIG) and data[-1] == 0xF7, "reset packet framing")
    req(data[WIRE_PLAYBACK_OFFSET] == RESET_PACKET_BYTE_161, "reset packet byte 161 fixed")
    return {"kind": "reset", "order": 0, "trigger_note": None, "playback_note": None, "file": "packet00-reset-signature-6465.bin", "sha256": sha(data), "bytes": data, "name": "explicit reset (not a voice)"}


def transport_packets() -> dict[str, Any]:
    out = HERE / "inputs" / "packets"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    parent_manifest = json.loads((PARENT / "inputs" / "packets" / "packet-manifest.json").read_text())
    packets: list[dict[str, Any]] = []
    rp = reset_packet()
    (out / rp["file"]).write_bytes(rp["bytes"])
    packets.append({"kind": "reset", "order": 0, "slot": None, "trigger_note": None, "playback_note": None, "file": rp["file"], "sha256": rp["sha256"], "name": "explicit reset packet (structurally impossible signature 0x64 0x65; not loaded as a voice)", "wire_bytes_6_7": bytes(RESET_SIG).hex(), "byte_161": RESET_PACKET_BYTE_161})
    for slot, item in enumerate(parent_manifest["packets"]):
        trig = 36 + slot
        playback = 60
        src = PARENT / "inputs" / "packets" / item["file"]
        tmpl = bytearray(src.read_bytes())
        req(len(tmpl) == 163 and tmpl.startswith(HEADER) and tmpl.endswith(TERM), f"template packet {slot} framing")
        req(hashlib.sha256(tmpl).hexdigest() == item["sha256"], f"template packet {slot} hash vs S1-C5 manifest")
        pkt = bytearray(tmpl)
        pkt[WIRE_PLAYBACK_OFFSET] = playback
        name = f"packet{slot + 1:02d}-slot{slot:02d}-trigger{trig:02d}-playback{playback:02d}-all-c4-163.bin"
        (out / name).write_bytes(pkt)
        packets.append({"kind": "voice", "order": slot + 1, "slot": slot, "trigger_note": trig, "playback_note": playback, "file": name, "sha256": sha(pkt), "template_file": item["file"], "template_sha256": item["sha256"], "only_changed_wire_offsets_vs_template": [] if tmpl[WIRE_PLAYBACK_OFFSET] == playback else [WIRE_PLAYBACK_OFFSET], "duplicate_group": "all-c4", "name": item.get("name"), "wire_bytes_6_7": bytes(pkt[6:8]).hex()})
    req(len(packets) == 17 and packets[0]["kind"] == "reset", "17-packet transport (1 reset + 16 voices)")
    req(len({p["playback_note"] for p in packets if p["kind"] == "voice"}) == 1, "voice playback notes all C4")
    req(not any(p["wire_bytes_6_7"] == bytes(RESET_SIG) for p in packets if p["kind"] == "voice"), "no voice packet carries the reset signature")
    man = {"format": FORMAT + ".reset-transport-packets-v1", "status": "PASS", "device_accessed": False, "midi_transport_opened": False, "send_enabled": False, "packet_count": 17, "reset_packet_count": 1, "voice_packet_count": 16, "packet_bytes": 163, "supported_ingress_modes": ["direct_163_byte_sysex", "segmented_final_sysex_after_final_f7_total_0x9e"], "order_basis": "explicit reset first, then resident_slot_order_trigger_note_36_51", "wire_playback_note_offset": WIRE_PLAYBACK_OFFSET, "payload_playback_note_offset": 0x9B, "reset_signature": {"wire_bytes_6_7": list(RESET_SIG), "structural_impossibility": "payload bytes 0..1 are OP1 EG rates 1..2 (DX7 range 0..99); 0x64/0x65 cannot occur in any valid voice", "not_loaded_as_voice": True}, "policy": "host sends 1 explicit reset packet then 16 voice packets; reset packet clears lock/count/state and is never loaded; voice packets may use any Playback Note 0..127 including duplicates", "duplicate_playback_note_test": {"value": ALL_C4_PLAYBACK_NOTE, "label": "C4", "slots": 16, "status": "PASS"}, "packets": packets}
    wjson(out / "packet-manifest.json", man)
    (out / "SHA256SUMS").write_text("\n".join([f"{shaf(out / 'packet-manifest.json')}  packet-manifest.json"] + [f"{shaf(out / p['file'])}  {p['file']}" for p in packets]) + "\n")
    return man


def c_array(hex_digest: str) -> str:
    return ", ".join(f"0x{hex_digest[i:i + 2]}" for i in range(0, len(hex_digest), 2))


def exact_ota_c(pkgsha: str) -> str:
    token = f"INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-{pkgsha[:8].upper()}"
    return f'''/* Exact-hash v15-only OTA wrapper for S1-C6 Reset Signature Isolation (S16).
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {c_array(pkgsha)} }};
static const char CONFIRM[] = "{token}";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C6 Reset Signature Isolation candidate";
static int check_exact(const char *path) {{ struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{ printf("exact v15 S1-C6 Reset Signature Isolation package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length); status = 0; }} else fputs("offline check rejected: not exact S1-C6 Reset Signature Isolation package\\n", stderr); smk37_fwsc_free(&firmware); return status; }}
int main(int argc, char **argv) {{ if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C6 Reset Signature Isolation candidate installed"); fprintf(stderr, "usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n", argv[0], argv[0], CONFIRM); return 2; }}
'''


def exact_sender_c(manifest: dict[str, Any], token: str) -> str:
    specs = []
    for pkt in manifest["packets"]:
        if pkt["kind"] == "reset":
            specs.append(f'    {{ {pkt["order"]}u, 0u, "RESET", 0u, {RESET_PACKET_BYTE_161}u, "{pkt["file"]}", {{ {c_array(pkt["sha256"])} }} }}')
        else:
            specs.append(f'    {{ {pkt["order"]}u, {pkt["slot"]}u, "VOICE", {pkt["trigger_note"]}u, {pkt["playback_note"]}u, "{pkt["file"]}", {{ {c_array(pkt["sha256"])} }} }}')
    joined_specs = ",\n".join(specs)
    return f'''/* Guarded exact 17-packet sender (1 reset + 16 voices) for S1-C6 Reset Signature Isolation.
 * Default build has live USB disabled and only supports dry-run validation.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef S1C6_ENABLE_LIVE_USB
#include <time.h>
#include <libusb.h>
#endif
#include "../../../../../src/sha256.h"
#define S1C6_PACKET_COUNT 17u
#define S1C6_VOICE_COUNT 16u
#define S1C6_PACKET_SIZE 163u
#define S1C6_USB_MIDI_BYTES 220u
#define S1C6_USB_MIDI_PACKET_SIZE 4u
#define S1C6_MAX_PATH 4096u
static const uint8_t EXPECTED_HEADER[6] = {{0xf0,0x43,0x00,0x00,0x01,0x1b}};
static const char CONFIRM_TOKEN[] = "{token}";
struct packet_spec {{ unsigned order; unsigned slot; const char *kind; unsigned trigger_note; unsigned playback_note; const char *file; uint8_t sha256[SMK37_SHA256_LENGTH]; }};
static const struct packet_spec PACKETS[S1C6_PACKET_COUNT] = {{
{joined_specs}
}};
static int build_path(char *out, size_t out_size, const char *dir, const char *file) {{ int n = snprintf(out, out_size, "%s/%s", dir, file); return (n < 0 || (size_t)n >= out_size) ? 1 : 0; }}
static int read_file_exact(const char *path, uint8_t packet[S1C6_PACKET_SIZE]) {{ FILE *f = fopen(path, "rb"); int extra; if (!f) {{ perror(path); return 1; }} if (fread(packet, 1, S1C6_PACKET_SIZE, f) != S1C6_PACKET_SIZE) {{ fprintf(stderr, "S1-C6 packet must be exactly %u bytes: %s\\n", (unsigned)S1C6_PACKET_SIZE, path); fclose(f); return 1; }} extra = fgetc(f); fclose(f); if (extra != EOF) {{ fprintf(stderr, "S1-C6 packet has trailing bytes: %s\\n", path); return 1; }} return 0; }}
static size_t packetize(const uint8_t *sysex, size_t length, uint8_t *events, size_t capacity) {{ size_t input = 0, output = 0; while (input < length) {{ size_t remaining = length - input; size_t count = remaining > 3 ? 3 : remaining; uint8_t cin; if (output + S1C6_USB_MIDI_PACKET_SIZE > capacity) return 0; cin = remaining > 3 ? 0x04 : (remaining == 1 ? 0x05 : (remaining == 2 ? 0x06 : 0x07)); events[output] = cin; events[output + 1] = sysex[input]; events[output + 2] = count > 1 ? sysex[input + 1] : 0; events[output + 3] = count > 2 ? sysex[input + 2] : 0; input += count; output += S1C6_USB_MIDI_PACKET_SIZE; }} return output; }}
static int verify_packet(const char *dir, const struct packet_spec *spec, uint8_t packet[S1C6_PACKET_SIZE], uint8_t events[S1C6_USB_MIDI_BYTES]) {{ uint8_t digest[SMK37_SHA256_LENGTH]; char path[S1C6_MAX_PATH]; size_t event_len; if (build_path(path, sizeof(path), dir, spec->file) != 0 || read_file_exact(path, packet) != 0) return 1; if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 || packet[S1C6_PACKET_SIZE - 1] != 0xf7) {{ fprintf(stderr, "S1-C6 order %u %s framing mismatch\\n", spec->order, spec->kind); return 1; }} if (strcmp(spec->kind, "RESET") == 0) {{ if (packet[6] != 0x64 || packet[7] != 0x65 || packet[161] != (uint8_t)spec->playback_note) {{ fprintf(stderr, "S1-C6 reset packet signature/byte-161 mismatch\\n"); return 1; }} }} else if (packet[161] != (uint8_t)spec->playback_note) {{ fprintf(stderr, "S1-C6 order %u slot %u trigger %u playback %u mismatch\\n", spec->order, spec->slot, spec->trigger_note, spec->playback_note); return 1; }} smk37_sha256(packet, S1C6_PACKET_SIZE, digest); if (memcmp(digest, spec->sha256, sizeof(digest)) != 0) {{ fprintf(stderr, "S1-C6 order %u packet SHA-256 mismatch\\n", spec->order); return 1; }} event_len = packetize(packet, S1C6_PACKET_SIZE, events, S1C6_USB_MIDI_BYTES); if (event_len != S1C6_USB_MIDI_BYTES || events[event_len - 4] != 0x05 || events[event_len - 3] != 0xf7) {{ fputs("USB-MIDI packetization invariant failed\\n", stderr); return 1; }} return 0; }}
#ifdef S1C6_ENABLE_LIVE_USB
static int send_verified(uint8_t events[S1C6_PACKET_COUNT][S1C6_USB_MIDI_BYTES]) {{ (void)events; fputs("live USB path intentionally not implemented in this artifact; use only after separate authorization and implementation review\\n", stderr); return 2; }}
#else
static int send_verified(uint8_t events[S1C6_PACKET_COUNT][S1C6_USB_MIDI_BYTES]) {{ (void)events; fputs("send BLOCK: live USB sender is disabled in the offline validation build\\n", stderr); return 2; }}
#endif
static void usage(const char *p) {{ fprintf(stderr, "usage:\\n  %s dry-run <packet-dir>\\n  %s send <packet-dir> --confirm %s\\n", p, p, CONFIRM_TOKEN); }}
int main(int argc, char **argv) {{ uint8_t packets[S1C6_PACKET_COUNT][S1C6_PACKET_SIZE]; uint8_t events[S1C6_PACKET_COUNT][S1C6_USB_MIDI_BYTES]; if (argc != 3 && argc != 5) {{ usage(argv[0]); return 2; }} for (unsigned i = 0; i < S1C6_PACKET_COUNT; ++i) if (verify_packet(argv[2], &PACKETS[i], packets[i], events[i]) != 0) return 2; if (strcmp(argv[1], "dry-run") == 0 && argc == 3) {{ puts("S1-C6 Reset Signature Isolation 17-packet sender dry-run PASS: 1 explicit reset (0x64 0x65, not a voice) + 16 voices all-C4, no USB/MIDI opened"); return 0; }} if (strcmp(argv[1], "send") == 0 && argc == 5 && strcmp(argv[3], "--confirm") == 0 && strcmp(argv[4], CONFIRM_TOKEN) == 0) return send_verified(events); usage(argv[0]); return 2; }}
'''
def dry_run_py(pkgsha: str, packet_hashes: list[str]) -> str:
    return f'''#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parent; PKG={PACKAGE_NAME!r}; PKGSHA={pkgsha!r}; HASHES={packet_hashes!r}; HEADER=bytes.fromhex('f0430000011b')
def sh(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def req(x,m):
    if not x: raise SystemExit('FAIL: '+m)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); a=ap.parse_args(); req(sh(HERE/PKG)==PKGSHA,'package hash'); man=json.loads((HERE/'inputs/packets/packet-manifest.json').read_text()); req(man['packet_count']==17 and man['reset_packet_count']==1 and man['voice_packet_count']==16,'17-packet manifest')
    for i,it in enumerate(man['packets']):
        b=(HERE/'inputs/packets'/it['file']).read_bytes(); req(len(b)==163 and b.startswith(HEADER) and b[-1]==0xf7, f'packet {{i}} framing'); req(hashlib.sha256(b).hexdigest()==HASHES[i]==it['sha256'], f'packet {{i}} hash')
        if it['kind']=='reset': req(b[6]==0x64 and b[7]==0x65 and b[161]==0x00, f'reset packet signature/byte161')
        else: req(b[161]==it['playback_note']==60, f'packet {{i}} C4 playback byte')
    res={{'status':'DRY_RUN_PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'package_sha256':PKGSHA,'wire_playback_note_offset':161,'packet_count':17,'reset_signature':'0x64 0x65','duplicate_playback_note':'all C4 (60)'}}
    print(json.dumps(res,sort_keys=True) if a.json else 'S1-C6 Reset Signature Isolation dry-run PASS: 1 reset + 16 all-C4 packets, no USB/MIDI/device/flash/reset action')
if __name__=='__main__': main()
'''


def write_code_evidence(rows: list[dict[str, Any]], checks: list[str], code: bytes, tail: bytes) -> dict[str, Any]:
    if CODEDIR.exists():
        shutil.rmtree(CODEDIR)
    CODEDIR.mkdir(parents=True, exist_ok=True)
    with (CODEDIR / "reset-wrapper-decode.tsv").open("w") as f:
        f.write("address\tsize\tbytes\tname\tasm\tmeaning\ttarget\n")
        for r in rows:
            f.write(f"{r['address']}\t{r['size']}\t{r['bytes']}\t{r['name']}\t{r['asm']}\t{r['meaning']}\t{r.get('target', '')}\n")
    (CODEDIR / "reset-wrapper.bin").write_bytes(code)
    (CODEDIR / "reset-wrapper.hex").write_text(code.hex() + "\n")
    ev = {
        "format": FORMAT + ".code-evidence-v1",
        "decision": "PASS",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False},
        "basis": {"parent_candidate": str(PARENT.relative_to(ROOT)), "parent_app_sha256": EXPECTED["parent_app"], "parent_package_sha256": EXPECTED["parent_fwsc"]},
        "preserved_code": {"start": hx(SEL_START), "end_exclusive": hx(RESET_ENTRY), "combined_sha256": EXPECTED["core_combined"], "selector_sha256": EXPECTED["selector"], "producer_core_sha256": EXPECTED["producer_core"], "status": "preserved byte-for-byte from exact S1-C5 marked"},
        "callsites": {"direct": {"address": hx(DIRECT_CALL), "bytes": EXPECTED["direct_call"], "target": hx(RESET_ENTRY), "status": "unchanged"}, "segmented": {"address": hx(SEG_CALL), "bytes": EXPECTED["seg_call"], "target": hx(RESET_ENTRY), "status": "unchanged"}},
        "changed_code": {"start": hx(RESET_ENTRY), "end_exclusive": hx(OWNED_END), "bytes": len(code) + len(tail), "instructions": rows, "tail_padding_hex": tail.hex()},
        "reset_contract": {"signature": {"wire_bytes_6_7": list(RESET_SIG), "structural_impossibility": "payload bytes 0..1 = OP1 EG rates 1..2, DX7 range 0..99; 0x64/0x65 impossible in any valid voice"}, "on_match": "clear lock/count/state, csync, pop return (packet NOT loaded as voice)", "on_mismatch": "r0 = stage preserved, call producer 0x0201e196", "host_protocol": "1 explicit reset packet + 16 voice packets = 17 total"},
        "abi_contract": {"r0": "stage on entry, preserved through the skip path", "r4_r9": "preserved by push/pop (segmented caller r7 contract)", "r0_r1": "scratch, as in S1-C5", "r5": "clobbered and restored by push/pop, as in S1-C5"},
        "validation": checks,
    }
    wjson(CODEDIR / "evidence.json", ev)
    (CODEDIR / "validation.txt").write_text("S1-C6 Reset Signature Isolation code evidence: PASS\n" + "\n".join(checks) + "\n")
    (CODEDIR / "report.md").write_text("# S1-C6 Reset Signature Isolation code evidence PASS\n\nThe S1-C5 reset wrapper at `0x0201e228` is replaced in place with an impossible-signature reset wrapper: `lb.z r1,[r0]`/`lb.z r1,[r0+1]` check `stage[0..1] == 0x64 0x65` (wire bytes 6..7). Payload bytes 0..1 are OP1 EG rates 1..2 with DX7 value range 0..99, so `0x64`/`0x65` cannot occur in any valid voice. On match the wrapper clears lock/count/state, `csync`s, and pops -- the reset packet is **not** loaded as a voice. On mismatch it calls the sequential producer at `0x0201e196` with `r0 = stage` intact. The selector/producer-core bytes `0x0201e13e..0x0201e228` are preserved byte-for-byte, and both callsites `0x0201e468`/`0x0201e49c` still target `0x0201e228` unchanged. The display marker changes from `S1C5` to `S16`.\n")
    (CODEDIR / "SHA256SUMS").write_text("\n".join(f"{shaf(CODEDIR / name)}  {name}" for name in ["reset-wrapper-decode.tsv", "reset-wrapper.bin", "reset-wrapper.hex", "evidence.json", "report.md", "validation.txt"]) + "\n")
    return ev


def write_sha_inventory() -> None:
    paths = []
    for name in ["build_s1c6_reset_signature_isolation.py", "validate.py", "dry_run_validate.py", "app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "evidence.json", "report.md", "README.md", "exact_ota.c", "exact_17_packet_sender.c", "validation.txt"]:
        p = HERE / name
        if p.exists():
            paths.append(p)
    for base in ["code-evidence", "rollback", "inputs"]:
        root = HERE / base
        if root.exists():
            paths.extend(p for p in sorted(root.rglob("*")) if p.is_file())
    seen = []
    for p in paths:
        if p not in seen:
            seen.append(p)
    (HERE / "SHA256SUMS").write_text("\n".join(f"{shaf(p)}  {p.relative_to(HERE)}" for p in seen) + "\n")


ALL_C4_PLAYBACK_NOTE = 60


def build(check: bool = False, no_write: bool = False) -> dict[str, Any]:
    parent, gates = gate_basis()
    code, tail, rows, labels = build_reset_wrapper()
    checks = verify_wrapper(code, tail, rows, labels)
    collision = collision_scan()
    if no_write:
        return {"decision": "PASS", "candidate_built": False, "validation": checks}
    if check:
        ev = json.loads((HERE / "evidence.json").read_text())
        req(shaf(HERE / "app.bin") == ev["app"]["output_app_sha256"] == sha(build_app(parent, gates, [])[0]), "deterministic app hash")
        req(json.loads((CODEDIR / "evidence.json").read_text())["decision"] == "PASS", "code evidence exists")
        return ev
    app, app_manifest, app_checks = build_app(parent, gates, checks)
    code_ev = write_code_evidence(rows, app_checks, code, tail)
    (HERE / "app.bin").write_bytes(app)
    wjson(HERE / "app-manifest.json", app_manifest)
    repack(HERE / "app.bin", HERE / PACKAGE_NAME, HERE / "package-manifest.json")
    pkg_info = rollback_info(app, HERE / PACKAGE_NAME)
    pman = json.loads((HERE / "package-manifest.json").read_text())
    req(pman["output"]["sha256"] == pkg_info["package_sha256"], "package manifest hash")
    transport = transport_packets()
    packet_hashes = [p["sha256"] for p in transport["packets"]]
    ota_token = f"INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-{pkg_info['package_sha256'][:8].upper()}"
    sender_token = "SEND-SMK37PRO-V15-S1C6-RESET-SIG-" + "-".join(h[:8].upper() for h in packet_hashes[:4])
    (HERE / "exact_ota.c").write_text(exact_ota_c(pkg_info["package_sha256"]))
    (HERE / "exact_17_packet_sender.c").write_text(exact_sender_c(transport, sender_token))
    (HERE / "dry_run_validate.py").write_text(dry_run_py(pkg_info["package_sha256"], packet_hashes))
    (HERE / "dry_run_validate.py").chmod(0o755)
    evidence = {
        "format": FORMAT + ".release-evidence-v1",
        "decision": "PASS",
        "candidate_built": True,
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "reset_performed": False, "live_send_performed": False},
        "basis": {"official_fwsc_sha256": EXPECTED["official_fwsc"], "official_app_sha256": EXPECTED["official_app"], "parent_s1c5_marked_app_sha256": EXPECTED["parent_app"], "parent_s1c5_marked_package_sha256": EXPECTED["parent_fwsc"]},
        "input_gates": gates,
        "collision_scan": collision,
        "code": {"candidate_dir": str(CODEDIR.relative_to(ROOT)), "reset_wrapper_range": f"{hx(RESET_ENTRY)}..{hx(OWNED_END)}", "core_sha256": EXPECTED["core_combined"], "code_evidence_sha256": shaf(CODEDIR / "evidence.json")},
        "app": app_manifest,
        "package": pkg_info,
        "transport": transport,
        "flash": {"artifact": PACKAGE_NAME, "confirmation_token": ota_token, "default_check_offline_only": True},
        "sender": {"artifact": "exact_17_packet_sender.c", "packets": "inputs/packets", "confirmation_token": sender_token, "default_compile_live_usb_enabled": False, "wire_playback_note_offset": WIRE_PLAYBACK_OFFSET, "packet_count": 17, "reset_first": True, "duplicate_test": "all 16 voice playback notes C4 (60)"},
        "invariants": {"reset_signature": "wire bytes 6..7 == 0x64 0x65 (structurally impossible in any valid DX7 voice)", "reset_not_a_voice": True, "callsites_unchanged": True, "core_preserved": "selector/producer core 0x0201e13e..0x0201e228 byte-for-byte", "trigger_source": "slot = trigger_note - 36; unchanged", "playback_note_range": "0..127 including duplicates", "reload_without_power_cycle": True, "display_marker": "S16"},
    }
    wjson(HERE / "evidence.json", evidence)
    (HERE / "validation.txt").write_text("S1-C6 Reset Signature Isolation build validation: PASS\n" + "\n".join(app_checks) + "\n")
    (HERE / "README.md").write_text(f"# S1-C6 Reset Signature Isolation (S16) offline release\n\nStatus: **PASS, candidate built offline**.\n\nApp SHA-256 `{app_manifest['output_app_sha256']}`. FWSC SHA-256 `{pkg_info['package_sha256']}`. OTA token `{ota_token}`.\n\nFixes the 2026-08-14 FM Drum load failure: the S1-C5 reset wrapper detected `0x62 0x63` at wire bytes 6..7 and loaded the packet as a voice, so any voice whose first payload bytes were `62 63` (HITUN RIMS, BUZZ BASS) reset the transaction mid-load. S1-C6 replaces the signature with the structurally impossible `0x64 0x65` (payload bytes 0..1 are OP1 EG rates, DX7 range 0..99) and returns without loading the reset packet as a voice. Hosts send 1 explicit reset packet + 16 voice packets. The new wrapper fits in place; callsites `0x0201e468`/`0x0201e49c` and the selector/producer core are unchanged. Display marker `S16`. No live actions were performed.\n")
    (HERE / "report.md").write_text(f"# S1-C6 Reset Signature Isolation PASS\n\n- App SHA-256: `{app_manifest['output_app_sha256']}`.\n- FWSC SHA-256: `{pkg_info['package_sha256']}`.\n- Parent S1-C5 marked app SHA-256: `{EXPECTED['parent_app']}`.\n- Preserved core SHA-256: `{EXPECTED['core_combined']}`.\n- Reset signature: `0x64 0x65` at wire bytes 6..7 (structurally impossible in any DX7 voice).\n- OTA token: `{ota_token}`.\n- Sender token: `{sender_token}`.\n\nPASS: exact S1-C5 marked basis, impossible-signature reset wrapper in place, reset packet not loaded as a voice, callsites and core unchanged, 17-packet transport (1 reset + 16 all-C4 voices), bundled-voice collision scan 0 hits, rollback reconstructs official v15, and no device/flash path was used.\n")
    write_sha_inventory()
    return evidence


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    ev = build(check=args.check, no_write=args.no_write)
    print("S1-C6 Reset Signature Isolation build gate: PASS")
    if ev.get("candidate_built"):
        print("app_sha256=" + ev["app"]["output_app_sha256"])
        print("package_sha256=" + ev["package"]["package_sha256"])
        print("ota_confirmation_token=" + ev["flash"]["confirmation_token"])
        print("sender_confirmation_token=" + ev["sender"]["confirmation_token"])


if __name__ == "__main__":
    main()
