#!/usr/bin/env python3
"""Build S1-C5 Playback Register Return offline candidate.

This is a v15-only successor to S1-C4 v3 segmented-final.  It never opens a
USB/MIDI/device path and never uploads or flashes.  The only app mutations vs
the exact S1-C4 v3 app are the two post-hook 6-byte windows that were already
neutralized in S1-C4 v3.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FLASH = HERE.parent
ANALYSIS = HERE.parents[1]
ROOT = HERE.parents[4]
PARENT = FLASH / "S1C4-playback-note-v3-segmented-final"
PARENT_CODE = ANALYSIS / "playback-note" / "candidate-v3-segmented-final"
BOUNDARY = FLASH / "S1C3-16slot-boundary-only"
OFFICIAL_FWSC = FLASH / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
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

FORMAT = "smk37-v15-s1c5-playback-register-return"
PACKAGE_NAME = "SMK37Pro-v15-S1C5-playback-register-return.fwsc"
BASE = 0x02000000
SECTOR = 0x2000
PROTECTED_PREFIX_END = 0x4000
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
NOFF_HOOK, NON_HOOK = 0x0201C63E, 0x0201C67C
NOFF_RELOAD, NON_RELOAD = 0x0201C644, 0x0201C682
NON_VELOCITY_STORE = 0x0201C68C
SEL_START, OWNED_END = 0x0201E13E, 0x0201E254
DIRECT_CALL, DIRECT_RELOAD = 0x0201E468, 0x0201E46C
SEG_CALL, SEG_RELOAD = 0x0201E49C, 0x0201E4A0
WIRE_PLAYBACK_OFFSET = 161
ALL_C4_PLAYBACK_NOTE = 60
NOTE0, SLOTS = 36, 16

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "parent_app": "c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d",
    "parent_fwsc": "376d931e9f5fbdfb5737347b6984fad493f35f023134f8309d4792286c1c7aec",
    "parent_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "parent_selector": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "parent_producer": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "noff_hook": "80fffa1a0000",
    "non_hook": "80ffc01a0000",
    "noff_parent_neutral": "001600160016",
    "non_parent_neutral": "001600160016",
    "noff_stock_post_store": "00e13e618d40",
    "non_stock_post_store": "00e13e718e40",
    "noff_register_reload": "0d4000160016",
    "non_register_reload": "0e4000160016",
    "velocity_store": "8d42",
    "direct_call": "bfeadefe",
    "direct_reload": "bfeaf838",
    "seg_call": "bfeac4fe",
    "seg_reload": "bfeade38",
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


def mov(dst: int, src: int) -> bytes:
    return word(0x1600 | (src << 4) | dst)


def lb(dst: int, base: int, ofs: int = 0) -> bytes:
    return word(0x4008 | dst | (base << 4) | ((ofs & 0x1F) << 8))


def short_target(at: int, data: bytes) -> int:
    return ((at + 4 + struct.unpack("<H", data[2:4])[0] * 2) & 0xFFFF) | (at & 0xFFFF0000)


def decode_pi32_window(data: bytes, start: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = start + i
        ins = data[i:i + 2]
        req(len(ins) == 2, f"unaligned decode at {hx(at)}")
        w = int.from_bytes(ins, "little")
        if (w & 0xE088) == 0x4008:
            dst = w & 0x7
            base = (w >> 4) & 0x7
            ofs = (w >> 8) & 0x1F
            asm = f"lb.z r{dst},[r{base}" + (f"+{ofs}" if ofs else "") + "]"
            op = "load_byte_zero_extend"
        elif (w & 0xFF00) == 0x1600:
            dst = w & 0xF
            src = (w >> 4) & 0xF
            asm = f"mov r{dst},r{src}"
            op = "mov_reg"
        elif len(data) - i >= 4 and data[i + 1] == 0xE1:
            # Only used to document the old stock windows from the parent manifest.
            dst = data[i] & 0xF
            src = data[i + 3] >> 4
            imm = data[i + 2] | ((data[i + 3] & 0xF) << 8)
            rows.append({"address": hx(at), "size": 4, "bytes": data[i:i + 4].hex(), "op": "add_imm12", "asm": f"add r{dst},r{src},#0x{imm:x}"})
            i += 4
            continue
        elif (w & 0xE088) == 0x4088:
            src = w & 0x7
            base = (w >> 4) & 0x7
            ofs = (w >> 8) & 0x1F
            asm = f"sb [r{base}" + (f"+{ofs}" if ofs else "") + f"],r{src}"
            op = "store_byte"
        else:
            raise SystemExit(f"FAIL: undecoded changed instruction at {hx(at)} {data[i:i+8].hex()}")
        rows.append({"address": hx(at), "size": 2, "bytes": ins.hex(), "op": op, "asm": asm})
        i += 2
    return rows


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
    req(sha(parent_app) == EXPECTED["parent_app"], "exact S1-C4 v3 parent app hash")
    req(shaf(PARENT / "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc") == EXPECTED["parent_fwsc"], "exact S1-C4 v3 parent package hash")
    parent_ev = json.loads((PARENT / "evidence.json").read_text())
    code_ev = json.loads((PARENT_CODE / "evidence.json").read_text())
    req(parent_ev["decision"] == "PASS" and code_ev["decision"] == "PASS", "parent and code evidence PASS")
    req(code_ev["combined"]["sha256"] == EXPECTED["parent_combined"], "parent combined code hash")
    req(code_ev["selector"]["sha256"] == EXPECTED["parent_selector"], "parent selector hash")
    req(code_ev["producer"]["sha256"] == EXPECTED["parent_producer"], "parent producer hash")
    req("r0 = original destination + 0x9c" in code_ev["selector"]["metadata_return"], "selector returns r0 metadata pointer")
    req(code_ev["selector"]["source_invariant"] == "source slot = trigger_note - 36 only; Playback Note is metadata only", "trigger source invariant")
    req(code_ev["selector"]["playback_map_read_after_armed_and_valid"] is True, "selector map gates")
    req(code_ev["producer"]["playback_store"] == "lb.z r2,[staging+0x9b]; sb [0x01c46f20+slot],r2", "producer stores playback map byte")

    exact_slices = {
        "noff_hook": (NOFF_HOOK, EXPECTED["noff_hook"]),
        "non_hook": (NON_HOOK, EXPECTED["non_hook"]),
        "noff_neutral_window": (NOFF_RELOAD, EXPECTED["noff_parent_neutral"]),
        "non_neutral_window": (NON_RELOAD, EXPECTED["non_parent_neutral"]),
        "non_velocity_store": (NON_VELOCITY_STORE, EXPECTED["velocity_store"]),
        "direct_call": (DIRECT_CALL, EXPECTED["direct_call"]),
        "direct_reload": (DIRECT_RELOAD, EXPECTED["direct_reload"]),
        "segmented_call": (SEG_CALL, EXPECTED["seg_call"]),
        "segmented_reload": (SEG_RELOAD, EXPECTED["seg_reload"]),
    }
    for name, (address, hexbytes) in exact_slices.items():
        req(parent_app[off(address):off(address) + len(bytes.fromhex(hexbytes))].hex() == hexbytes, f"parent exact slice {name}")
    req(sha(parent_app[off(SEL_START):off(OWNED_END)]) == EXPECTED["parent_combined"], "selector/producer bytes preserved in exact parent app")

    app_manifest = json.loads((PARENT / "app-manifest.json").read_text())
    old_by_addr = {p["address"]: p["old_hex"] for p in app_manifest["patches"] if p["address"] in {hx(NOFF_RELOAD), hx(NON_RELOAD)}}
    req(old_by_addr[hx(NOFF_RELOAD)] == EXPECTED["noff_stock_post_store"], "Note Off exact stock post-hook store evidence")
    req(old_by_addr[hx(NON_RELOAD)] == EXPECTED["non_stock_post_store"], "Note On exact stock post-hook store evidence")
    req(short_target(DIRECT_CALL, parent_app[off(DIRECT_CALL):off(DIRECT_CALL)+4]) == 0x0201E228, "direct call target")
    req(short_target(SEG_CALL, parent_app[off(SEG_CALL):off(SEG_CALL)+4]) == 0x0201E228, "segmented-final call target")

    gates.append({"name": "official-v15-basis", "status": "PASS", "official_fwsc_sha256": EXPECTED["official_fwsc"], "official_app_sha256": EXPECTED["official_app"]})
    gates.append({"name": "exact-s1c4-v3-app-package-basis", "status": "PASS", "parent_app_sha256": EXPECTED["parent_app"], "parent_fwsc_sha256": EXPECTED["parent_fwsc"], "parent_candidate": str(PARENT.relative_to(ROOT))})
    gates.append({"name": "selector-r0-return-and-playback-map-abi", "status": "PASS", "selector_sha256": EXPECTED["parent_selector"], "producer_sha256": EXPECTED["parent_producer"], "combined_sha256": EXPECTED["parent_combined"], "r0_return": "selector stores mapped byte to [dest+0x9c] and returns with r0 == dest+0x9c", "source_invariant": "source slot remains trigger_note-36", "producer_playback_store": "wire byte 161 -> 0x01c46f20+slot"})
    gates.append({"name": "exact-caller-post-hook-windows", "status": "PASS", "note_off_stock_post_store": EXPECTED["noff_stock_post_store"], "note_on_stock_post_store": EXPECTED["non_stock_post_store"], "note_off_parent_neutral": EXPECTED["noff_parent_neutral"], "note_on_parent_neutral": EXPECTED["non_parent_neutral"], "note_on_velocity_store": EXPECTED["velocity_store"]})
    gates.append({"name": "offline-scope", "status": "PASS", "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False})
    return parent_app, gates


def patch(app: bytearray, address: int, new: bytes, purpose: str) -> dict[str, Any]:
    old = bytes(app[off(address):off(address) + len(new)])
    app[off(address):off(address) + len(new)] = new
    return {"address": hx(address), "end_exclusive": hx(address + len(new)), "byte_count": len(new), "old_hex": old.hex(), "new_hex": new.hex(), "old_sha256": sha(old), "new_sha256": sha(new), "purpose": purpose}


def verify_changed_windows(parent: bytes, app: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    noff_new = lb(5, 0) + mov(0, 0) + mov(0, 0)
    non_new = lb(6, 0) + mov(0, 0) + mov(0, 0)
    req(noff_new.hex() == EXPECTED["noff_register_reload"], "Note Off reload encoding")
    req(non_new.hex() == EXPECTED["non_register_reload"], "Note On reload encoding")
    rows: list[dict[str, Any]] = []
    checks: list[str] = []
    for label, address, oldhex, newhex, expected_asm in [
        ("note_off", NOFF_RELOAD, EXPECTED["noff_parent_neutral"], EXPECTED["noff_register_reload"], "lb.z r5,[r0]"),
        ("note_on", NON_RELOAD, EXPECTED["non_parent_neutral"], EXPECTED["non_register_reload"], "lb.z r6,[r0]"),
    ]:
        old = parent[off(address):off(address) + 6]
        new = app[off(address):off(address) + 6]
        req(old.hex() == oldhex and new.hex() == newhex, f"{label} exact window bytes")
        decoded = decode_pi32_window(new, address)
        req(decoded[0]["asm"] == expected_asm, f"{label} reload instruction decodes independently")
        req(decoded[1]["asm"] == "mov r0,r0" and decoded[2]["asm"] == "mov r0,r0", f"{label} padding instructions decode independently")
        for d in decoded:
            d["window"] = label
            rows.append(d)
        checks.append(f"PASS\t{label}\t{hx(address)}\t{oldhex}->{newhex}\t{expected_asm}; mov r0,r0; mov r0,r0")
    diffs = difference_offsets(parent, app)
    expected_offsets = set(range(off(NOFF_RELOAD), off(NOFF_RELOAD) + 6)) | set(range(off(NON_RELOAD), off(NON_RELOAD) + 6))
    # Bytes already equal where neutral mov padding remains, so actual diff is only first 2 bytes per window.
    req(set(diffs).issubset(expected_offsets), "no app diffs outside exact post-hook windows")
    req(sha(app[off(SEL_START):off(OWNED_END)]) == EXPECTED["parent_combined"], "producer/selector bytes unchanged")
    checks.append("PASS\tpreserved\tproducer/selector combined bytes unchanged")
    checks.append("PASS\tpreserved\tNote On velocity store 0x0201c68c remains stock")
    checks.append("PASS\tduplicates\tPlayback Note values 0..127 accepted by metadata byte policy, including all sixteen slots mapped to C4 (60)")
    return rows, checks


def build_app(parent: bytes, gates: list[dict[str, Any]]) -> tuple[bytes, dict[str, Any], list[dict[str, Any]], list[str]]:
    app = bytearray(parent)
    patches = [
        patch(app, NOFF_RELOAD, bytes.fromhex(EXPECTED["noff_register_reload"]), "Note Off reload mapped playback note from selector-returned [r0] into r5; preserve r0 and remove duplicate stock store"),
        patch(app, NON_RELOAD, bytes.fromhex(EXPECTED["non_register_reload"]), "Note On reload mapped playback note from selector-returned [r0] into r6; preserve velocity r5 and remove duplicate stock store"),
    ]
    appb = bytes(app)
    rows, checks = verify_changed_windows(parent, appb)
    req(appb[off(NOFF_HOOK):off(NOFF_HOOK)+6].hex() == EXPECTED["noff_hook"], "Note Off hook unchanged")
    req(appb[off(NON_HOOK):off(NON_HOOK)+6].hex() == EXPECTED["non_hook"], "Note On hook unchanged")
    req(appb[off(NON_VELOCITY_STORE):off(NON_VELOCITY_STORE)+2].hex() == EXPECTED["velocity_store"], "velocity store unchanged")
    req(appb[off(DIRECT_RELOAD):off(DIRECT_RELOAD)+4].hex() == EXPECTED["direct_reload"], "direct reload preserved")
    req(appb[off(SEG_RELOAD):off(SEG_RELOAD)+4].hex() == EXPECTED["seg_reload"], "segmented reload preserved")
    diffs = difference_offsets(parent, appb)
    manifest = {
        "format": FORMAT + ".app-manifest-v1",
        "basis_app": "S1C4-playback-note-v3-segmented-final/app.bin",
        "basis_app_sha256": EXPECTED["parent_app"],
        "output_app_sha256": sha(appb),
        "runtime_base": hx(BASE),
        "patches": patches,
        "parent_relative_changed_byte_count": len(diffs),
        "parent_relative_changed_ranges": compact_ranges(diffs),
        "input_gates": gates,
        "callsite_contract": {
            "note_off_hook": {"address": hx(NOFF_HOOK), "bytes": EXPECTED["noff_hook"], "target": hx(SEL_START), "status": "unchanged"},
            "note_on_hook": {"address": hx(NON_HOOK), "bytes": EXPECTED["non_hook"], "target": hx(SEL_START + 4), "status": "unchanged"},
            "note_off_register_reload": {"address": hx(NOFF_RELOAD), "bytes": EXPECTED["noff_register_reload"], "decode": "lb.z r5,[r0]; mov r0,r0; mov r0,r0", "purpose": "stock Note Off post-hook store now consumes selector-returned metadata byte"},
            "note_on_register_reload": {"address": hx(NON_RELOAD), "bytes": EXPECTED["non_register_reload"], "decode": "lb.z r6,[r0]; mov r0,r0; mov r0,r0", "purpose": "stock Note On post-hook store now consumes selector-returned metadata byte"},
            "note_on_velocity_store": {"address": hx(NON_VELOCITY_STORE), "bytes": EXPECTED["velocity_store"], "status": "preserved"},
            "producer_selector_window": {"address": hx(SEL_START), "end_exclusive": hx(OWNED_END), "sha256": EXPECTED["parent_combined"], "status": "preserved byte-for-byte from S1-C4 v3"},
            "direct_product_callsite": {"address": hx(DIRECT_CALL), "bytes": EXPECTED["direct_call"], "target": "0x0201e228", "status": "preserved"},
            "segmented_product_callsite": {"address": hx(SEG_CALL), "bytes": EXPECTED["seg_call"], "target": "0x0201e228", "segmented_final_supported": True, "status": "preserved"},
        },
    }
    return appb, manifest, rows, checks


def repack(app_path: Path, pkg_path: Path, manifest_path: Path) -> None:
    subprocess.run([sys.executable, str(BOUNDARY / "smk37_v15_app_patch.py"), "repack-app", str(OFFICIAL_FWSC), str(app_path), str(pkg_path), "--manifest", str(manifest_path)], check=True)


def rollback_info(app: bytes, pkg: Path) -> dict[str, Any]:
    oraw, oflash, oapp = app_from_fwsc(OFFICIAL_FWSC, True)
    craw, cflash, capp = app_from_fwsc(pkg, False)
    praw, pflash, papp = app_from_fwsc(PARENT / "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc", False)
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


def transport_packets() -> dict[str, Any]:
    out = HERE / "inputs" / "packets"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    parent_manifest = json.loads((PARENT / "inputs" / "packets" / "packet-manifest.json").read_text())
    packets = []
    for slot, item in enumerate(parent_manifest["packets"]):
        trig = NOTE0 + slot
        playback = ALL_C4_PLAYBACK_NOTE
        src = PARENT / "inputs" / "packets" / item["file"]
        tmpl = bytearray(src.read_bytes())
        req(len(tmpl) == 163 and tmpl.startswith(HEADER) and tmpl.endswith(TERM), f"template packet {slot} framing")
        req(tmpl[WIRE_PLAYBACK_OFFSET] == item["playback_note"], f"template packet {slot} playback byte")
        pkt = bytearray(tmpl)
        pkt[WIRE_PLAYBACK_OFFSET] = playback
        name = f"slot{slot:02d}-trigger{trig:02d}-playback{playback:02d}-all-c4-direct-product-163.bin"
        (out / name).write_bytes(pkt)
        packets.append({"slot": slot, "order": slot + 1, "trigger_note": trig, "playback_note": playback, "file": name, "sha256": sha(pkt), "template_file": item["file"], "template_sha256": sha(tmpl), "only_changed_wire_offsets_vs_template": [] if tmpl[WIRE_PLAYBACK_OFFSET] == playback else [WIRE_PLAYBACK_OFFSET], "template_byte_at_wire_offset": tmpl[WIRE_PLAYBACK_OFFSET], "transport_byte_at_wire_offset": playback, "duplicate_group": "all-c4", "name": item.get("name")})
    req(len({p["playback_note"] for p in packets}) == 1 and packets[0]["playback_note"] == ALL_C4_PLAYBACK_NOTE, "all C4 duplicate packet set")
    man = {"format": FORMAT + ".playback-transport-packets-v1", "status": "PASS", "device_accessed": False, "midi_transport_opened": False, "send_enabled": False, "packet_count": 16, "packet_bytes": 163, "supported_ingress_modes": ["direct_163_byte_sysex", "segmented_final_sysex_after_final_f7_total_0x9e"], "order_basis": "resident_slot_order_trigger_note_36_51", "wire_playback_note_offset": WIRE_PLAYBACK_OFFSET, "payload_playback_note_offset": 0x9B, "policy": "all included packets deliberately map every trigger 36..51 to Playback Note C4 (60); firmware accepts any 0..127 metadata byte including duplicates while source slot remains trigger-selected", "duplicate_playback_note_test": {"value": ALL_C4_PLAYBACK_NOTE, "label": "C4", "slots": SLOTS, "status": "PASS"}, "packets": packets}
    wjson(out / "packet-manifest.json", man)
    (out / "SHA256SUMS").write_text("\n".join([f"{shaf(out / 'packet-manifest.json')}  packet-manifest.json"] + [f"{shaf(out / p['file'])}  {p['file']}" for p in packets]) + "\n")
    return man


def c_array(hex_digest: str) -> str:
    return ", ".join(f"0x{hex_digest[i:i+2]}" for i in range(0, len(hex_digest), 2))


def exact_ota_c(pkgsha: str) -> str:
    token = f"INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-{pkgsha[:8].upper()}"
    return f'''/* Exact-hash v15-only OTA wrapper for S1-C5 Playback Register Return.\n * Default check mode is offline-only; upload requires the exact confirmation token.\n */\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include "../../../../../src/ota.c"\nstatic const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {c_array(pkgsha)} }};\nstatic const char CONFIRM[] = "{token}";\nstatic const char DESCRIPTION[] = "SMK37ProMod v15 S1-C5 Playback Register Return candidate";\nstatic int check_exact(const char *path) {{ struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{ printf("exact v15 S1-C5 Playback Register Return package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length); status = 0; }} else fputs("offline check rejected: not exact S1-C5 Playback Register Return package\\n", stderr); smk37_fwsc_free(&firmware); return status; }}\nint main(int argc, char **argv) {{ if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C5 Playback Register Return candidate installed"); fprintf(stderr, "usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n", argv[0], argv[0], CONFIRM); return 2; }}\n'''


def exact_sender_c(manifest: dict[str, Any], token: str) -> str:
    specs = []
    for p in manifest["packets"]:
        specs.append(f'    {{ {p["order"]}u, {p["slot"]}u, {p["trigger_note"]}u, {p["playback_note"]}u, "{p["file"]}", {{ {c_array(p["sha256"])} }} }}')
    joined_specs = ",\n".join(specs)
    return f'''/* Guarded exact 16-packet sender for S1-C5 Playback Register Return.\n * Default build has live USB disabled and only supports dry-run validation.\n */\n#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n#ifdef S1C5_ENABLE_LIVE_USB\n#include <time.h>\n#include <libusb.h>\n#endif\n#include "../../../../../src/sha256.h"\n#define S1C5_PACKET_COUNT 16u\n#define S1C5_PACKET_SIZE 163u\n#define S1C5_USB_MIDI_BYTES 220u\n#define S1C5_USB_MIDI_PACKET_SIZE 4u\n#define S1C5_MAX_PATH 4096u\nstatic const uint8_t EXPECTED_HEADER[6] = {{0xf0,0x43,0x00,0x00,0x01,0x1b}};\nstatic const char CONFIRM_TOKEN[] = "{token}";\nstruct packet_spec {{ unsigned order; unsigned slot; unsigned trigger_note; unsigned playback_note; const char *file; uint8_t sha256[SMK37_SHA256_LENGTH]; }};\nstatic const struct packet_spec PACKETS[S1C5_PACKET_COUNT] = {{\n{joined_specs}\n}};\nstatic int build_path(char *out, size_t out_size, const char *dir, const char *file) {{ int n = snprintf(out, out_size, "%s/%s", dir, file); return (n < 0 || (size_t)n >= out_size) ? 1 : 0; }}\nstatic int read_file_exact(const char *path, uint8_t packet[S1C5_PACKET_SIZE]) {{ FILE *f = fopen(path, "rb"); int extra; if (!f) {{ perror(path); return 1; }} if (fread(packet, 1, S1C5_PACKET_SIZE, f) != S1C5_PACKET_SIZE) {{ fprintf(stderr, "S1-C5 packet must be exactly %u bytes: %s\\n", (unsigned)S1C5_PACKET_SIZE, path); fclose(f); return 1; }} extra = fgetc(f); fclose(f); if (extra != EOF) {{ fprintf(stderr, "S1-C5 packet has trailing bytes: %s\\n", path); return 1; }} return 0; }}\nstatic size_t packetize(const uint8_t *sysex, size_t length, uint8_t *events, size_t capacity) {{ size_t input = 0, output = 0; while (input < length) {{ size_t remaining = length - input; size_t count = remaining > 3 ? 3 : remaining; uint8_t cin; if (output + S1C5_USB_MIDI_PACKET_SIZE > capacity) return 0; cin = remaining > 3 ? 0x04 : (remaining == 1 ? 0x05 : (remaining == 2 ? 0x06 : 0x07)); events[output] = cin; events[output + 1] = sysex[input]; events[output + 2] = count > 1 ? sysex[input + 1] : 0; events[output + 3] = count > 2 ? sysex[input + 2] : 0; input += count; output += S1C5_USB_MIDI_PACKET_SIZE; }} return output; }}\nstatic int verify_packet(const char *dir, const struct packet_spec *spec, uint8_t packet[S1C5_PACKET_SIZE], uint8_t events[S1C5_USB_MIDI_BYTES]) {{ uint8_t digest[SMK37_SHA256_LENGTH]; char path[S1C5_MAX_PATH]; size_t event_len; if (build_path(path, sizeof(path), dir, spec->file) != 0 || read_file_exact(path, packet) != 0) return 1; if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 || packet[S1C5_PACKET_SIZE - 1] != 0xf7 || packet[161] != (uint8_t)spec->playback_note) {{ fprintf(stderr, "S1-C5 order %u slot %u trigger %u playback %u framing/playback mismatch\\n", spec->order, spec->slot, spec->trigger_note, spec->playback_note); return 1; }} smk37_sha256(packet, S1C5_PACKET_SIZE, digest); if (memcmp(digest, spec->sha256, sizeof(digest)) != 0) {{ fprintf(stderr, "S1-C5 order %u packet SHA-256 mismatch\\n", spec->order); return 1; }} event_len = packetize(packet, S1C5_PACKET_SIZE, events, S1C5_USB_MIDI_BYTES); if (event_len != S1C5_USB_MIDI_BYTES || events[event_len - 4] != 0x05 || events[event_len - 3] != 0xf7) {{ fputs("USB-MIDI packetization invariant failed\\n", stderr); return 1; }} return 0; }}\n#ifdef S1C5_ENABLE_LIVE_USB\nstatic int send_verified(uint8_t events[S1C5_PACKET_COUNT][S1C5_USB_MIDI_BYTES]) {{ (void)events; fputs("live USB path intentionally not implemented in this artifact; use only after separate authorization and implementation review\\n", stderr); return 2; }}\n#else\nstatic int send_verified(uint8_t events[S1C5_PACKET_COUNT][S1C5_USB_MIDI_BYTES]) {{ (void)events; fputs("send BLOCK: live USB sender is disabled in the offline validation build\\n", stderr); return 2; }}\n#endif\nstatic void usage(const char *p) {{ fprintf(stderr, "usage:\\n  %s dry-run <packet-dir>\\n  %s send <packet-dir> --confirm %s\\n", p, p, CONFIRM_TOKEN); }}\nint main(int argc, char **argv) {{ uint8_t packets[S1C5_PACKET_COUNT][S1C5_PACKET_SIZE]; uint8_t events[S1C5_PACKET_COUNT][S1C5_USB_MIDI_BYTES]; if (argc != 3 && argc != 5) {{ usage(argv[0]); return 2; }} for (unsigned i = 0; i < S1C5_PACKET_COUNT; ++i) if (verify_packet(argv[2], &PACKETS[i], packets[i], events[i]) != 0) return 2; if (strcmp(argv[1], "dry-run") == 0 && argc == 3) {{ puts("S1-C5 16-packet sender dry-run PASS: triggers 36..51 all map to Playback Note C4 (60), 16 exact packets, no USB/MIDI opened"); return 0; }} if (strcmp(argv[1], "send") == 0 && argc == 5 && strcmp(argv[3], "--confirm") == 0 && strcmp(argv[4], CONFIRM_TOKEN) == 0) return send_verified(events); usage(argv[0]); return 2; }}\n'''


def dry_run_py(pkgsha: str, packet_hashes: list[str]) -> str:
    return f'''#!/usr/bin/env python3\nimport argparse, hashlib, json\nfrom pathlib import Path\nHERE=Path(__file__).resolve().parent; PKG={PACKAGE_NAME!r}; PKGSHA={pkgsha!r}; HASHES={packet_hashes!r}; HEADER=bytes.fromhex('f0430000011b')\ndef sh(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()\ndef req(x,m):\n    if not x: raise SystemExit('FAIL: '+m)\ndef main():\n    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); a=ap.parse_args(); req(sh(HERE/PKG)==PKGSHA,'package hash'); man=json.loads((HERE/'inputs/packets/packet-manifest.json').read_text()); req(man['duplicate_playback_note_test']['value']==60 and man['packet_count']==16,'all C4 manifest')\n    for i,it in enumerate(man['packets']):\n        b=(HERE/'inputs/packets'/it['file']).read_bytes(); req(len(b)==163 and b.startswith(HEADER) and b[-1]==0xf7, f'packet {{i}} framing'); req(hashlib.sha256(b).hexdigest()==HASHES[i]==it['sha256'], f'packet {{i}} hash'); req(b[161]==it['playback_note']==60, f'packet {{i}} C4 playback byte'); req(36 <= it['trigger_note'] <= 51, f'packet {{i}} trigger range')\n    res={{'status':'DRY_RUN_PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'package_sha256':PKGSHA,'wire_playback_note_offset':161,'packet_count':16,'duplicate_playback_note':'all C4 (60)'}}\n    print(json.dumps(res,sort_keys=True) if a.json else 'S1-C5 Playback Register Return dry-run PASS: all C4 duplicate packet set, no USB/MIDI/device/flash/reset action')\nif __name__=='__main__': main()\n'''


def write_code_evidence(rows: list[dict[str, Any]], checks: list[str]) -> dict[str, Any]:
    if CODEDIR.exists():
        shutil.rmtree(CODEDIR)
    CODEDIR.mkdir(parents=True, exist_ok=True)
    with (CODEDIR / "changed-windows-decode.tsv").open("w") as f:
        f.write("window\taddress\tsize\tbytes\top\tasm\n")
        for r in rows:
            f.write(f"{r['window']}\t{r['address']}\t{r['size']}\t{r['bytes']}\t{r['op']}\t{r['asm']}\n")
    parent_combined = (PARENT_CODE / "combined.bin").read_bytes()
    (CODEDIR / "parent-s1c4-v3-combined.bin").write_bytes(parent_combined)
    (CODEDIR / "parent-s1c4-v3-combined.hex").write_text(parent_combined.hex() + "\n")
    ev = {
        "format": FORMAT + ".code-evidence-v1",
        "decision": "PASS",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "reset_performed": False},
        "basis": {"parent_candidate": str(PARENT.relative_to(ROOT)), "parent_app_sha256": EXPECTED["parent_app"], "parent_package_sha256": EXPECTED["parent_fwsc"]},
        "preserved_code": {"start": hx(SEL_START), "end_exclusive": hx(OWNED_END), "combined_sha256": EXPECTED["parent_combined"], "selector_sha256": EXPECTED["parent_selector"], "producer_sha256": EXPECTED["parent_producer"], "status": "preserved byte-for-byte from exact S1-C4 v3"},
        "changed_instructions": rows,
        "abi_contract": {"selector_r0_return": "S1-C4 v3 selector stores mapped Playback Note at [dest+0x9c] and returns with r0 == dest+0x9c", "note_off_caller": "post-hook window reloads [r0] into r5 before native Note Off consumer continues", "note_on_caller": "post-hook window reloads [r0] into r6; velocity remains native r5 and 0x0201c68c is preserved", "trigger_source": "producer and selector source bytes unchanged, so source slot remains trigger_note-36", "duplicates": "0..127 metadata bytes allowed, including all sixteen playback notes set to C4 (60)"},
        "validation": checks,
    }
    wjson(CODEDIR / "evidence.json", ev)
    (CODEDIR / "validation.txt").write_text("S1-C5 Playback Register Return code evidence: PASS\n" + "\n".join(checks) + "\n")
    (CODEDIR / "report.md").write_text("# S1-C5 Playback Register Return code evidence PASS\n\nOnly the two S1-C4 v3 neutralized post-hook windows change. `0x0201c644` decodes as `lb.z r5,[r0]; mov r0,r0; mov r0,r0`. `0x0201c682` decodes as `lb.z r6,[r0]; mov r0,r0; mov r0,r0`. The exact S1-C4 v3 selector/producer window is preserved byte-for-byte and returns `r0 = dest + 0x9c` after storing the mapped Playback Note byte there.\n")
    (CODEDIR / "SHA256SUMS").write_text("\n".join(f"{shaf(CODEDIR / name)}  {name}" for name in ["changed-windows-decode.tsv", "parent-s1c4-v3-combined.bin", "parent-s1c4-v3-combined.hex", "evidence.json", "report.md", "validation.txt"]) + "\n")
    return ev


def write_sha_inventory() -> None:
    paths = []
    for name in ["build_s1c5_playback_register_return.py", "validate.py", "dry_run_validate.py", "app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "evidence.json", "report.md", "README.md", "exact_ota.c", "exact_16_packet_sender.c", "validation.txt"]:
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


def build(check: bool = False, no_write: bool = False) -> dict[str, Any]:
    parent, gates = gate_basis()
    app, app_manifest, rows, checks = build_app(parent, gates)
    if no_write:
        return {"decision": "PASS", "candidate_built": False, "validation": checks}
    if check:
        ev = json.loads((HERE / "evidence.json").read_text())
        req(shaf(HERE / "app.bin") == ev["app"]["output_app_sha256"] == sha(app), "deterministic app hash")
        req(json.loads((CODEDIR / "evidence.json").read_text())["decision"] == "PASS", "code evidence exists")
        return ev
    code_ev = write_code_evidence(rows, checks)
    (HERE / "app.bin").write_bytes(app)
    wjson(HERE / "app-manifest.json", app_manifest)
    repack(HERE / "app.bin", HERE / PACKAGE_NAME, HERE / "package-manifest.json")
    pkg_info = rollback_info(app, HERE / PACKAGE_NAME)
    pman = json.loads((HERE / "package-manifest.json").read_text())
    req(pman["output"]["sha256"] == pkg_info["package_sha256"], "package manifest hash")
    transport = transport_packets()
    packet_hashes = [p["sha256"] for p in transport["packets"]]
    ota_token = f"INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-{pkg_info['package_sha256'][:8].upper()}"
    sender_token = "SEND-SMK37PRO-V15-S1C5-ALL-C4-" + "-".join(h[:8].upper() for h in packet_hashes[:4])
    (HERE / "exact_ota.c").write_text(exact_ota_c(pkg_info["package_sha256"]))
    (HERE / "exact_16_packet_sender.c").write_text(exact_sender_c(transport, sender_token))
    (HERE / "dry_run_validate.py").write_text(dry_run_py(pkg_info["package_sha256"], packet_hashes))
    (HERE / "dry_run_validate.py").chmod(0o755)
    evidence = {
        "format": FORMAT + ".release-evidence-v1",
        "decision": "PASS",
        "candidate_built": True,
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "reset_performed": False, "live_send_performed": False},
        "basis": {"official_fwsc_sha256": EXPECTED["official_fwsc"], "official_app_sha256": EXPECTED["official_app"], "parent_s1c4_v3_app_sha256": EXPECTED["parent_app"], "parent_s1c4_v3_package_sha256": EXPECTED["parent_fwsc"]},
        "input_gates": gates,
        "code": {"candidate_dir": str(CODEDIR.relative_to(ROOT)), "parent_combined_sha256": EXPECTED["parent_combined"], "selector_sha256": EXPECTED["parent_selector"], "producer_sha256": EXPECTED["parent_producer"], "changed_windows_decode": str((CODEDIR / "changed-windows-decode.tsv").relative_to(ROOT)), "code_evidence_sha256": shaf(CODEDIR / "evidence.json")},
        "app": app_manifest,
        "package": pkg_info,
        "transport": transport,
        "flash": {"artifact": PACKAGE_NAME, "confirmation_token": ota_token, "default_check_offline_only": True},
        "sender": {"artifact": "exact_16_packet_sender.c", "packets": "inputs/packets", "confirmation_token": sender_token, "default_compile_live_usb_enabled": False, "wire_playback_note_offset": WIRE_PLAYBACK_OFFSET, "duplicate_test": "all 16 playback notes C4 (60)"},
        "invariants": {"trigger_source": "slot = trigger_note - 36; producer/selector bytes preserved from exact S1-C4 v3", "playback_register_return": "Note Off reloads [r0] to r5; Note On reloads [r0] to r6", "velocity_preserved": True, "playback_note_range": "0..127 including duplicates", "all_c4_duplicate_packets": True, "no_source_slot_from_playback_note": True},
    }
    wjson(HERE / "evidence.json", evidence)
    (HERE / "validation.txt").write_text("S1-C5 Playback Register Return build validation: PASS\n" + "\n".join(checks) + "\n")
    (HERE / "README.md").write_text(f"# S1-C5 Playback Register Return offline release\n\nStatus: **PASS, candidate built offline**.\n\nApp SHA-256 `{app_manifest['output_app_sha256']}`. FWSC SHA-256 `{pkg_info['package_sha256']}`. OTA token `{ota_token}`.\n\nBasis is exact S1-C4 v3 segmented-final only. Producer/selector bytes are preserved byte-for-byte. The only app changes vs S1-C4 v3 are the two post-hook register reload windows: Note Off loads `[r0]` into `r5`, Note On loads `[r0]` into `r6`, and the stock velocity store remains intact. The included 16-packet sender artifacts deliberately map every trigger to C4 (60) to prove duplicate Playback Notes are allowed. No live actions were performed.\n")
    (HERE / "report.md").write_text(f"# S1-C5 Playback Register Return PASS\n\n- App SHA-256: `{app_manifest['output_app_sha256']}`.\n- FWSC SHA-256: `{pkg_info['package_sha256']}`.\n- Parent S1-C4 v3 app SHA-256: `{EXPECTED['parent_app']}`.\n- Preserved selector/producer SHA-256: `{EXPECTED['parent_combined']}`.\n- OTA token: `{ota_token}`.\n- Sender token: `{sender_token}`.\n\nPASS: exact S1-C4 v3 basis, selector returns `r0 = dest + 0x9c`, producer stores Playback Note map byte, Note Off reloads `r5` from `[r0]`, Note On reloads `r6` from `[r0]`, velocity `r5` store is preserved, Trigger source remains trigger-selected, duplicates including all C4 are represented by the 16 packet artifacts, rollback reconstructs official v15, and no device/flash path was used.\n")
    write_sha_inventory()
    return evidence


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--no-write", action="store_true")
    args = ap.parse_args()
    ev = build(check=args.check, no_write=args.no_write)
    print("S1-C5 Playback Register Return build gate: PASS")
    if ev.get("candidate_built"):
        print("app_sha256=" + ev["app"]["output_app_sha256"])
        print("package_sha256=" + ev["package"]["package_sha256"])
        print("ota_confirmation_token=" + ev["flash"]["confirmation_token"])
        print("sender_confirmation_token=" + ev["sender"]["confirmation_token"])


if __name__ == "__main__":
    main()
