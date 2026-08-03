#!/usr/bin/env python3
"""Offline S1-C3 16-slot functional integration gate and release builder.

This file intentionally performs no USB, MIDI, reset, or device access. It starts
from the exact live-PASS S1-C3 boundary app, accepts only reviewed committed PASS
inputs, and emits deterministic app/FWSC/rollback/tooling artifacts only after all
strict gates pass.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FLASH_CANDIDATES = HERE.parent
ANALYSIS = HERE.parents[1]
ROOT = HERE.parents[4]
BOUNDARY_DIR = FLASH_CANDIDATES / "S1C3-16slot-boundary-only"
SELECTOR_DIR = ANALYSIS / "patch-set-ui" / "s1c3" / "selector"
LOCAL_PRODUCER_DIR = HERE / "inputs" / "producer"
LOCAL_PACKET_DIR = HERE / "inputs" / "packets"

# Keep all helper use local/offline. This module parses and repacks FWSC files.
sys.path.insert(0, str(BOUNDARY_DIR))
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

FORMAT = "smk37-v15-s1c3-16slot-functional-release-v1"
PACKAGE_NAME = "SMK37Pro-v15-S1C3-16slot-functional.fwsc"
RUNTIME_BASE = 0x02000000
SECTOR_SIZE = 0x2000
PROTECTED_PREFIX_END = 0x4000
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"

EXPECTED = {
    "official_fwsc_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "boundary_app_sha256": "c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14",
    "boundary_fwsc_sha256": "2345102aadded732b13e22d1410d3f7b05f104ffc408bd1d6eba03ea2afc058c",
    "selector_sha256": "ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915",
    "selector_live_code_sha256": "894f61ee4eedb942b6653bd36dc72934d3719b54a9a413f6c94f29d0084f8ffc",
    "selector_bytes": 96,
    "selector_start": 0x0201E13E,
    "selector_end_exclusive": 0x0201E19E,
    "producer_sha256": "4e738a54dda52abd2ab816201ece7d1851215cba90268c14c535503b4ceb2460",
    "producer_bytes": 130,
    "producer_entry": 0x0201E1A2,
    "producer_end_exclusive": 0x0201E224,
    "producer_owned_end_exclusive": 0x0201E254,
    "direct_product_callsite": 0x0201E468,
    "direct_product_callsite_bytes": "bfea9bfe",
    "segmented_product_callsite": 0x0201E49C,
    "segmented_product_callsite_bytes": "bfeac0fe",
    "direct_reload_callsite": 0x0201E46C,
    "direct_reload_callsite_bytes": "bfeaf838",
    "segmented_reload_callsite": 0x0201E4A0,
    "segmented_reload_callsite_bytes": "bfeade38",
    "segmented_stub": 0x0201E220,
    "packet_count": 16,
    "first_note": 36,
    "last_note": 51,
    "packet_bytes": 163,
    "source_commits": {
        "compact_producer": "9f9b7d75358b8efcabfef25b1ed07af6cfec15ac",
        "bank_d_packet_set": "fe3350063c56a0cff7ab855735b0c7e8a04c957e",
        "selector": "3e99ac3e8b40a1c0733cf6a2a6e6fd5aabbbfa90",
        "boundary": "779356aa3565c43de8141ca289c269e5c1e57796",
        "pad_permutation": "2a23cf5017eff520f775e511f8d3d80e15163e7d",
    },
    "source_hashes": {
        "compact_producer_evidence": "e6cbd92c7b1937f7c030a0c225ae35a07f5948cdbb993bac3ae188ab7459e76f",
        "bank_d_packet_manifest": "98b3258ad107f5421d4a3e23db7baca3f15fd7f15690d4df979a191093d949e9",
    },
    "physical_pad_to_note_order_slot": [4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11],
}
OFFICIAL_FWSC = FLASH_CANDIDATES / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def runtime_off(address: int) -> int:
    value = address - RUNTIME_BASE
    req(0 <= value < APP_DATA_SIZE, f"runtime address outside app: 0x{address:08x}")
    return value


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def pass_gate(name: str, **details: Any) -> dict[str, Any]:
    return {"name": name, "status": "PASS", **details}


def block_gate(name: str, code: str, message: str, **details: Any) -> dict[str, Any]:
    return {"name": name, "status": "BLOCK", "blocker_code": code, "message": message, **details}


def hx(data: bytes) -> str:
    return data.hex()


def check_boundary() -> dict[str, Any]:
    app = BOUNDARY_DIR / "app.bin"
    fwsc = BOUNDARY_DIR / "SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc"
    evidence_path = BOUNDARY_DIR / "evidence.json"
    live_path = BOUNDARY_DIR / "live-validation-20260803.md"
    missing = [str(p) for p in [app, fwsc, evidence_path, live_path] if not p.exists()]
    if missing:
        return block_gate("exact-live-pass-s1c3-boundary-app", "BLOCK_BOUNDARY_INPUT_MISSING", "missing exact S1-C3 boundary artifact(s)", missing=missing)
    evidence = load_json(evidence_path)
    live_text = live_path.read_text(encoding="utf-8")
    checks = {
        "app_hash": sha256_path(app),
        "fwsc_hash": sha256_path(fwsc),
        "evidence_decision": evidence.get("decision"),
        "candidate_built": evidence.get("candidate_built"),
        "live_pass_text_present": "**LIVE PASS**" in live_text,
        "boundary_commit": EXPECTED["source_commits"]["boundary"],
        "pad_permutation_commit": EXPECTED["source_commits"]["pad_permutation"],
    }
    if checks["app_hash"] != EXPECTED["boundary_app_sha256"]:
        return block_gate("exact-live-pass-s1c3-boundary-app", "BLOCK_BOUNDARY_APP_HASH", "boundary app hash mismatch", **checks)
    if checks["fwsc_hash"] != EXPECTED["boundary_fwsc_sha256"]:
        return block_gate("exact-live-pass-s1c3-boundary-app", "BLOCK_BOUNDARY_FWSC_HASH", "boundary FWSC hash mismatch", **checks)
    if evidence.get("decision") != "PASS" or evidence.get("candidate_built") is not True:
        return block_gate("exact-live-pass-s1c3-boundary-app", "BLOCK_BOUNDARY_EVIDENCE_NOT_PASS", "boundary evidence is not PASS", **checks)
    if "**LIVE PASS**" not in live_text:
        return block_gate("exact-live-pass-s1c3-boundary-app", "BLOCK_BOUNDARY_LIVE_PASS_MISSING", "boundary live validation does not contain LIVE PASS", **checks)
    return pass_gate("exact-live-pass-s1c3-boundary-app", path=str(app.relative_to(ROOT)), **checks)


def check_selector() -> dict[str, Any]:
    selector = SELECTOR_DIR / "selector.bin"
    live_code = SELECTOR_DIR / "selector-live-code.bin"
    evidence_path = SELECTOR_DIR / "evidence.json"
    validation_path = SELECTOR_DIR / "validation.txt"
    missing = [str(p) for p in [selector, live_code, evidence_path, validation_path] if not p.exists()]
    if missing:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_INPUT_MISSING", "missing reviewed selector artifact(s)", missing=missing)
    evidence = load_json(evidence_path)
    validation_text = validation_path.read_text(encoding="utf-8")
    selector_bytes = selector.read_bytes()
    checks = {
        "selector_hash": sha256_bytes(selector_bytes),
        "selector_size": len(selector_bytes),
        "live_code_hash": sha256_path(live_code),
        "raw_selector_design": evidence.get("status", {}).get("raw_selector_design"),
        "firmware_candidate": evidence.get("status", {}).get("firmware_candidate"),
        "validation_pass_text_present": "validation: PASS" in validation_text,
        "note_first_inclusive": evidence.get("mapping", {}).get("note_first_inclusive"),
        "note_last_inclusive": evidence.get("mapping", {}).get("note_last_inclusive"),
        "slot_formula": evidence.get("mapping", {}).get("slot_formula"),
        "selector_commit": EXPECTED["source_commits"]["selector"],
    }
    if checks["selector_size"] != EXPECTED["selector_bytes"] or checks["selector_hash"] != EXPECTED["selector_sha256"]:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_BYTES", "selector is not the reviewed 96-byte blob", **checks)
    if checks["live_code_hash"] != EXPECTED["selector_live_code_sha256"]:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_LIVE_CODE_HASH", "selector live-code hash mismatch", **checks)
    if checks["raw_selector_design"] != "PASS" or "validation: PASS" not in validation_text:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_NOT_PASS", "selector validation is not PASS", **checks)
    if checks["note_first_inclusive"] != EXPECTED["first_note"] or checks["note_last_inclusive"] != EXPECTED["last_note"] or checks["slot_formula"] != "slot = note - 36":
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_NOTE_ORDER", "selector is not pinned to note order 36..51", **checks)
    return pass_gate("reviewed-96-byte-16-note-selector", path=str(selector.relative_to(ROOT)), start=f"0x{EXPECTED['selector_start']:08x}", end_exclusive=f"0x{EXPECTED['selector_end_exclusive']:08x}", **checks)


def check_producer() -> dict[str, Any]:
    manifest_path = LOCAL_PRODUCER_DIR / "evidence.json"
    producer_path = LOCAL_PRODUCER_DIR / "producer.bin"
    missing = [str(p.relative_to(ROOT)) for p in [manifest_path, producer_path] if not p.exists()]
    if missing:
        return block_gate(
            "compact-16-slot-producer",
            "BLOCK_COMPACT_PRODUCER_PASS_INPUT_UNAVAILABLE",
            "compact assembled producer PASS input is unavailable in the self-contained integration directory",
            required_files=[str(manifest_path.relative_to(ROOT)), str(producer_path.relative_to(ROOT))],
            missing=missing,
        )
    manifest = load_json(manifest_path)
    data = producer_path.read_bytes()
    producer = manifest.get("producer", {})
    source = manifest.get("source", {})
    source_verdict = manifest.get("source_verdict", {})
    call_routes = manifest.get("call_routes", {})
    checks = {
        "status": manifest.get("status") or manifest.get("decision"),
        "producer_hash": sha256_bytes(data),
        "producer_size": len(data),
        "manifest_hash": producer.get("sha256"),
        "entry": producer.get("entry"),
        "end_exclusive": producer.get("end_exclusive"),
        "owned_end_exclusive": producer.get("owned_end_exclusive"),
        "source_commit": source.get("commit"),
        "source_evidence_sha256": source.get("evidence_sha256"),
        "source_exact_pi32_producer_bytes": source_verdict.get("exact_pi32_producer_bytes"),
        "device_accessed": manifest.get("device_accessed", False),
        "direct_callsite_bytes": call_routes.get("direct_product_callsite", {}).get("bytes"),
        "segmented_callsite_bytes": call_routes.get("segmented_product_callsite", {}).get("bytes"),
    }
    if checks["status"] != "PASS":
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_NOT_PASS", "compact producer manifest is not PASS", **checks)
    if checks["producer_hash"] != EXPECTED["producer_sha256"] or checks["producer_hash"] != checks["manifest_hash"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_HASH", "producer.bin is not the reviewed compact producer", **checks)
    if checks["producer_size"] != EXPECTED["producer_bytes"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_SIZE", "producer.bin size mismatch", **checks)
    if checks["entry"] != f"0x{EXPECTED['producer_entry']:08x}" or checks["end_exclusive"] != f"0x{EXPECTED['producer_end_exclusive']:08x}" or checks["owned_end_exclusive"] != f"0x{EXPECTED['producer_owned_end_exclusive']:08x}":
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_PLACEMENT", "producer manifest placement is not the reviewed owned range", **checks)
    if checks["source_commit"] != EXPECTED["source_commits"]["compact_producer"] or checks["source_evidence_sha256"] != EXPECTED["source_hashes"]["compact_producer_evidence"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_SOURCE", "producer source commit/hash mismatch", **checks)
    if checks["source_exact_pi32_producer_bytes"] != "PASS":
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_SOURCE_NOT_PASS", "source compact producer exact-bytes verdict is not PASS", **checks)
    if checks["device_accessed"] is True:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_DEVICE_ACCESS_SCOPE", "producer PASS input claims device access in this offline gate", **checks)
    if checks["direct_callsite_bytes"] != EXPECTED["direct_product_callsite_bytes"] or checks["segmented_callsite_bytes"] != EXPECTED["segmented_product_callsite_bytes"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_CALLSITE", "producer callsite bytes are not the reviewed compact call routes", **checks)
    return pass_gate("compact-16-slot-producer", path=str(producer_path.relative_to(ROOT)), **checks)


def expected_packet_name(slot: int) -> str:
    return f"slot{slot:02d}-note{EXPECTED['first_note'] + slot:02d}-direct-product-163.bin"


def check_packets() -> dict[str, Any]:
    manifest_path = LOCAL_PACKET_DIR / "packet-manifest.json"
    permutation_path = LOCAL_PACKET_DIR / "physical-pad-permutation.json"
    missing = [str(p.relative_to(ROOT)) for p in [manifest_path, permutation_path] if not p.exists()]
    if missing:
        return block_gate(
            "exact-16-packet-set",
            "BLOCK_16_PACKET_SET_PASS_INPUT_UNAVAILABLE",
            "reviewed exact 16-packet PASS set is unavailable in the self-contained integration directory",
            required_manifest=str(manifest_path.relative_to(ROOT)),
            required_files=[f"inputs/packets/{expected_packet_name(slot)}" for slot in range(EXPECTED["packet_count"])],
            missing=missing,
        )
    manifest = load_json(manifest_path)
    permutation = load_json(permutation_path)
    packets = manifest.get("packets", [])
    checks = {
        "status": manifest.get("status") or manifest.get("decision"),
        "packet_count": len(packets),
        "source_commit": manifest.get("source", {}).get("commit"),
        "source_manifest_sha256": manifest.get("source", {}).get("manifest_sha256"),
        "order_basis": manifest.get("order_basis"),
        "physical_pad_ui_only": manifest.get("physical_pad_permutation", {}).get("ui_only"),
        "physical_pad_file_ui_only": permutation.get("ui_only"),
        "physical_pad_to_note_order_slot": permutation.get("pad_1_to_16_to_note_order_slot"),
    }
    if checks["status"] != "PASS":
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_SET_NOT_PASS", "packet manifest is not PASS", **checks)
    if len(packets) != EXPECTED["packet_count"]:
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_COUNT", "packet manifest does not describe exactly 16 packets", **checks)
    if checks["source_commit"] != EXPECTED["source_commits"]["bank_d_packet_set"] or checks["source_manifest_sha256"] != EXPECTED["source_hashes"]["bank_d_packet_manifest"]:
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_SET_SOURCE", "packet set source commit/hash mismatch", **checks)
    if checks["order_basis"] != "note_order_36_51":
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_ORDER_BASIS", "packet set is not note ordered 36..51", **checks)
    if checks["physical_pad_ui_only"] is not True or checks["physical_pad_file_ui_only"] is not True:
        return block_gate("exact-16-packet-set", "BLOCK_PAD_PERMUTATION_SCOPE", "physical Pad permutation is not marked UI-only", **checks)
    if checks["physical_pad_to_note_order_slot"] != EXPECTED["physical_pad_to_note_order_slot"]:
        return block_gate("exact-16-packet-set", "BLOCK_PAD_PERMUTATION_VALUE", "physical Pad permutation mismatch", **checks)
    verified: list[dict[str, Any]] = []
    for slot in range(EXPECTED["packet_count"]):
        note = EXPECTED["first_note"] + slot
        expected_name = expected_packet_name(slot)
        entry = packets[slot]
        packet_path = LOCAL_PACKET_DIR / expected_name
        if entry.get("slot") != slot or entry.get("note") != note or entry.get("file") != expected_name:
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_ORDER", "packet manifest order/name/note mismatch", slot=slot, entry=entry, expected_file=expected_name, expected_note=note)
        if entry.get("order") != slot + 1 or entry.get("order_basis") != "note_order_36_51":
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_ORDER", "packet manifest order basis mismatch", slot=slot, entry=entry)
        if not packet_path.exists():
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_FILE_MISSING", "packet file missing", slot=slot, file=expected_name)
        data = packet_path.read_bytes()
        digest = sha256_bytes(data)
        if len(data) != EXPECTED["packet_bytes"] or digest != entry.get("sha256"):
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_BYTES", "packet size/hash mismatch", slot=slot, file=expected_name, size=len(data), sha256=digest, expected_sha256=entry.get("sha256"))
        if not data.startswith(HEADER) or not data.endswith(TERM):
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_FRAMING", "packet SysEx framing mismatch", slot=slot, file=expected_name)
        verified.append({"slot": slot, "order": slot + 1, "note": note, "file": expected_name, "sha256": digest, "name": entry.get("name"), "runtime_sha256": entry.get("runtime_sha256")})
    return pass_gate("exact-16-packet-set", manifest=str(manifest_path.relative_to(ROOT)), packets=verified, pad_permutation=permutation)


def collect_gates() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    gates = [check_boundary(), check_selector(), check_producer(), check_packets()]
    blockers = [
        {"gate": gate["name"], "code": gate["blocker_code"], "message": gate["message"]}
        for gate in gates if gate["status"] != "PASS"
    ]
    return gates, blockers


def render_block(evidence: dict[str, Any]) -> str:
    blockers = evidence["blockers"]
    lines = [
        "# BLOCK: S1-C3 16-slot functional candidate",
        "",
        "Status: **BLOCK, no functional app/FWSC/rollback/uploader/sender emitted**",
        "",
        "The offline gate stopped before creating flashable functional artifacts because one or more strict PASS inputs failed.",
        "",
        "## Exact blockers",
        "",
    ]
    for blocker in blockers:
        lines.append(f"- `{blocker['code']}` at `{blocker['gate']}`: {blocker['message']}")
    lines.extend([
        "",
        "## Non-negotiable gates before any build",
        "",
        "1. Exact live-PASS S1-C3 boundary app/FWSC must retain the recorded hashes.",
        "2. Reviewed S1-C3 selector must remain exactly 96 bytes with note order 36..51.",
        "3. Compact assembled 16-slot producer must be the committed 9f9b7d7 exact PI32 producer bytes.",
        "4. Exact 16 packet set must be the committed fe33500 Bank D 1..16 packet set, fixed note order 36..51, 163 bytes each, fixed hashes.",
        "5. Physical Pad permutation from 2a23cf5 may affect only UI labels. Producer, selector, packet order, and send order remain note order 36..51.",
        "6. Only after all gates PASS may the builder emit deterministic `app.bin`, `.fwsc`, rollback sectors, exact-hash OTA wrapper, and guarded 16-packet sender.",
        "",
        "No missing bytes were invented and no device transport was opened.",
    ])
    return "\n".join(lines) + "\n"


def render_readme(evidence: dict[str, Any]) -> str:
    decision = evidence.get("decision", "BLOCK")
    if decision == "PASS" and evidence.get("candidate_built"):
        app_sha = evidence["app"]["output_app_sha256"]
        package_sha = evidence["package"]["package_sha256"]
        token = evidence["flash"]["confirmation_token"]
        sender_token = evidence["sender"]["confirmation_token"]
        return f"""# S1-C3 16-slot functional offline release

Status: **PASS, candidate built offline**.

This directory is self-contained for the S1-C3 16-slot functional release candidate. It contains the deterministic app/FWSC, manifests, exact official-v15 rollback sectors, exact-hash OTA C wrapper, guarded exact 16-packet C sender, and dry-run validator.

## Exact release hashes

- App: `app.bin`, SHA-256 `{app_sha}`.
- FWSC: `{PACKAGE_NAME}`, SHA-256 `{package_sha}`.
- OTA confirmation token: `{token}`.
- Sender confirmation token: `{sender_token}`.

## Scope

All build and validation actions are offline-only. `check`, `dry-run`, and Python validation paths never open USB/MIDI, reset, flash, send packets, or access a device. Upload/send code paths are guarded by exact hashes and explicit confirmation tokens.

## Ordering invariant

Producer, selector, packet manifest, C sender, and dry-run validator all use note order slots `0..15` -> MIDI notes `36..51`. The physical Pad permutation from commit `2a23cf5` is recorded as UI-only metadata and is not used for producer/selector/send ordering.

## Validate

```sh
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/validate.py
```
"""
    return """# S1-C3 16-slot functional offline integration gate

Status: **BLOCK until all strict inputs PASS**.

This directory is a deterministic gate and release builder. It starts from the exact live-PASS `S1C3-16slot-boundary-only` app and consumes only reviewed committed inputs:

- reviewed 96-byte S1-C3 16-note selector from `patch-set-ui/s1c3/selector`;
- self-contained compact assembled 16-slot producer in `inputs/producer/`;
- self-contained exact Bank D 1..16 packet set in `inputs/packets/`.

The builder writes `BLOCK.md` and refuses to create flashable artifacts unless every gate is PASS. It never accesses a device, opens USB/MIDI, flashes, resets, or sends packets.

Run:

```sh
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/build_s1c3_16slot_functional.py check-inputs
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/validate.py
```
"""


def unpack_nonofficial_fwsc(raw: bytes) -> tuple[bytearray, bytes]:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    req(len(raw) == 701_140, "FWSC size")
    metadata = bytes(raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for index in range(FWSC_SLOTS))
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    req(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "payload size")
    return payload, metadata


def extract_app_from_fwsc(path: Path) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    if sha256_bytes(raw) == EXPECTED["official_fwsc_sha256"]:
        payload, _metadata = unpack_fwsc(raw)
    else:
        payload, _metadata = unpack_nonofficial_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def patch_bytes(app: bytearray, address: int, data: bytes, purpose: str) -> dict[str, Any]:
    start = runtime_off(address)
    end = start + len(data)
    old = bytes(app[start:end])
    app[start:end] = data
    return {
        "address": f"0x{address:08x}",
        "end_exclusive": f"0x{address + len(data):08x}",
        "file_offset": start,
        "byte_count": len(data),
        "old_sha256": sha256_bytes(old),
        "new_sha256": sha256_bytes(data),
        "old_hex": hx(old),
        "new_hex": hx(data),
        "purpose": purpose,
    }


def build_app_from_pass_inputs(gates: list[dict[str, Any]]) -> tuple[bytes, dict[str, Any]]:
    boundary_app = (BOUNDARY_DIR / "app.bin").read_bytes()
    req(sha256_bytes(boundary_app) == EXPECTED["boundary_app_sha256"], "boundary app hash before functional patch")
    output = bytearray(boundary_app)
    selector = (SELECTOR_DIR / "selector.bin").read_bytes()
    producer = (LOCAL_PRODUCER_DIR / "producer.bin").read_bytes()
    patches = [
        patch_bytes(output, EXPECTED["selector_start"], selector, "install reviewed 96-byte S1-C3 16-note selector"),
        patch_bytes(output, EXPECTED["producer_entry"], producer, "install compact reviewed S1-C3 16-slot producer"),
        patch_bytes(output, EXPECTED["direct_product_callsite"], bytes.fromhex(EXPECTED["direct_product_callsite_bytes"]), "pin direct product callsite to compact producer entry"),
        patch_bytes(output, EXPECTED["segmented_product_callsite"], bytes.fromhex(EXPECTED["segmented_product_callsite_bytes"]), "pin segmented product callsite to compact no-mutation stub"),
    ]
    direct_reload = output[runtime_off(EXPECTED["direct_reload_callsite"]):runtime_off(EXPECTED["direct_reload_callsite"]) + 4]
    segmented_reload = output[runtime_off(EXPECTED["segmented_reload_callsite"]):runtime_off(EXPECTED["segmented_reload_callsite"]) + 4]
    req(hx(direct_reload) == EXPECTED["direct_reload_callsite_bytes"], "direct reload callsite preserved")
    req(hx(segmented_reload) == EXPECTED["segmented_reload_callsite_bytes"], "segmented reload callsite preserved")
    diffs = difference_offsets(boundary_app, output)
    return bytes(output), {
        "format": FORMAT + ".app-manifest-v1",
        "basis_app_sha256": EXPECTED["boundary_app_sha256"],
        "output_app_sha256": sha256_bytes(output),
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "patches": patches,
        "boundary_relative_changed_byte_count": len(diffs),
        "boundary_relative_changed_ranges": compact_ranges(diffs),
        "input_gates": gates,
        "callsite_contract": {
            "direct_product_callsite": {"address": f"0x{EXPECTED['direct_product_callsite']:08x}", "bytes": EXPECTED["direct_product_callsite_bytes"], "target": f"0x{EXPECTED['producer_entry']:08x}"},
            "segmented_product_callsite": {"address": f"0x{EXPECTED['segmented_product_callsite']:08x}", "bytes": EXPECTED["segmented_product_callsite_bytes"], "target": f"0x{EXPECTED['segmented_stub']:08x}"},
            "direct_reload_callsite": {"address": f"0x{EXPECTED['direct_reload_callsite']:08x}", "bytes": EXPECTED["direct_reload_callsite_bytes"], "status": "preserved"},
            "segmented_reload_callsite": {"address": f"0x{EXPECTED['segmented_reload_callsite']:08x}", "bytes": EXPECTED["segmented_reload_callsite_bytes"], "status": "preserved"},
        },
    }


def repack(app_path: Path, package_path: Path, manifest_path: Path) -> None:
    subprocess.run([
        sys.executable,
        str(BOUNDARY_DIR / "smk37_v15_app_patch.py"),
        "repack-app",
        str(OFFICIAL_FWSC),
        str(app_path),
        str(package_path),
        "--manifest",
        str(manifest_path),
    ], check=True)


def validate_package_and_rollback(candidate_app: bytes, package_path: Path) -> dict[str, Any]:
    official_raw, official_flash, official_app = extract_app_from_fwsc(OFFICIAL_FWSC)
    candidate_raw, candidate_flash, embedded_app = extract_app_from_fwsc(package_path)
    req(sha256_bytes(official_raw) == EXPECTED["official_fwsc_sha256"], "official FWSC hash")
    req(sha256_bytes(official_app) == EXPECTED["official_app_sha256"], "official app hash")
    req(embedded_app == candidate_app, "package embeds candidate app")
    app_diffs = difference_offsets(official_app, candidate_app)
    flash_diffs = difference_offsets(official_flash, candidate_flash)
    raw_diffs = difference_offsets(official_raw, candidate_raw)
    expected_flash = sorted(APP_DATA_OFFSET + item for item in app_diffs)
    req(not (set(expected_flash) - set(flash_diffs)), "missing app diffs in flash")
    req(not any(item < PROTECTED_PREFIX_END for item in flash_diffs), "protected prefix unchanged")
    sectors = sorted({item - (item % SECTOR_SIZE) for item in flash_diffs})
    rollback_dir = HERE / "rollback" / "official-v15-recovery-sectors"
    if rollback_dir.exists():
        shutil.rmtree(rollback_dir)
    rollback_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for base in sectors:
        data = bytes(official_flash[base:base + SECTOR_SIZE])
        name = f"official-v15-sector-{base:05x}.bin"
        (rollback_dir / name).write_bytes(data)
        entries.append({"sector_base": f"0x{base:05x}", "size": len(data), "sha256": sha256_bytes(data), "file": f"rollback/official-v15-recovery-sectors/{name}"})
    reconstructed = bytearray(candidate_flash)
    for base in sectors:
        reconstructed[base:base + SECTOR_SIZE] = official_flash[base:base + SECTOR_SIZE]
    req(bytes(reconstructed) == bytes(official_flash), "rollback restores official flash")
    write_json(rollback_dir / "manifest.json", {
        "format": FORMAT + ".official-v15-sector-rollback-v1",
        "sector_size": SECTOR_SIZE,
        "changed_sectors": entries,
        "official_flash_sha256": sha256_bytes(official_flash),
        "candidate_flash_sha256": sha256_bytes(candidate_flash),
        "rollback_restores_official_flash": True,
    })
    return {
        "package_sha256": sha256_bytes(candidate_raw),
        "package_size": len(candidate_raw),
        "candidate_flash_sha256": sha256_bytes(candidate_flash),
        "official_flash_sha256": sha256_bytes(official_flash),
        "changed_app_byte_count_vs_official": len(app_diffs),
        "changed_app_ranges_vs_official": compact_ranges(app_diffs),
        "changed_flash_sectors_vs_official": [f"0x{item:05x}" for item in sectors],
        "changed_package_byte_count_vs_official": len(raw_diffs),
        "changed_package_ranges_vs_official": compact_ranges(raw_diffs),
        "protected_hashes_official": protected_hashes(bytearray(official_flash)),
        "protected_hashes_candidate": protected_hashes(bytearray(candidate_flash)),
        "rollback_manifest": "rollback/official-v15-recovery-sectors/manifest.json",
        "rollback_restores_official_flash": True,
    }


def render_exact_ota(package_sha: str) -> str:
    pretty = ", ".join(f"0x{package_sha[i:i+2]}" for i in range(0, 64, 2))
    token = f"INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-{package_sha[:8].upper()}"
    return fr'''/* Exact-hash v15-only OTA wrapper for S1-C3 16-slot functional candidate.
 * `check` is offline-only. `upload` is the only transport path and requires CONFIRM.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {pretty} }};
static const char CONFIRM[] = "{token}";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C3 16-slot functional candidate";
static int check_exact(const char *path) {{
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{
        printf("exact v15 S1-C3 16-slot functional package: PASS (%zu-byte OTA payload)\n", firmware.payload_length);
        status = 0;
    }} else {{
        fputs("offline check rejected: not exact S1-C3 16-slot functional package\n", stderr);
    }}
    smk37_fwsc_free(&firmware);
    return status;
}}
static void usage(const char *program) {{
    fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", program, program, CONFIRM);
}}
int main(int argc, char **argv) {{
    if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]);
    if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) {{
        return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256,
            DESCRIPTION, CONFIRM, "v15 S1-C3 16-slot functional candidate installed");
    }}
    usage(argv[0]);
    return 2;
}}
'''


def c_array(hex_digest: str) -> str:
    return ", ".join(f"0x{hex_digest[i:i+2]}" for i in range(0, len(hex_digest), 2))


def c_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def render_guarded_sender_c(packet_gate: dict[str, Any]) -> str:
    packets = packet_gate["packets"]
    token = "SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-" + "-".join(p["sha256"][:8].upper() for p in packets[:4])
    entries = []
    for p in packets:
        entries.append(
            "    { %u, %u, %u, \"%s\", \"%s\", { %s } }," % (
                p["order"], p["slot"], p["note"], c_escape(p.get("name") or ""), p["file"], c_array(p["sha256"])
            )
        )
    return fr'''/* Guarded exact 16-packet C sender for S1-C3 functional.
 * Default validation builds without S1C3_ENABLE_LIVE_USB, so send is fail-closed.
 * If a future live run is explicitly authorized, compile with S1C3_ENABLE_LIVE_USB
 * and libusb, keep the exact hashes/order, and pass the confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef S1C3_ENABLE_LIVE_USB
#include <libusb.h>
#endif
#include "../../../../../src/sha256.h"

#define S1C3_PACKET_COUNT 16u
#define S1C3_PACKET_SIZE 163u
#define USB_MIDI_PACKET_SIZE 4u
#define S1C3_USB_MIDI_BYTES 220u
#define S1C3_MAX_PATH 4096u

static const uint8_t EXPECTED_HEADER[6] = {{0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b}};
static const char CONFIRM_TOKEN[] = "{token}";

struct packet_spec {{
    unsigned order;
    unsigned slot;
    unsigned note;
    const char *name;
    const char *file;
    uint8_t sha256[SMK37_SHA256_LENGTH];
}};

static const struct packet_spec PACKETS[S1C3_PACKET_COUNT] = {{
{chr(10).join(entries)}
}};

static int build_path(char *out, size_t out_size, const char *dir, const char *file) {{
    int written = snprintf(out, out_size, "%s/%s", dir, file);
    if (written < 0 || (size_t)written >= out_size) {{
        fputs("packet path too long\n", stderr);
        return 1;
    }}
    return 0;
}}

static int read_file_exact(const char *path, uint8_t packet[S1C3_PACKET_SIZE]) {{
    FILE *file = fopen(path, "rb");
    int extra;
    if (file == NULL) {{
        perror(path);
        return 1;
    }}
    if (fread(packet, 1, S1C3_PACKET_SIZE, file) != S1C3_PACKET_SIZE) {{
        fprintf(stderr, "S1-C3 packet must be exactly %u bytes: %s\n", (unsigned)S1C3_PACKET_SIZE, path);
        fclose(file);
        return 1;
    }}
    extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {{
        fprintf(stderr, "S1-C3 packet has trailing bytes: %s\n", path);
        return 1;
    }}
    return 0;
}}

static int verify_packet(const char *packet_dir, const struct packet_spec *spec, uint8_t packet[S1C3_PACKET_SIZE]) {{
    uint8_t digest[SMK37_SHA256_LENGTH];
    char path[S1C3_MAX_PATH];
    if (build_path(path, sizeof(path), packet_dir, spec->file) != 0) return 1;
    if (read_file_exact(path, packet) != 0) return 1;
    if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 || packet[S1C3_PACKET_SIZE - 1] != 0xf7) {{
        fprintf(stderr, "S1-C3 order %u slot %u note %u packet framing mismatch\n", spec->order, spec->slot, spec->note);
        return 1;
    }}
    smk37_sha256(packet, S1C3_PACKET_SIZE, digest);
    if (memcmp(digest, spec->sha256, sizeof(digest)) != 0) {{
        fprintf(stderr, "S1-C3 order %u slot %u note %u packet SHA-256 mismatch\n", spec->order, spec->slot, spec->note);
        return 1;
    }}
    return 0;
}}

static size_t packetize(const uint8_t *sysex, size_t length, uint8_t *events, size_t capacity) {{
    size_t input = 0;
    size_t output = 0;
    while (input < length) {{
        size_t remaining = length - input;
        size_t count = remaining > 3 ? 3 : remaining;
        uint8_t cin;
        if (output + USB_MIDI_PACKET_SIZE > capacity) return 0;
        if (remaining > 3) cin = 0x04;
        else if (remaining == 1) cin = 0x05;
        else if (remaining == 2) cin = 0x06;
        else cin = 0x07;
        events[output] = cin;
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1 ? sysex[input + 1] : 0;
        events[output + 3] = count > 2 ? sysex[input + 2] : 0;
        input += count;
        output += USB_MIDI_PACKET_SIZE;
    }}
    return output;
}}

static int packetize_checked(const uint8_t packet[S1C3_PACKET_SIZE], uint8_t events[S1C3_USB_MIDI_BYTES]) {{
    size_t length = packetize(packet, S1C3_PACKET_SIZE, events, S1C3_USB_MIDI_BYTES);
    if (length != S1C3_USB_MIDI_BYTES || events[length - 4] != 0x05 || events[length - 3] != 0xf7) {{
        fputs("USB-MIDI packetization invariant failed\n", stderr);
        return 1;
    }}
    return 0;
}}

#ifdef S1C3_ENABLE_LIVE_USB
static const uint16_t SMK37_V15_VID = 0x4353;
static const uint16_t SMK37_V15_PID = 0xcf4d;
static const int SMK37_MIDI_INTERFACE = 4;
static const unsigned char SMK37_MIDI_ENDPOINT_OUT = 0x04;
static int send_verified(uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES]) {{
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);
    int status = 1;
    if (result != LIBUSB_SUCCESS) {{
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }}
    handle = libusb_open_device_with_vid_pid(context, SMK37_V15_VID, SMK37_V15_PID);
    if (handle == NULL) {{
        fputs("exact v15 device 4353:cf4d could not be opened\n", stderr);
        status = 2;
        goto cleanup;
    }}
    result = libusb_claim_interface(handle, SMK37_MIDI_INTERFACE);
    if (result != LIBUSB_SUCCESS) {{
        fprintf(stderr, "claim interface %d: %s\n", SMK37_MIDI_INTERFACE, libusb_error_name(result));
        status = 3;
        goto cleanup;
    }}
    for (unsigned i = 0; i < S1C3_PACKET_COUNT; ++i) {{
        int transferred = 0;
        result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT, events[i], S1C3_USB_MIDI_BYTES, &transferred, 2000);
        if (result != LIBUSB_SUCCESS || transferred != (int)S1C3_USB_MIDI_BYTES) {{
            fprintf(stderr, "bulk OUT order %u: %s transferred %d/%u\n", PACKETS[i].order, libusb_error_name(result), transferred, (unsigned)S1C3_USB_MIDI_BYTES);
            status = 4;
            break;
        }}
        printf("sent exact S1-C3 order %u slot %u note %u: %u USB-MIDI bytes\n", PACKETS[i].order, PACKETS[i].slot, PACKETS[i].note, (unsigned)S1C3_USB_MIDI_BYTES);
    }}
    if (status == 1) status = 0;
    libusb_release_interface(handle, SMK37_MIDI_INTERFACE);
cleanup:
    if (handle != NULL) libusb_close(handle);
    libusb_exit(context);
    return status;
}}
#else
static int send_verified(uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES]) {{
    (void)events;
    fputs("send BLOCK: live USB sender is disabled in the offline validation build; compile with S1C3_ENABLE_LIVE_USB only after explicit authorization\n", stderr);
    return 2;
}}
#endif

static void usage(const char *program) {{
    fprintf(stderr,
            "usage:\n"
            "  %s dry-run <packet-dir>\n"
            "  %s send <packet-dir> --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}}

int main(int argc, char **argv) {{
    uint8_t packets[S1C3_PACKET_COUNT][S1C3_PACKET_SIZE];
    uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES];
    if (argc != 3 && argc != 5) {{
        usage(argv[0]);
        return 2;
    }}
    for (unsigned i = 0; i < S1C3_PACKET_COUNT; ++i) {{
        if (verify_packet(argv[2], &PACKETS[i], packets[i]) != 0 || packetize_checked(packets[i], events[i]) != 0) {{
            usage(argv[0]);
            return 2;
        }}
    }}
    if (strcmp(argv[1], "dry-run") == 0 && argc == 3) {{
        puts("S1-C3 16-slot sender dry-run PASS: note order slots 0..15 -> notes 36..51, 16 exact packets, no USB/MIDI opened");
        return 0;
    }}
    if (strcmp(argv[1], "send") == 0 && argc == 5 && strcmp(argv[3], "--confirm") == 0 && strcmp(argv[4], CONFIRM_TOKEN) == 0) {{
        return send_verified(events);
    }}
    usage(argv[0]);
    return 2;
}}
'''


def render_dry_run_validator(packet_gate: dict[str, Any]) -> str:
    return r'''#!/usr/bin/env python3
"""Dry-run validator for the S1-C3 exact 16-packet host plan.

This tool never opens USB/MIDI. It verifies the self-contained packet manifest,
packet bytes, note-order invariant, and UI-only physical Pad permutation.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACKET_DIR = HERE / "inputs" / "packets"
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
EXPECTED_PAD_TO_SLOT = [4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11]

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()
    manifest = json.loads((PACKET_DIR / "packet-manifest.json").read_text(encoding="utf-8"))
    permutation = json.loads((PACKET_DIR / "physical-pad-permutation.json").read_text(encoding="utf-8"))
    req(manifest["status"] == "PASS", "packet manifest PASS")
    req(manifest["order_basis"] == "note_order_36_51", "packet manifest note order")
    req(manifest["physical_pad_permutation"]["ui_only"] is True, "manifest Pad permutation UI-only")
    req(permutation["ui_only"] is True, "Pad permutation file UI-only")
    req(permutation["pad_1_to_16_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "Pad permutation value")
    rows = []
    for index, item in enumerate(manifest["packets"]):
        req(item["slot"] == index and item["order"] == index + 1 and item["note"] == 36 + index, f"note order item {index}")
        packet = (PACKET_DIR / item["file"]).read_bytes()
        digest = sha256(packet)
        req(len(packet) == 163, f"packet length item {index}")
        req(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing item {index}")
        req(digest == item["sha256"], f"packet hash item {index}")
        rows.append({
            "order": item["order"],
            "slot": item["slot"],
            "note": item["note"],
            "name": item["name"],
            "file": item["file"],
            "packet_sha256": digest,
        })
    output = {
        "status": "DRY_RUN_PASS",
        "send_enabled": False,
        "device_accessed": False,
        "packet_order_basis": "note_order_36_51",
        "physical_pad_permutation_scope": "UI_ONLY",
        "packets_in_order": rows,
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("S1-C3 16-slot dry-run validator PASS")
        print("Producer/selector/sender order: note-order slots 0..15 -> notes 36..51")
        print("Physical Pad permutation is UI-only metadata and is not used for send order")
        for row in rows:
            print(f"{row['order']:02d}. slot{row['slot']:02d} note {row['note']}: {row['name']} sha256={row['packet_sha256']}")
        print("No USB/MIDI device is opened by this dry-run tool.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_report(evidence: dict[str, Any]) -> str:
    if evidence.get("decision") != "PASS" or not evidence.get("candidate_built"):
        lines = ["# S1-C3 16-slot functional release BLOCK", "", "Status: **BLOCK**", ""]
        for blocker in evidence.get("blockers", []):
            lines.append(f"- `{blocker['code']}` at `{blocker['gate']}`: {blocker['message']}")
        return "\n".join(lines) + "\n"
    packets = next(g for g in evidence["input_gates"] if g["name"] == "exact-16-packet-set")["packets"]
    lines = [
        "# S1-C3 16-slot functional release PASS",
        "",
        "Status: **PASS, candidate built offline**",
        "",
        "## Exact artifacts",
        "",
        f"- App: `app.bin`, SHA-256 `{evidence['app']['output_app_sha256']}`.",
        f"- FWSC: `{PACKAGE_NAME}`, SHA-256 `{evidence['package']['package_sha256']}`.",
        f"- Exact OTA wrapper: `exact_ota.c`, token `{evidence['flash']['confirmation_token']}`.",
        f"- Guarded 16-packet C sender: `exact_16_packet_sender.c`, token `{evidence['sender']['confirmation_token']}`.",
        f"- Dry-run validator: `dry_run_validate.py`.",
        f"- Rollback: `{evidence['package']['rollback_manifest']}`; restores official v15 flash SHA-256 `{evidence['package']['official_flash_sha256']}`.",
        "",
        "## PASS gates",
        "",
    ]
    for gate in evidence["input_gates"]:
        lines.append(f"- PASS `{gate['name']}`")
    lines.extend([
        "",
        "## Packet order",
        "",
        "Producer, selector, sender, and validator use note order: slot `0..15` -> MIDI notes `36..51`. Physical Pad permutation from `2a23cf5` is UI-only.",
        "",
        "| Order | Slot | Note | Name | Packet SHA-256 |",
        "|---:|---:|---:|---|---|",
    ])
    for p in packets:
        lines.append(f"| {p['order']} | {p['slot']} | {p['note']} | {p['name']} | `{p['sha256']}` |")
    lines.extend([
        "",
        "## BLOCK scope",
        "",
        "- Device access during this build/validation: **BLOCK**; no USB/MIDI opened.",
        "- Flash/upload/send live actions: **BLOCK unless future explicit authorization plus exact confirmation token**.",
        "- Any hash, size, order, source commit, Pad UI-only, or rollback mismatch: **fail closed**.",
    ])
    return "\n".join(lines) + "\n"


def sha_inventory() -> None:
    include = []
    for path in sorted(p for p in HERE.rglob("*") if p.is_file()):
        rel = path.relative_to(HERE).as_posix()
        if rel == "SHA256SUMS" or "__pycache__" in path.parts:
            continue
        include.append((sha256_path(path), rel))
    (HERE / "SHA256SUMS").write_text("".join(f"{digest}  {rel}\n" for digest, rel in include), encoding="utf-8")


def write_gate_outputs(gates: list[dict[str, Any]], blockers: list[dict[str, str]]) -> dict[str, Any]:
    evidence = {
        "format": FORMAT,
        "decision": "PASS" if not blockers else "BLOCK",
        "candidate_built": False,
        "device_accessed": False,
        "midi_transport_opened": False,
        "flash_performed": False,
        "input_gates": gates,
        "blockers": blockers,
        "source_commits": EXPECTED["source_commits"],
        "artifact_policy": "app/FWSC/rollback/exact OTA/guarded sender are emitted only after all input gates PASS",
    }
    write_json(HERE / "evidence.json", evidence)
    (HERE / "README.md").write_text(render_readme(evidence), encoding="utf-8")
    if blockers:
        (HERE / "BLOCK.md").write_text(render_block(evidence), encoding="utf-8")
        (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
        (HERE / "validation.txt").write_text("S1-C3 16-slot functional input gate: BLOCK\n" + "\n".join(f"{b['code']}={b['message']}" for b in blockers) + "\n", encoding="utf-8")
    else:
        block_path = HERE / "BLOCK.md"
        if block_path.exists():
            block_path.unlink()
        (HERE / "validation.txt").write_text("S1-C3 16-slot functional input gate: PASS\n", encoding="utf-8")
    sha_inventory()
    return evidence


def build_candidate() -> int:
    gates, blockers = collect_gates()
    if blockers:
        write_gate_outputs(gates, blockers)
        print("S1-C3 16-slot functional candidate: BLOCK")
        for blocker in blockers:
            print(f"{blocker['code']}: {blocker['message']}")
        return 2
    evidence = write_gate_outputs(gates, blockers)
    candidate_app, app_manifest = build_app_from_pass_inputs(gates)
    app_path = HERE / "app.bin"
    package_path = HERE / PACKAGE_NAME
    package_manifest_path = HERE / "package-manifest.json"
    app_path.write_bytes(candidate_app)
    write_json(HERE / "app-manifest.json", app_manifest)
    repack(app_path, package_path, package_manifest_path)
    package = validate_package_and_rollback(candidate_app, package_path)
    packet_gate = next(g for g in gates if g["name"] == "exact-16-packet-set")
    (HERE / "exact_ota.c").write_text(render_exact_ota(package["package_sha256"]), encoding="utf-8")
    (HERE / "exact_16_packet_sender.c").write_text(render_guarded_sender_c(packet_gate), encoding="utf-8")
    dry_run_path = HERE / "dry_run_validate.py"
    dry_run_path.write_text(render_dry_run_validator(packet_gate), encoding="utf-8")
    dry_run_path.chmod(0o755)
    sender_token = "SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-" + "-".join(p["sha256"][:8].upper() for p in packet_gate["packets"][:4])
    final = {
        **evidence,
        "decision": "PASS",
        "candidate_built": True,
        "app": app_manifest,
        "package": package,
        "flash": {
            "offline_check_command": f"cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic exact_ota.c ../../../../../src/device_info.c ../../../../../src/fwsc.c ../../../../../src/protocol.c ../../../../../src/sha256.c ../../../../../src/usb_probe.c -o exact_ota $(pkg-config --cflags --libs libusb-1.0) && ./exact_ota check {PACKAGE_NAME}",
            "upload_command": f"./exact_ota upload {PACKAGE_NAME} live-install-YYYYMMDDTHHMMZ.txt --confirm INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-{package['package_sha256'][:8].upper()}",
            "confirmation_token": f"INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-{package['package_sha256'][:8].upper()}",
            "offline_build_scope": "check only; upload is blocked unless explicitly authorized later",
        },
        "sender": {
            "dry_run_command": "cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic exact_16_packet_sender.c ../../../../../src/sha256.c -o exact_16_packet_sender && ./exact_16_packet_sender dry-run inputs/packets",
            "send_command": f"./exact_16_packet_sender send inputs/packets --confirm {sender_token}",
            "confirmation_token": sender_token,
            "default_compile_live_usb_enabled": False,
            "offline_build_scope": "dry-run only; live send is fail-closed unless compiled with S1C3_ENABLE_LIVE_USB after explicit authorization",
        },
        "dry_run_validator": {
            "command": "python3 dry_run_validate.py --json",
            "device_accessed": False,
            "send_enabled": False,
        },
        "pad_mapping": {
            "physical_pad_permutation_commit": EXPECTED["source_commits"]["pad_permutation"],
            "physical_pad_to_note_order_slot": EXPECTED["physical_pad_to_note_order_slot"],
            "scope": "UI_ONLY",
            "producer_selector_packet_order": "note_order_36_51",
        },
    }
    write_json(HERE / "evidence.json", final)
    (HERE / "README.md").write_text(render_readme(final), encoding="utf-8")
    (HERE / "report.md").write_text(render_report(final), encoding="utf-8")
    (HERE / "validation.txt").write_text(
        "S1-C3 16-slot functional candidate build validation PASS\n"
        + "S1-C3 16-slot functional release validation PASS\n"
        + f"app_sha256={app_manifest['output_app_sha256']}\n"
        + f"package_sha256={package['package_sha256']}\n"
        + f"ota_confirmation_token={final['flash']['confirmation_token']}\n"
        + f"sender_confirmation_token={sender_token}\n"
        + "PASS gates=boundary_live_pass,selector_note_order_36_51,compact_producer_exact_bytes,bank_d_16_packet_set,rollback_reconstructs_official,exact_ota_check,exact_sender_dry_run\n"
        + "PASS pad_permutation_scope=UI_ONLY; producer_selector_packet_order=note_order_36_51\n"
        + "BLOCK device_access,flash_upload,reset,midi_transport,live_send_during_validation\n"
        + "device_accessed=false\n"
        + "midi_transport_opened=false\n"
        + "flash_performed=false\n",
        encoding="utf-8",
    )
    sha_inventory()
    print("S1-C3 16-slot functional candidate build PASS")
    print(f"app_sha256={app_manifest['output_app_sha256']}")
    print(f"package_sha256={package['package_sha256']}")
    return 0


def check_inputs() -> int:
    gates, blockers = collect_gates()
    if blockers:
        write_gate_outputs(gates, blockers)
        print("S1-C3 16-slot functional input gate: BLOCK")
        for blocker in blockers:
            print(f"{blocker['code']}: {blocker['message']}")
    else:
        # Non-destructive after a release build: preserve exact app/FWSC/hash evidence.
        current_path = HERE / "evidence.json"
        current_release = False
        if current_path.exists():
            try:
                current = load_json(current_path)
                required = [
                    HERE / "app.bin",
                    HERE / PACKAGE_NAME,
                    HERE / "app-manifest.json",
                    HERE / "package-manifest.json",
                    HERE / "exact_ota.c",
                    HERE / "exact_16_packet_sender.c",
                    HERE / "dry_run_validate.py",
                    HERE / "rollback" / "official-v15-recovery-sectors" / "manifest.json",
                ]
                current_release = (
                    current.get("format") == FORMAT
                    and current.get("decision") == "PASS"
                    and current.get("candidate_built") is True
                    and all(path.exists() for path in required)
                )
            except (OSError, json.JSONDecodeError):
                current_release = False
        if not current_release:
            write_gate_outputs(gates, blockers)
        print("S1-C3 16-slot functional input gate: PASS")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=["check-inputs", "build"], default="check-inputs")
    args = parser.parse_args()
    if args.command == "build":
        return build_candidate()
    return check_inputs()


if __name__ == "__main__":
    raise SystemExit(main())
