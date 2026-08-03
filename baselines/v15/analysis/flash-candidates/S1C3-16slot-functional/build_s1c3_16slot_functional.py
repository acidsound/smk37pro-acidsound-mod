#!/usr/bin/env python3
"""Offline S1-C3 16-slot functional integration gate and builder skeleton.

This file intentionally performs no USB, MIDI, reset, or device access. It starts
from the exact live-PASS S1-C3 boundary app, accepts only reviewed PASS inputs,
and refuses to emit a functional app/FWSC/rollback/uploader/sender until all
required inputs are present and PASS.
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
CURRENT_PRODUCER_DESIGN_DIR = ANALYSIS / "patch-set-ui" / "s1c3" / "producer"
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

FORMAT = "smk37-v15-s1c3-16slot-functional-offline-skeleton-v1"
PACKAGE_NAME = "SMK37Pro-v15-S1C3-16slot-functional.fwsc"
RUNTIME_BASE = 0x02000000
SECTOR_SIZE = 0x2000
PROTECTED_PREFIX_END = 0x4000

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
    "producer_entry": 0x0201E1A2,
    "producer_owned_end_exclusive": 0x0201E254,
    "packet_count": 16,
    "first_note": 36,
    "last_note": 51,
    "packet_bytes": 163,
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
    }
    if checks["selector_size"] != EXPECTED["selector_bytes"] or checks["selector_hash"] != EXPECTED["selector_sha256"]:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_BYTES", "selector is not the reviewed 96-byte blob", **checks)
    if checks["live_code_hash"] != EXPECTED["selector_live_code_sha256"]:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_LIVE_CODE_HASH", "selector live-code hash mismatch", **checks)
    if checks["raw_selector_design"] != "PASS" or "validation: PASS" not in validation_text:
        return block_gate("reviewed-96-byte-16-note-selector", "BLOCK_SELECTOR_NOT_PASS", "selector validation is not PASS", **checks)
    return pass_gate("reviewed-96-byte-16-note-selector", path=str(selector.relative_to(ROOT)), start=f"0x{EXPECTED['selector_start']:08x}", end_exclusive=f"0x{EXPECTED['selector_end_exclusive']:08x}", **checks)


def check_producer() -> dict[str, Any]:
    """Accept only a future target-local compact producer PASS manifest and bytes."""
    manifest_path = LOCAL_PRODUCER_DIR / "evidence.json"
    producer_path = LOCAL_PRODUCER_DIR / "producer.bin"
    current_evidence_path = CURRENT_PRODUCER_DESIGN_DIR / "evidence.json"
    if not manifest_path.exists() or not producer_path.exists():
        current = load_json(current_evidence_path) if current_evidence_path.exists() else {}
        return block_gate(
            "compact-16-slot-producer",
            "BLOCK_COMPACT_PRODUCER_PASS_INPUT_UNAVAILABLE",
            "compact assembled producer PASS input is unavailable; current producer checkpoint is design-only and not firmware/live-authorizing",
            required_files=[str(manifest_path.relative_to(ROOT)), str(producer_path.relative_to(ROOT))],
            current_design_verdict=current.get("verdict", {}),
        )
    manifest = load_json(manifest_path)
    data = producer_path.read_bytes()
    producer = manifest.get("producer", {})
    checks = {
        "status": manifest.get("status") or manifest.get("decision") or manifest.get("verdict"),
        "producer_hash": sha256_bytes(data),
        "producer_size": len(data),
        "manifest_hash": producer.get("sha256"),
        "entry": producer.get("entry"),
        "owned_end_exclusive": producer.get("owned_end_exclusive"),
        "device_accessed": manifest.get("device_accessed", False),
    }
    if checks["status"] != "PASS":
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_NOT_PASS", "compact producer manifest is not PASS", **checks)
    if checks["producer_hash"] != checks["manifest_hash"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_HASH", "producer.bin hash does not match manifest", **checks)
    if checks["entry"] != f"0x{EXPECTED['producer_entry']:08x}" or checks["owned_end_exclusive"] != f"0x{EXPECTED['producer_owned_end_exclusive']:08x}":
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_PLACEMENT", "producer manifest placement is not the reviewed owned range", **checks)
    if len(data) > EXPECTED["producer_owned_end_exclusive"] - EXPECTED["producer_entry"]:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_TOO_LARGE", "producer bytes exceed owned range", **checks)
    if checks["device_accessed"] is True:
        return block_gate("compact-16-slot-producer", "BLOCK_COMPACT_PRODUCER_DEVICE_ACCESS_SCOPE", "producer PASS input claims device access in this offline gate", **checks)
    return pass_gate("compact-16-slot-producer", path=str(producer_path.relative_to(ROOT)), **checks)


def expected_packet_name(slot: int) -> str:
    return f"slot{slot:02d}-note{EXPECTED['first_note'] + slot:02d}-direct-product-163.bin"


def check_packets() -> dict[str, Any]:
    manifest_path = LOCAL_PACKET_DIR / "packet-manifest.json"
    if not manifest_path.exists():
        return block_gate(
            "exact-16-packet-set",
            "BLOCK_16_PACKET_SET_PASS_INPUT_UNAVAILABLE",
            "reviewed exact 16-packet PASS set is unavailable",
            required_manifest=str(manifest_path.relative_to(ROOT)),
            required_files=[f"inputs/packets/{expected_packet_name(slot)}" for slot in range(EXPECTED["packet_count"])],
        )
    manifest = load_json(manifest_path)
    packets = manifest.get("packets", [])
    checks = {"status": manifest.get("status") or manifest.get("decision"), "packet_count": len(packets)}
    if checks["status"] != "PASS":
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_SET_NOT_PASS", "packet manifest is not PASS", **checks)
    if len(packets) != EXPECTED["packet_count"]:
        return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_COUNT", "packet manifest does not describe exactly 16 packets", **checks)
    verified: list[dict[str, Any]] = []
    for slot in range(EXPECTED["packet_count"]):
        note = EXPECTED["first_note"] + slot
        expected_name = expected_packet_name(slot)
        entry = packets[slot]
        packet_path = LOCAL_PACKET_DIR / expected_name
        if entry.get("slot") != slot or entry.get("note") != note or entry.get("file") != expected_name:
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_ORDER", "packet manifest order/name/note mismatch", slot=slot, entry=entry, expected_file=expected_name, expected_note=note)
        if not packet_path.exists():
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_FILE_MISSING", "packet file missing", slot=slot, file=expected_name)
        data = packet_path.read_bytes()
        digest = sha256_bytes(data)
        if len(data) != EXPECTED["packet_bytes"] or digest != entry.get("sha256"):
            return block_gate("exact-16-packet-set", "BLOCK_16_PACKET_BYTES", "packet size/hash mismatch", slot=slot, file=expected_name, size=len(data), sha256=digest, expected_sha256=entry.get("sha256"))
        verified.append({"slot": slot, "note": note, "file": expected_name, "sha256": digest})
    return pass_gate("exact-16-packet-set", manifest=str(manifest_path.relative_to(ROOT)), packets=verified)


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
        "The offline gate consumed the live-PASS S1-C3 boundary app and reviewed 96-byte selector, then stopped before creating any flashable functional artifacts because required PASS inputs are missing.",
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
        "2. Reviewed S1-C3 selector must remain exactly 96 bytes with the recorded SHA-256.",
        "3. Compact assembled 16-slot producer must be supplied as target-local PASS evidence plus `producer.bin` in the reviewed owned range.",
        "4. Exact 16 packet set must be supplied as target-local PASS evidence, exactly 16 files, fixed note order 36..51, 163 bytes each, fixed hashes.",
        "5. Only after all gates PASS may the builder emit deterministic `app.bin`, `.fwsc`, rollback sectors, exact-hash OTA wrapper, and guarded 16-packet sender.",
        "",
        "No missing bytes were invented and no device transport was opened.",
    ])
    return "\n".join(lines) + "\n"


def render_readme() -> str:
    return """# S1-C3 16-slot functional offline integration skeleton

Status: **BLOCK until all inputs PASS**.

This directory is a deterministic gate and builder skeleton for a future flashable
S1-C3 16-slot functional candidate. It starts from the exact live-PASS
`S1C3-16slot-boundary-only` app and consumes only reviewed inputs:

- reviewed 96-byte S1-C3 16-note selector from `patch-set-ui/s1c3/selector`;
- future compact assembled 16-slot producer in `inputs/producer/`;
- future exact 16-packet PASS set in `inputs/packets/`.

The builder writes `BLOCK.md` and refuses to create `app.bin`, FWSC, rollback,
exact OTA, or guarded sender until every input gate is PASS. It never accesses a
device, opens USB/MIDI, flashes, resets, or sends packets.

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
    ]
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
    return f'''/* Exact-hash v15-only OTA wrapper for S1-C3 16-slot functional candidate. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {pretty} }};
static const char CONFIRM[] = "{token}";
static int check_exact(const char *path) {{
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{
        puts("exact v15 S1-C3 16-slot functional package: PASS");
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
            "SMK37ProMod v15 S1-C3 16-slot functional candidate", CONFIRM,
            "v15 S1-C3 functional candidate installed");
    }}
    usage(argv[0]);
    return 2;
}}
'''


def render_guarded_sender(packet_gate: dict[str, Any]) -> str:
    packets = packet_gate["packets"]
    return """#!/usr/bin/env python3
\"\"\"Guarded S1-C3 16-packet sender skeleton generated only after packet PASS.

Default mode is offline verification. Any future live transport path must add an
explicit confirmation token and keep these fixed hashes/order checks intact.
\"\"\"
from __future__ import annotations
import hashlib
from pathlib import Path
HERE = Path(__file__).resolve().parent
PACKETS = [
""" + "".join(f"    ({p['slot']}, {p['note']}, '{p['file']}', '{p['sha256']}'),\n" for p in packets) + """
]
def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main() -> int:
    for slot, note, name, digest in PACKETS:
        path = HERE / 'inputs' / 'packets' / name
        data = path.read_bytes()
        if len(data) != 163 or sha256(path) != digest:
            raise SystemExit(f'FAIL packet {slot} note {note}: {name}')
    print('S1-C3 guarded sender offline packet verification PASS')
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
"""


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
        "artifact_policy": "app/FWSC/rollback/exact OTA/guarded sender are emitted only after all input gates PASS",
    }
    write_json(HERE / "evidence.json", evidence)
    (HERE / "README.md").write_text(render_readme(), encoding="utf-8")
    if blockers:
        (HERE / "BLOCK.md").write_text(render_block(evidence), encoding="utf-8")
        (HERE / "validation.txt").write_text("S1-C3 16-slot functional skeleton input gate: BLOCK (expected until producer and packet PASS inputs exist)\n" + "\n".join(f"{b['code']}={b['message']}" for b in blockers) + "\n", encoding="utf-8")
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
    (HERE / "guarded_sender.py").write_text(render_guarded_sender(packet_gate), encoding="utf-8")
    final = {
        **evidence,
        "decision": "PASS",
        "candidate_built": True,
        "app": app_manifest,
        "package": package,
        "flash": {
            "offline_check_command": f"cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic exact_ota.c -o exact_ota $(pkg-config --cflags --libs libusb-1.0) && ./exact_ota check {PACKAGE_NAME}",
            "confirmation_token": f"INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-{package['package_sha256'][:8].upper()}",
        },
    }
    write_json(HERE / "evidence.json", final)
    (HERE / "validation.txt").write_text("S1-C3 16-slot functional candidate build validation PASS\n" + f"app_sha256={app_manifest['output_app_sha256']}\npackage_sha256={package['package_sha256']}\n", encoding="utf-8")
    sha_inventory()
    print("S1-C3 16-slot functional candidate build PASS")
    return 0


def check_inputs() -> int:
    gates, blockers = collect_gates()
    write_gate_outputs(gates, blockers)
    if blockers:
        print("S1-C3 16-slot functional input gate: BLOCK")
        for blocker in blockers:
            print(f"{blocker['code']}: {blocker['message']}")
    else:
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
