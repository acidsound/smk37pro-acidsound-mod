#!/usr/bin/env python3
"""Read-only validator for the official-v15/H2 S1-C1 RAM analysis."""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
EVIDENCE_PATH = HERE / "evidence.json"
REPORT_PATH = HERE / "report.md"

RUNTIME_BASE = 0x02000000
BSS_INSN = 0x0200001E
HEAP_BEGIN_INSN = 0x0205E9F8
HEAP_END_INSN = 0x0205EA00

BSS_START = 0x01C099D4
OFFICIAL_BSS_SIZE = 0x0003CB48
OFFICIAL_BSS_END = 0x01C4651C
OFFICIAL_HEAP_BEGIN = 0x01C46520
H2_BSS_SIZE = 0x0003CBEC
H2_HEAP_BEGIN = 0x01C465C0
NEW_HEAP_BEGIN = 0x01C46660
HEAP_END = 0x01C7FD30
SLOT_STRIDE = 0xA0
VOICE_SIZE = 0x9C


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def app_bytes(image: bytes, address: int, size: int) -> bytes:
    offset = address - RUNTIME_BASE
    return image[offset : offset + size]


def require(condition: bool, label: str, detail: object, checks: list[str]) -> None:
    if not condition:
        raise SystemExit(f"FAIL\t{label}\t{detail}")
    checks.append(f"PASS\t{label}\t{detail}")


def main() -> None:
    evidence = json.loads(EVIDENCE_PATH.read_text())
    report = REPORT_PATH.read_text()
    checks: list[str] = []

    require(evidence["format"] == "smk37-v15-s1c1-two-slot-ram-v2",
            "evidence-format", evidence["format"], checks)

    scope = evidence["scope"]
    require(scope == {
        "firmware_basis": "official-v15 plus recorded H0/H1/H2 evidence, with H2 as the live parent",
        "v12_evidence_used": False,
        "firmware_built": False,
        "device_accessed": False,
        "flash_performed": False,
    }, "scope", "official-v15/H2 only; no build/device/flash/v12", checks)

    for item in evidence["inputs"]:
        path = ROOT / item["path"]
        require(path.is_file(), "input-exists", item["path"], checks)
        actual = sha256(path)
        require(actual == item["sha256"], "input-sha256", f"{actual}  {item['path']}", checks)

    official_path = ROOT / "build/v15-official-app.bin"
    h2_path = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin"
    official = official_path.read_bytes()
    h2 = h2_path.read_bytes()

    official_bss_hex = "c2ff48cb0300"
    h2_bss_hex = "c2ffeccb0300"
    proposed_bss_hex = "c2ff8ccc0300"
    official_heap_hex = "c5ff2065c401"
    h2_heap_hex = "c5ffc065c401"
    proposed_heap_hex = "c5ff6066c401"
    heap_end_hex = "caff30fdc701"

    require(app_bytes(official, BSS_INSN, 6).hex() == official_bss_hex,
            "official-bss-instruction", official_bss_hex, checks)
    require(app_bytes(h2, BSS_INSN, 6).hex() == h2_bss_hex,
            "h2-bss-instruction", h2_bss_hex, checks)
    require(app_bytes(official, HEAP_BEGIN_INSN, 6).hex() == official_heap_hex,
            "official-heap-begin-instruction", official_heap_hex, checks)
    require(app_bytes(h2, HEAP_BEGIN_INSN, 6).hex() == h2_heap_hex,
            "h2-heap-begin-instruction", h2_heap_hex, checks)
    require(app_bytes(official, HEAP_END_INSN, 6).hex() == heap_end_hex,
            "official-heap-end-instruction", heap_end_hex, checks)
    require(app_bytes(h2, HEAP_END_INSN, 6).hex() == heap_end_hex,
            "h2-heap-end-unchanged", heap_end_hex, checks)

    new_bss_size = NEW_HEAP_BEGIN - BSS_START
    require(new_bss_size == 0x3CC8C,
            "new-bss-size", f"0x{new_bss_size:08x}", checks)
    require((b"\xc2\xff" + struct.pack("<I", new_bss_size)).hex() == proposed_bss_hex,
            "proposed-bss-encoding", proposed_bss_hex, checks)
    require((b"\xc5\xff" + struct.pack("<I", NEW_HEAP_BEGIN)).hex() == proposed_heap_hex,
            "proposed-heap-begin-encoding", proposed_heap_hex, checks)

    layout = evidence["minimum_two_note_layout"]
    base = int(layout["base"], 16)
    end = int(layout["end_exclusive"], 16)
    require(base == OFFICIAL_HEAP_BEGIN,
            "layout-base", f"0x{base:08x}", checks)
    require(end == NEW_HEAP_BEGIN,
            "layout-end", f"0x{end:08x}", checks)
    require(end - base == 2 * SLOT_STRIDE == layout["total_size"] == 0x140,
            "two-slot-size", f"2 * 0xa0 = 0x{end - base:03x}", checks)
    tail_capacity = 2 * (SLOT_STRIDE - VOICE_SIZE)
    require(layout["functional_metadata_size"] == 7,
            "minimum-functional-metadata", "valid0 + lock + note0 + state + valid1 + tx + note1 = 7", checks)
    require(layout["tail_capacity"] == tail_capacity == 8 and layout["reserved_tail_bytes"] == 1,
            "slot-tail-capacity", "7 functional + 1 reserved = 8", checks)
    require(layout["metadata_is_embedded_in_both_slot_tails"] is True,
            "metadata-embedded", "no bytes beyond two 0xa0 strides", checks)

    h2_mem = evidence["h2_memory"]
    require(h2_mem["slot0_voice"] == "0x01c46520..0x01c465bc",
            "h2-slot0-voice", h2_mem["slot0_voice"], checks)
    require(h2_mem["slot0_valid"] == "0x01c465bc",
            "h2-slot0-valid", h2_mem["slot0_valid"], checks)
    require(h2_mem["global_lock"] == "0x01c465bd",
            "h2-global-lock", h2_mem["global_lock"], checks)

    ranges = {row["range"]: row for row in layout["layout"]}
    require(ranges["0x01c46520..0x01c465bc"]["size"] == VOICE_SIZE,
            "slot0-voice-range", "0x01c46520..0x01c465bc", checks)
    require(ranges["0x01c465bc"]["size"] == 1 and ranges["0x01c465bd"]["size"] == 1,
            "h2-metadata-addresses", "valid0=0x01c465bc lock=0x01c465bd", checks)
    require(ranges["0x01c465be"]["size"] == 1 and ranges["0x01c465bf"]["size"] == 1,
            "slot0-tail-addresses", "note0=0x01c465be state=0x01c465bf", checks)
    require(ranges["0x01c465c0..0x01c4665c"]["size"] == VOICE_SIZE,
            "slot1-voice-range", "0x01c465c0..0x01c4665c", checks)
    require(all(ranges[f"0x{address:08x}"]["size"] == 1 for address in range(0x01C4665C, 0x01C46660)),
            "slot1-tail-range", "valid1=0x01c4665c tx=0x01c4665d note1=0x01c4665e reserved=0x01c4665f", checks)

    publication = layout["publication"]
    require((publication["boot_state"], publication["loading_state"], publication["armed_state"]) == (0, 1, 2),
            "publication-states", "EMPTY=0 LOADING=1 ARMED=2", checks)
    require("EMPTY and valid0==1 selects exact H2 slot0" in layout["h2_compatibility"],
            "h2-empty-valid0-compatibility", layout["h2_compatibility"], checks)

    ingress = json.loads((ROOT / "baselines/v15/analysis/patch-set-ui/s1c1/ingress/evidence.json").read_text())
    ingress_ram = ingress["ram"]
    require(ingress_ram["base"] == layout["base"] and ingress_ram["end_exclusive"] == layout["end_exclusive"],
            "ingress-ram-boundary", f"{ingress_ram['base']}..{ingress_ram['end_exclusive']}", checks)
    ingress_rows = {(row.get("range") or row.get("address")): row for row in ingress_ram["layout"]}
    expected_purposes = {
        "0x01c465bc": "valid0, exact H2",
        "0x01c465bd": "global nonblocking lock, exact H2",
        "0x01c465be": "note0",
        "0x01c465bf": "state",
        "0x01c4665c": "valid1",
        "0x01c4665d": "transaction id",
        "0x01c4665e": "note1",
        "0x01c4665f": "reserved zero",
    }
    require({address: ingress_rows[address]["purpose"] for address in expected_purposes} == expected_purposes,
            "ingress-metadata-contract", expected_purposes, checks)
    require(ingress["state_machine"]["states"] == {"EMPTY": 0, "LOADING": 1, "ARMED": 2},
            "ingress-state-machine", ingress["state_machine"]["states"], checks)
    require(ingress["consumer"]["legacy_h2_selection"] == "EMPTY and valid0==1 selects slot0 for Ch10",
            "ingress-h2-compatibility", ingress["consumer"]["legacy_h2_selection"], checks)

    boundary = evidence["boundary_changes"]
    require(OFFICIAL_BSS_END == BSS_START + OFFICIAL_BSS_SIZE,
            "official-bss-arithmetic", "0x01c099d4 + 0x3cb48 = 0x01c4651c", checks)
    require(OFFICIAL_HEAP_BEGIN - OFFICIAL_BSS_END == 4,
            "official-linker-padding", "4 bytes", checks)
    require(H2_HEAP_BEGIN - OFFICIAL_HEAP_BEGIN == SLOT_STRIDE,
            "h2-reservation", "0xa0", checks)
    require(H2_BSS_SIZE - OFFICIAL_BSS_SIZE == 0xA4,
            "h2-bss-growth", "0xa4 including 4-byte linker padding", checks)
    require(new_bss_size - OFFICIAL_BSS_SIZE == boundary["bss_growth_from_official"] == 0x144,
            "official-to-s1c1-bss-growth", "0x144", checks)
    require(new_bss_size - H2_BSS_SIZE == boundary["bss_growth_from_h2"] == 0xA0,
            "h2-to-s1c1-bss-growth", "0xa0", checks)
    require(NEW_HEAP_BEGIN - OFFICIAL_HEAP_BEGIN == boundary["heap_loss_from_official"] == 0x140,
            "official-to-s1c1-heap-loss", "0x140", checks)
    require(NEW_HEAP_BEGIN - H2_HEAP_BEGIN == boundary["heap_loss_from_h2"] == 0xA0,
            "h2-to-s1c1-heap-loss", "0xa0", checks)
    require(HEAP_END - OFFICIAL_HEAP_BEGIN == 0x39810,
            "official-heap-span", "0x39810", checks)
    require(HEAP_END - H2_HEAP_BEGIN == 0x39770,
            "h2-heap-span", "0x39770", checks)
    require(HEAP_END - NEW_HEAP_BEGIN == boundary["new_heap_span"] == 0x396D0,
            "s1c1-heap-span", "0x396d0", checks)

    patches = {row["address"]: row for row in boundary["instruction_patches"]}
    require(patches["0x0200001e"]["proposed_hex"] == proposed_bss_hex,
            "evidence-proposed-bss", proposed_bss_hex, checks)
    require(patches["0x0205e9f8"]["proposed_hex"] == proposed_heap_hex,
            "evidence-proposed-heap", proposed_heap_hex, checks)
    require(boundary["heap_end_unchanged"] == "0x01c7fd30",
            "evidence-heap-end", boundary["heap_end_unchanged"], checks)

    h2_manifest = json.loads((ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json").read_text())
    policy = h2_manifest["h2_policy"]
    require(policy["producer_owned_destination"] == "0x01c46520..0x01c465bc",
            "manifest-h2-slot0", policy["producer_owned_destination"], checks)
    require(policy["valid"] == "0x01c465bc" and policy["lock"] == "0x01c465bd",
            "manifest-h2-metadata", f"valid={policy['valid']} lock={policy['lock']}", checks)
    require(policy["copy_size"] == VOICE_SIZE,
            "manifest-h2-copy-size", "0x9c", checks)

    live_paths = {
        "h0": ROOT / "baselines/v15/analysis/flash-candidates/H0-memory-boundary-only/live-validation-20260802.md",
        "h1": ROOT / "baselines/v15/analysis/flash-candidates/H1-producer-unconsumed/live-validation-20260802.md",
        "h2": ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md",
    }
    live = {name: path.read_text() for name, path in live_paths.items()}
    require("H0 LIVE PASS" in live["h0"] and "does not prove complete heap ownership" in live["h0"],
            "h0-live-scope", "narrow immediate first-Pad boundary PASS only", checks)
    require("H1 LIVE PASS" in live["h1"] and "no consumer reference to `0x01c46520`" in live["h1"],
            "h1-live-scope", "producer at same H2 boundary", checks)
    require("H2 LIVE PASS" in live["h2"] and "intended Bank D patch 14 Mooger #1 sound" in live["h2"],
            "h2-live-scope", "slot0 consumed at same H2 boundary", checks)

    assessment = evidence["live_evidence_assessment"]
    require(assessment["boundary_discriminator_verdict"] == "DEFENSIBLE_ONLY_FOR_H2_0xA0_IMMEDIATE_SMOKE",
            "boundary-discriminator", assessment["boundary_discriminator_verdict"], checks)
    require(assessment["s1c1_headroom_verdict"] == "BLOCK",
            "s1c1-headroom-verdict", "BLOCK", checks)

    headroom = evidence["headroom_gate"]
    require(headroom["delta_from_h2"] == SLOT_STRIDE,
            "headroom-delta", "0xa0", checks)
    require("Bmax + 0xa0 < 0x01c7fd30" in " ".join(headroom["offline_pass_condition"]),
            "strict-headroom-inequality", "Bmax + 0xa0 < HEAP_END; equality blocked", checks)
    require(headroom["offline_status"] == "BLOCK_NO_HIGH_WATER_OR_COMPLETE_MODEL",
            "offline-headroom-status", headroom["offline_status"], checks)
    require(headroom["paired_live_gate_if_offline_proof_is_incomplete"]["status"] == "REQUIRED_BEFORE_S1C1_SELECTOR",
            "paired-live-gate-status", "REQUIRED_BEFORE_S1C1_SELECTOR", checks)

    gates = {item["id"]: item["status"] for item in evidence["gates"]}
    require(gates == {
        "exact-static-placement": "PASS",
        "h2-slot0-address-compatibility": "PASS",
        "minimum-ingress-map-state-metadata": "PASS",
        "existing-live-boundary-discriminator": "PASS_NARROW",
        "additional-0xa0-headroom": "BLOCK",
        "s1c1-firmware-build-or-live-selector": "BLOCK",
    }, "gate-set", gates, checks)

    markers = (
        "`0x01c46520..0x01c46660`",
        "0x0003cc8c",
        "`c2ff8ccc0300`",
        "`c5ff6066c401`",
        "0x01c4665e",
        "Seven functional bytes plus one reserved byte",
        "when state is EMPTY and the existing H2 producer has written `valid0 == 1`",
        "Bmax + 0x000000a0 < 0x01c7fd30",
        "A no-reboot observation is not a heap high-water measurement.",
        "**Additional S1-C1 heap headroom: BLOCK.**",
        "built no firmware, accessed no device, flashed nothing, and used no v12 evidence",
    )
    for marker in markers:
        require(marker in report, "report-marker", marker, checks)

    print("\n".join(checks))


if __name__ == "__main__":
    main()
