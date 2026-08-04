#!/usr/bin/env python3
"""Revalidate the v15/S1-C3/S1-C4 Ch10 playback-note consumer path.

This script is analysis-only. It reads the official v15 app, current S1-C3
and S1-C4 evidence/artifacts, then writes evidence.json, report.md,
validation.txt, and SHA256SUMS in this directory. It does not build firmware,
open USB/MIDI, flash, or modify any app/FWSC artifact.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent
BASE = 0x02000000

OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
S1C3_DIR = ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload"
S1C3_APP = S1C3_DIR / "app.bin"
S1C3_EVIDENCE = S1C3_DIR / "evidence.json"
S1C3_SELECTOR_DECODE = ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload-review/selector-independent-decode.tsv"
S1C4_DIR = ROOT / "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final"
S1C4_APP = S1C4_DIR / "app.bin"
S1C4_EVIDENCE = S1C4_DIR / "evidence.json"
S1C4_DECODE = ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv"

EXPECTED_SHA = {
    str(OFFICIAL_APP): "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    str(S1C3_APP): "7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b",
    str(S1C4_APP): "c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d",
}

CHECK_BYTES = {
    "official": {
        OFFICIAL_APP: {
            0x0201C62E: "1d41",            # Note Off: r5 = msg[1]
            0x0201C63E: "80ff8ac60200",    # stock Note Off memcpy
            0x0201C644: "00e13e61",        # r0 = voice + 0x13e
            0x0201C648: "8d40",            # store r5 note
            0x0201C66A: "1d42",            # Note On: r5 = msg[2] velocity
            0x0201C66C: "e1f1a020",        # voice index * 0xa0
            0x0201C670: "1e41",            # Note On: r6 = msg[1] note
            0x0201C672: "0f1c",            # per-voice slot base
            0x0201C674: "00e1a270",        # r0 = slot + 0xa2
            0x0201C67C: "80ff4cc60200",    # stock Note On memcpy
            0x0201C682: "00e13e71",        # r0 = voice + 0x13e
            0x0201C686: "8e40",            # store r6 note
            0x0201C68C: "8d42",            # store r5 velocity
        }
    },
    "s1c3": {
        S1C3_APP: {
            0x0201C63E: "80fffa1a0000",    # Note Off hook -> 0x0201e13e
            0x0201C644: "00e13e61",        # stock post-call note pointer preserved
            0x0201C648: "8d40",            # stock stores restored r5
            0x0201C67C: "80ffc01a0000",    # Note On hook -> 0x0201e142
            0x0201C682: "00e13e71",        # stock post-call note pointer preserved
            0x0201C686: "8e40",            # stock stores restored r6
            0x0201C68C: "8d42",            # velocity preserved
            0x0201E142: "6316",            # Note On adapter: mov r3,r6
            0x0201E14A: "85f81712",        # Ch10 gate on r9 == 9
            0x0201E156: "f33c",            # slot = trigger - 36
            0x0201E158: "c8ff2065c401",    # slot base 0x01c46520
            0x0201E17E: "80ff4aab0200",    # selector memcpy call
            0x0201E184: "5904",            # pop restores r5/r6
        }
    },
    "s1c4": {
        S1C4_APP: {
            0x0201C63E: "80fffa1a0000",    # Note Off hook unchanged
            0x0201C644: "001600160016",    # stock Note Off metadata store neutralized
            0x0201C67C: "80ffc01a0000",    # Note On hook unchanged
            0x0201C682: "001600160016",    # stock Note On metadata note store neutralized
            0x0201C68C: "8d42",            # velocity store preserved
            0x0201E142: "6316",            # Note On adapter
            0x0201E158: "f33c",            # slot = trigger - 36
            0x0201E17C: "07e1008a",        # map base = slot_base + 0xa00
            0x0201E182: "7d40",            # r5 = playback_map[slot]
            0x0201E184: "6116",            # r1 = trigger-selected source
            0x0201E188: "80ff40ab0200",    # selector memcpy call
            0x0201E18E: "00e19c40",        # r0 = saved_dest + 0x9c
            0x0201E192: "8d40",            # local metadata note store = r5
            0x0201E1E8: "01e19b40",        # producer points at staging[0x9b]
            0x0201E1EC: "1a40",            # producer loads wire byte 161
            0x0201E1EE: "8a40",            # producer stores playback map
            0x0201E1F0: "4a3f",            # restores 0x3f to staging before copy
        }
    },
}


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def app_slice(path: Path, addr: int, n: int) -> bytes:
    data = path.read_bytes()
    off = addr - BASE
    if off < 0 or off + n > len(data):
        raise AssertionError(f"address {addr:#x} outside {path}")
    return data[off:off + n]


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def load_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def verify() -> dict[str, Any]:
    validation: list[str] = []
    inputs: dict[str, Any] = {}

    for path_s, expected in EXPECTED_SHA.items():
        path = Path(path_s)
        actual = sha256_path(path)
        if actual != expected:
            raise AssertionError(f"SHA mismatch {path}: {actual} != {expected}")
        inputs[rel(path)] = {"sha256": actual, "status": "PASS"}
        validation.append(f"PASS\tsha256\t{rel(path)}\t{actual}")

    byte_checks: dict[str, list[dict[str, str]]] = {}
    for group, files in CHECK_BYTES.items():
        byte_checks[group] = []
        for path, checks in files.items():
            for addr, expected_hex in checks.items():
                actual = app_slice(path, addr, len(bytes.fromhex(expected_hex))).hex()
                if actual != expected_hex:
                    raise AssertionError(f"byte mismatch {group} {rel(path)} {addr:#x}: {actual} != {expected_hex}")
                byte_checks[group].append({"address": f"0x{addr:08x}", "bytes": actual, "path": rel(path), "status": "PASS"})
                validation.append(f"PASS\tbytes\t{group}\t0x{addr:08x}\t{actual}")

    s1c3 = load_json(S1C3_EVIDENCE)
    s1c4 = load_json(S1C4_EVIDENCE)
    if s1c3["app"]["input_gates"][1]["slot_formula"] != "slot = note - 36":
        raise AssertionError("S1-C3 slot formula gate mismatch")
    if not s1c4["app"]["callsite_contract"]["segmented_product_callsite"].get("segmented_final_supported"):
        raise AssertionError("S1-C4 segmented-final support gate missing")
    if s1c4["transport"]["wire_playback_note_offset"] != 161:
        raise AssertionError("S1-C4 wire playback-note offset mismatch")
    validation.extend([
        "PASS\ts1c3-evidence\tslot_formula\tslot = note - 36",
        "PASS\ts1c4-evidence\tsegmented_final_supported\ttrue",
        "PASS\ts1c4-evidence\twire_playback_note_offset\t161",
    ])

    s1c3_rows = load_tsv(S1C3_SELECTOR_DECODE)
    s1c4_rows = load_tsv(S1C4_DECODE)
    needed_s1c3 = {
        "0x0201e142": "6316",
        "0x0201e156": "f33c",
        "0x0201e17a": "5116",
        "0x0201e17e": "80ff4aab0200",
        "0x0201e184": "5904",
    }
    by_addr3 = {r["address"]: r for r in s1c3_rows}
    for addr, b in needed_s1c3.items():
        if by_addr3.get(addr, {}).get("bytes") != b:
            raise AssertionError(f"S1-C3 decode mismatch {addr}")
        validation.append(f"PASS\ts1c3-selector-decode\t{addr}\t{b}")
    by_addr4 = {r["address"]: r for r in s1c4_rows}
    for addr in ("0x0201e17c", "0x0201e182", "0x0201e184", "0x0201e192", "0x0201e1ec", "0x0201e1f0"):
        if addr not in by_addr4:
            raise AssertionError(f"S1-C4 decode missing {addr}")
        validation.append(f"PASS\ts1c4-decode\t{addr}\t{by_addr4[addr].get('name','')}")

    evidence: dict[str, Any] = {
        "format": "smk37-v15-playback-note-live-reanalysis-consumer-v1",
        "scope": {
            "allowed_evidence": ["official v15 app bytes", "current S1-C3 evidence/artifacts", "current S1-C4 evidence/artifacts", "user-provided live result in request"],
            "no_firmware_build": True,
            "no_flash": True,
            "no_usb_or_midi_opened": True,
            "no_v12_assumptions": True,
        },
        "user_live_result_used": {
            "playback_original": "wire packet byte 161 = trigger note 36..51; 16 patches normal",
            "all_c4": "wire packet byte 161 = 60 repeated; transaction failure / Ch1 fallback",
            "deduction_limit": "This falsifies S1-C4's neutral-sideband assumption for byte 161. It does not prove the internal cause of the transaction failure.",
        },
        "inputs": inputs,
        "byte_checks": byte_checks,
        "official_ch10_note_on_consumer": {
            "dispatcher": "0x0201c5ec",
            "channel_register": "r9 = status & 0x0f; Ch10 is r9 == 9",
            "rows": [
                {"address": "0x0201c66a", "bytes": "1d42", "meaning": "r5 = msg[2] velocity"},
                {"address": "0x0201c66c", "bytes": "e1f1a020", "meaning": "r1 = voice index * 0xa0"},
                {"address": "0x0201c670", "bytes": "1e41", "meaning": "r6 = msg[1] trigger/native note"},
                {"address": "0x0201c672", "bytes": "0f1c", "meaning": "r7 = per-voice slot base"},
                {"address": "0x0201c674", "bytes": "00e1a270", "meaning": "r0 = per-voice slot base + 0xa2"},
                {"address": "0x0201c678", "bytes": "623c", "meaning": "r2 = 0x9c copy length"},
                {"address": "0x0201c67a", "bytes": "8116", "meaning": "r1 = current patch source 0x01c34c74"},
                {"address": "0x0201c67c", "bytes": "80ff4cc60200", "meaning": "stock memcpy(voice+0xa2, source, 0x9c)"},
                {"address": "0x0201c682", "bytes": "00e13e71", "meaning": "r0 = voice slot + 0x13e = copy destination + 0x9c"},
                {"address": "0x0201c686", "bytes": "8e40", "meaning": "synth-visible note metadata store consumes r6"},
                {"address": "0x0201c68c", "bytes": "8d42", "meaning": "synth-visible velocity metadata store consumes r5"},
            ],
            "consumer_note_register": "r6",
            "consumer_note_store": "0x0201c686 stores r6 to destination+0x9c",
            "packet_byte_161_role": "not in this official Note On consumer path",
        },
        "official_ch10_note_off_consumer_symmetry": {
            "rows": [
                {"address": "0x0201c62e", "bytes": "1d41", "meaning": "r5 = msg[1] trigger/native note"},
                {"address": "0x0201c63e", "bytes": "80ff8ac60200", "meaning": "stock memcpy(voice+0xa2, source, 0x9c)"},
                {"address": "0x0201c644", "bytes": "00e13e61", "meaning": "r0 = voice slot + 0x13e = copy destination + 0x9c"},
                {"address": "0x0201c648", "bytes": "8d40", "meaning": "synth-visible note metadata store consumes r5"},
            ],
            "consumer_note_register": "r5",
            "reason_for_symmetry": "A playback Note On map without the same Note Off map can leave mismatched release identity.",
        },
        "s1c3_selector_path": {
            "note_on_hook": "0x0201c67c -> 0x0201e142",
            "note_off_hook": "0x0201c63e -> 0x0201e13e",
            "path": [
                "0x0201e142 mov r3,r6: normalize Note On trigger note",
                "0x0201e144 push {rets,r9..r4}: saves/restores r5 velocity and r6 trigger note",
                "0x0201e14a gate r9 == 9: Ch10 only",
                "0x0201e14e/0x0201e152 gate 36 <= trigger note < 52",
                "0x0201e156 slot = trigger note - 36",
                "0x0201e158 base = 0x01c46520",
                "0x0201e168 multiply slot by 0xa0; 0x0201e16e source = base + slot*0xa0",
                "0x0201e174/0x0201e176 require selected slot valid == 1",
                "0x0201e17a r1 = trigger-selected source",
                "0x0201e17c r0 = saved destination",
                "0x0201e17e call memcpy; 0x0201e184 pop restores r6/r5 before stock stores",
            ],
            "delivered_note": "stock 0x0201c686 stores restored r6, so S1-C3 delivers Trigger Note as synth note",
        },
        "s1c4_selector_and_transport_path": {
            "consumer_hook_route": "same Note On/Off hooks as S1-C3, but stock note stores at 0x0201c644 and 0x0201c682 are neutralized",
            "selector_map_path": [
                "0x0201e158 slot = trigger note - 36; Trigger still selects source slot",
                "0x0201e17c map base = 0x01c46520 + 0xa00 = 0x01c46f20",
                "0x0201e182 r5 = playback_map[trigger slot]",
                "0x0201e184 r1 = trigger-selected source, not playback-note-selected source",
                "0x0201e188 call memcpy",
                "0x0201e18e r0 = saved destination + 0x9c",
                "0x0201e192 store r5 as local synth note metadata",
            ],
            "producer_wire_byte_161_path": [
                "0x0201e1e8 r1 = staging + 0x9b, the payload byte that appears as wire packet byte 161",
                "0x0201e1ec r2 = *(staging+0x9b)",
                "0x0201e1ee playback_map[count_slot] = r2",
                "0x0201e1f0/0x0201e1f2 restore staging+0x9b to 0x3f before resident slot copy",
            ],
            "live_reanalysis": "Playback Original works when byte 161 remains trigger 36..51; all-C4 fails when byte 161 is 60 repeated. Therefore byte 161 must be treated as trigger/transaction identity, not a safe playback-note sideband.",
        },
        "minimum_hook": {
            "hook_point": "consumer selector path reached from 0x0201c63e/0x0201c67c, after Ch10/range/ARMED/valid gates and before the synth metadata note store",
            "preserve_trigger_identity": [
                "Do not change the incoming MIDI event buffer msg[1].",
                "Do not change direct-product packet byte 161 away from trigger note 36..51 for resident slot loading.",
                "Do not use playback note P to select source; source_slot = trigger_note - 36 only.",
            ],
            "apply_map": [
                "Let T = proven native trigger register, r6 for Note On and r5 for Note Off.",
                "Let slot = T - 36 after the existing selector range gate.",
                "Let P = playback_map[slot], defaulting to T for Original.",
                "Copy source = 0x01c46520 + slot*0xa0 to the per-voice destination with r2 = 0x9c.",
                "For Note On, deliver P to destination+0x9c while preserving r5 velocity for 0x0201c68c.",
                "For Note Off, deliver the same P to destination+0x9c so release identity matches Note On.",
            ],
            "minimal_code_shape": "S1-C4's consumer-side map load/store shape is the right hook location, but its producer sideband is not: replace the byte161 map writer with an identity-preserving map source, or use a fixed/static map. Until that writer is proven, this remains analysis/minimal-hook guidance, not a flash candidate.",
            "blocked_until_proven": [
                "A per-slot playback_map writer/transport that leaves byte 161 as trigger identity 36..51.",
                "A validation case showing duplicate playback notes do not alter transaction slot identity.",
                "Symmetric Note On and Note Off delivery of P.",
            ],
        },
        "decision": "TRACE PASS; S1-C4 byte161 sideband is rejected by live evidence; minimum safe hook is consumer-side per-slot map after trigger-selected slot validation with byte161 identity preserved.",
    }

    return {"evidence": evidence, "validation": validation}


def write_report(evidence: dict[str, Any]) -> str:
    official = evidence["official_ch10_note_on_consumer"]
    s1c3 = evidence["s1c3_selector_path"]
    s1c4 = evidence["s1c4_selector_and_transport_path"]
    hook = evidence["minimum_hook"]
    lines: list[str] = []
    lines.append("# Playback Note live reanalysis: Ch10 consumer path")
    lines.append("")
    lines.append("Status: **TRACE PASS, no firmware built or flashed**.")
    lines.append("")
    lines.append("## Evidence boundary")
    lines.append("")
    lines.append("Used only official v15 app bytes, current S1-C3/S1-C4 artifacts, and the user-provided live result: Original byte161=trigger 36..51 works for all 16 slots, while all-C4 byte161=60 repeats fail transaction / fall back to Ch1. The live result falsifies the S1-C4 assumption that byte 161 is a neutral playback-note sideband. It does not prove the internal cause of that transaction failure.")
    lines.append("")
    lines.append("## Actual Note On synth consumer")
    lines.append("")
    lines.append("| Address | Bytes | Proven role |")
    lines.append("|---:|---|---|")
    for r in official["rows"]:
        lines.append(f"| `{r['address']}` | `{r.get('bytes','')}` | {r['meaning']} |")
    lines.append("")
    lines.append(f"Conclusion: the stock/S1-C3 synth-visible Note On note is `{official['consumer_note_register']}` stored at `0x0201c686` to `destination+0x9c`. Packet byte 161 is not consumed by this Note On path.")
    lines.append("")
    lines.append("Note Off is symmetric: `0x0201c62e` loads `msg[1]` into `r5`, and `0x0201c648` stores `r5` to the same metadata note position. Any playback map must affect Note On and Note Off together.")
    lines.append("")
    lines.append("## Current S1-C3 selector path")
    lines.append("")
    lines.append(f"- Note On hook: `{s1c3['note_on_hook']}`")
    lines.append(f"- Note Off hook: `{s1c3['note_off_hook']}`")
    for item in s1c3["path"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(f"Result: {s1c3['delivered_note']}.")
    lines.append("")
    lines.append("## Current S1-C4 path and live contradiction")
    lines.append("")
    lines.append(f"- Consumer route: {s1c4['consumer_hook_route']}.")
    lines.append("- Selector map path:")
    for item in s1c4["selector_map_path"]:
        lines.append(f"  - {item}")
    lines.append("- Producer byte161 path:")
    for item in s1c4["producer_wire_byte_161_path"]:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append(s1c4["live_reanalysis"])
    lines.append("")
    lines.append("## Minimum hook that preserves Trigger slot identity")
    lines.append("")
    lines.append(f"Hook point: {hook['hook_point']}.")
    lines.append("")
    lines.append("Must preserve:")
    for item in hook["preserve_trigger_identity"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("Apply map:")
    for item in hook["apply_map"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append(hook["minimal_code_shape"])
    lines.append("")
    lines.append("Blocked until proven:")
    for item in hook["blocked_until_proven"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("Run:")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/playback-note/live-reanalysis/consumer/trace_consumer.py")
    lines.append("shasum -a 256 -c baselines/v15/analysis/playback-note/live-reanalysis/consumer/SHA256SUMS")
    lines.append("```")
    lines.append("")
    lines.append(f"Decision: {evidence['decision']}")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    result = verify()
    evidence = result["evidence"]
    validation = result["validation"]

    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (OUT / "report.md").write_text(write_report(evidence))
    validation_text = "playback-note live consumer reanalysis validation PASS\n" + "\n".join(validation) + "\n"
    (OUT / "validation.txt").write_text(validation_text)

    files = ["trace_consumer.py", "evidence.json", "report.md", "validation.txt"]
    sums = []
    for name in files:
        p = OUT / name
        sums.append(f"{sha256_path(p)}  {name}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    print("playback-note live consumer reanalysis validation PASS")
    print(f"wrote {rel(OUT / 'evidence.json')}")
    print(f"wrote {rel(OUT / 'report.md')}")
    print(f"wrote {rel(OUT / 'validation.txt')}")
    print(f"wrote {rel(OUT / 'SHA256SUMS')}")


if __name__ == "__main__":
    main()
