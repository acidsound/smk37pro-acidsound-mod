#!/usr/bin/env python3
"""Offline-only v15 R03 first-consumer fault analysis.

Reads exact v15 R02/R03 manifests, builders, decoder trace, and prior v15-only
analysis. Writes evidence.json, report.md, validation.txt, and SHA256SUMS in this
same directory. It does not build firmware, patch binaries, flash, or access a
device.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent
ROOT = OUT.parents[5]
sys.path.insert(0, str(ROOT / "tools"))

from build_v15_r01_hand_drum import APP_SHA256, MEMCPY, RUNTIME_BASE, off, sha256  # noqa: E402
from build_v15_r02_sysex_staging import RAM_STAGING, VOICE_SIZE as R02_VOICE_SIZE, build_wrapper  # noqa: E402
from build_v15_r03_fixed_prefix import (  # noqa: E402
    BSS_SIZE_INSN,
    BSS_SIZE_R03,
    HEAP_BEGIN_INSN,
    HEAP_BEGIN_R03,
    LOCK,
    NOTE_OFF_CALL,
    NOTE_ON_CALL,
    PRODUCT_CALLS,
    RESERVED_END,
    SAVE_CALL,
    SAVE_REJECT_BRANCH,
    SAVE_REJECT_CALL,
    STAGING,
    VALID,
    VOICE,
    VOICE_SIZE,
    build_cave,
    call32,
    short_call,
)

R02_APP_SHA = "eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948"
R02_PACKAGE_SHA = "93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b"
R03_APP_SHA = "3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788"
R03_PACKAGE_SHA = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
PACKET_SHA = "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27"

PATHS = {
    "official_app": ROOT / "build/v15-official-app.bin",
    "r02_app": ROOT / "build/v15-R02-sysex-staging-app.bin",
    "r03_app": ROOT / "build/v15-R03-fixed-prefix-app.bin",
    "r02_manifest": ROOT / "baselines/v15/analysis/flash-candidates/R02/app-manifest.json",
    "r03_manifest": ROOT / "baselines/v15/analysis/flash-candidates/R03/app-manifest.json",
    "r02_package_manifest": ROOT / "baselines/v15/analysis/flash-candidates/R02/package-manifest.json",
    "r03_package_manifest": ROOT / "baselines/v15/analysis/flash-candidates/R03/package-manifest.json",
    "r02_live": ROOT / "baselines/v15/analysis/flash-candidates/R02/live-validation-20260802.md",
    "r03_live": ROOT / "baselines/v15/analysis/r03-owned-ram/live-validation-20260802.md",
    "r03_trace": ROOT / "baselines/v15/analysis/flash-candidates/R03/decoder-trace.tsv",
    "r03_trace_provenance": ROOT / "baselines/v15/analysis/flash-candidates/R03/decoder-provenance.json",
    "r02_review": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/r02-review/report.md",
    "sysex_staging": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md",
    "runtime_source": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md",
    "factory_loader": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/report.md",
    "heap_boundary": ROOT / "baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md",
    "heap_prefix": ROOT / "baselines/v15/analysis/r03-owned-ram/heap-prefix-reservation/report.md",
    "atomic_publish": ROOT / "baselines/v15/analysis/r03-owned-ram/atomic-publish/report.md",
    "validator": ROOT / "tools/validate_v15_r03.py",
}


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def hfile(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def read_trace() -> dict[int, list[str]]:
    rows: dict[int, list[str]] = {}
    for line in PATHS["r03_trace"].read_text(encoding="utf-8").splitlines():
        parts = line.split("\t")
        rows[int(parts[0], 16)] = parts
    return rows


def row(rows: dict[int, list[str]], address: int) -> dict[str, str | int]:
    parts = rows[address]
    return {
        "address": f"0x{address:08x}",
        "bytes": parts[1],
        "size": int(parts[2]),
        "mnemonic": parts[3],
        "text": parts[4],
        "flow": parts[5],
        "function": parts[6] if len(parts) > 6 else "-",
    }


def r02_instruction_table() -> list[dict[str, str | int]]:
    wrapper, layout = build_wrapper()
    expected_hex = (
        "7904931683f80a120416c1ffd07fc3014016623c80ff76ab0200590480ff6eab02005904"
    )
    assert wrapper.hex() == expected_hex, wrapper.hex()
    rows = [
        (0x0201E13E, "7904", 2, "push {rets,r9,r8,r7,r6,r5,r4}", "save wrapper callee state"),
        (0x0201E140, "9316", 2, "mov r3,r9", "copy live channel nibble"),
        (0x0201E142, "83f80a12", 4, "jne r3,#0x9,0x0201e15a", "non-Ch10 falls back to stock memcpy"),
        (0x0201E146, "0416", 2, "mov r4,r0", "preserve destination object"),
        (0x0201E148, "c1ffd07fc301", 6, "mov r1,#0x01c37fd0", "R02 source is official SysEx staging"),
        (0x0201E14E, "4016", 2, "mov r0,r4", "restore destination in r0"),
        (0x0201E150, "623c", 2, "mov r2,#0x9c", "copy exactly the runtime voice block"),
        (0x0201E152, "80ff76ab0200", 6, "call 0x02048cce", "memcpy(dest=slot, src=stage, len=0x9c)"),
        (0x0201E158, "5904", 2, "pop {pc,r9,r8,r7,r6,r5,r4}", "return"),
        (0x0201E15A, "80ff6eab0200", 6, "call 0x02048cce", "stock memcpy with untouched r0/r1/r2"),
        (0x0201E160, "5904", 2, "pop {pc,r9,r8,r7,r6,r5,r4}", "return"),
    ]
    return [
        {"address": f"0x{addr:08x}", "bytes": b, "size": size, "text": text, "semantics": sem}
        for addr, b, size, text, sem in rows
    ]


def collect() -> dict:
    official = PATHS["official_app"].read_bytes()
    r02 = PATHS["r02_app"].read_bytes()
    r03 = PATHS["r03_app"].read_bytes()
    r02_manifest = load_json(PATHS["r02_manifest"])
    r03_manifest = load_json(PATHS["r03_manifest"])
    r02_pkg = load_json(PATHS["r02_package_manifest"])
    r03_pkg = load_json(PATHS["r03_package_manifest"])
    trace = read_trace()
    r02_wrapper, r02_layout = build_wrapper()
    r03_cave, r03_layout = build_cave()

    validations: list[tuple[str, bool, str]] = []
    def check(name: str, cond: bool, detail: str):
        validations.append((name, cond, detail))
        if not cond:
            raise AssertionError(f"{name}: {detail}")

    check("official app sha", sha256(official) == APP_SHA256, sha256(official))
    check("R02 app sha", sha256(r02) == R02_APP_SHA, sha256(r02))
    check("R03 app sha", sha256(r03) == R03_APP_SHA, sha256(r03))
    check("R02 manifest package sha", r02_pkg["output"]["sha256"] == R02_PACKAGE_SHA, r02_pkg["output"]["sha256"])
    check("R03 manifest package sha", r03_pkg["output"]["sha256"] == R03_PACKAGE_SHA, r03_pkg["output"]["sha256"])
    check("R02 packet sha", r02_manifest["voice_packet"]["sha256"] == PACKET_SHA, r02_manifest["voice_packet"]["sha256"])
    check("R03 source staging", int(r03_manifest["protocol"]["source"], 16) == STAGING, r03_manifest["protocol"]["source"])
    check("R02 wrapper bytes", r02[off(0x0201E13E):off(0x0201E13E)+len(r02_wrapper)] == r02_wrapper, r02_wrapper.hex())
    check("R03 cave bytes", r03[off(0x0201E13E):off(0x0201E13E)+len(r03_cave)] == r03_cave, r03_cave.hex())
    check("R03 ifeq gap bytes", r03[off(0x0201E1AC):off(0x0201E1B0)].hex() == "40e81b00", r03[off(0x0201E1AC):off(0x0201E1B0)].hex())
    check("R03 Note Off target", r03[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL)+6] == call32(NOTE_OFF_CALL, r03_layout["off_entry"]), r03[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL)+6].hex())
    check("R03 Note On target", r03[off(NOTE_ON_CALL):off(NOTE_ON_CALL)+6] == call32(NOTE_ON_CALL, r03_layout["on_entry"]), r03[off(NOTE_ON_CALL):off(NOTE_ON_CALL)+6].hex())
    for address, _expected, purpose in PRODUCT_CALLS:
        check(f"R03 product call {purpose}", r03[off(address):off(address)+4] == short_call(address, r03_layout["producer"]), r03[off(address):off(address)+4].hex())
    check("R03 BSS patch", r03[off(BSS_SIZE_INSN):off(BSS_SIZE_INSN)+6] == BSS_SIZE_R03, BSS_SIZE_R03.hex())
    check("R03 HEAP_BEGIN patch", r03[off(HEAP_BEGIN_INSN):off(HEAP_BEGIN_INSN)+6] == HEAP_BEGIN_R03, HEAP_BEGIN_R03.hex())
    check("R03 SAVE reject", r03[off(SAVE_REJECT_CALL):off(SAVE_REJECT_CALL)+4] == SAVE_REJECT_BRANCH, SAVE_REJECT_BRANCH.hex())
    check("R03 SAVE packer neutralized", r03[off(SAVE_CALL):off(SAVE_CALL)+4] == b"\0"*4, r03[off(SAVE_CALL):off(SAVE_CALL)+4].hex())
    check("R03 owned voice/valid adjacency", VOICE + VOICE_SIZE == VALID, f"voice=0x{VOICE:x} valid=0x{VALID:x}")
    check("R03 owned reservation size", RESERVED_END - VOICE == 0xA0, f"0x{RESERVED_END - VOICE:x}")
    check("R02 and R03 voice copy size", R02_VOICE_SIZE == VOICE_SIZE == 0x9C, f"R02={R02_VOICE_SIZE} R03={VOICE_SIZE}")
    check("R02/R03 same staging address", RAM_STAGING == STAGING == 0x01C37FD0, f"0x{STAGING:08x}")

    selected_r03_trace = [
        row(trace, a) for a in [
            0x0201C630, 0x0201C636, 0x0201C63A, 0x0201C63C, 0x0201C63E,
            0x0201C666, 0x0201C66C, 0x0201C674, 0x0201C678, 0x0201C67A, 0x0201C67C,
            0x0201E13E, 0x0201E140, 0x0201E142, 0x0201E146, 0x0201E148, 0x0201E14E,
            0x0201E150, 0x0201E154, 0x0201E156, 0x0201E15C, 0x0201E15E, 0x0201E164,
            0x0201E166, 0x0201E16C, 0x0201E16E, 0x0201E170, 0x0201E172, 0x0201E176,
            0x0201E178, 0x0201E17E, 0x0201E180, 0x0201E184, 0x0201E186, 0x0201E18C,
            0x0201E18E, 0x0201E194, 0x0201E196, 0x0201E19C, 0x0201E19E, 0x0201E1A0,
            0x0201E1A2, 0x0201E1A8, 0x0201E1AA, 0x0201E1B0, 0x0201E1B2, 0x0201E1B8,
            0x0201E1BA, 0x0201E1BE, 0x0201E1C4, 0x0201E1C6, 0x0201E1C8, 0x0201E1CE,
            0x0201E1D4, 0x0201E1D6, 0x0201E1D8, 0x0201E1DE, 0x0201E1E0, 0x0201E1E2,
            0x0201E1E4, 0x0201E1E6, 0x0201E468, 0x0201E46C, 0x0201E49C, 0x0201E4A0,
        ]
    ]
    selected_r03_trace.append({
        "address": "0x0201e1ac",
        "bytes": "40e81b00",
        "size": 4,
        "mnemonic": "ifeq",
        "text": "ifeq goto 0x0201e1e6",
        "flow": "CONDITIONAL_JUMP",
        "function": "decoder gap documented by decoder-provenance.json and official objdump",
    })
    selected_r03_trace.sort(key=lambda item: int(str(item["address"]), 16))

    evidence = {
        "scope": "exact v15 offline evidence only; no device access, patching, flashing, or binary modification",
        "paths": {k: rel(v) for k, v in PATHS.items()},
        "path_hashes": {k: hfile(v) for k, v in PATHS.items() if v.exists() and v.is_file()},
        "artifacts": {
            "official_app_sha256": sha256(official),
            "r02_app_sha256": sha256(r02),
            "r02_package_sha256": r02_pkg["output"]["sha256"],
            "r03_app_sha256": sha256(r03),
            "r03_package_sha256": r03_pkg["output"]["sha256"],
            "shared_mooger_packet_sha256": PACKET_SHA,
            "r02_changed_app_bytes": r02_pkg["changes"]["app_byte_count"],
            "r03_changed_app_bytes": r03_pkg["changes"]["app_byte_count"],
        },
        "live_evidence": {
            "r02_result": "PASS controlled checkpoint; Pad Ch10 matched Mooger #1, Note Off worked, Ch1 UI patch change did not overwrite Ch10",
            "r03_result": "LIVE FAIL; first physical Pad Ch10 input after exact product packet immediately rebooted",
            "r02_live_path": rel(PATHS["r02_live"]),
            "r03_live_path": rel(PATHS["r03_live"]),
        },
        "r02_wrapper": {
            "layout": {k: f"0x{v:08x}" for k, v in r02_layout.items()},
            "bytes": r02_wrapper.hex(),
            "instructions": r02_instruction_table(),
            "semantics": {
                "entry_shared_by_note_on_off": "0x0201e13e",
                "channel_register": "r9 copied to r3; Ch10 nibble is 9",
                "destination": "r0 preserved in r4 then restored before memcpy",
                "source": "r1 = 0x01c37fd0 official SysEx staging only for Ch10",
                "copy": "memcpy(r0=destination, r1=0x01c37fd0, r2=0x9c)",
                "stock_fallback": "non-Ch10 calls original memcpy with untouched stock arguments",
                "producer_or_owner": "none; product-packer calls are neutralized, so publication is the stock handler staging copy",
            },
        },
        "r03_wrapper_and_producer": {
            "layout": {k: f"0x{v:08x}" for k, v in r03_layout.items()},
            "owned_ram": {"voice": f"0x{VOICE:08x}..0x{VALID:08x}", "valid": f"0x{VALID:08x}", "lock": f"0x{LOCK:08x}", "end": f"0x{RESERVED_END:08x}", "size": "0xa0"},
            "selected_trace": selected_r03_trace,
            "consumer_semantics": {
                "note_off_entry": "0x0201e13e",
                "note_on_entry": "0x0201e16e",
                "channel_register": "r9 copied to r3; Ch10 nibble is 9",
                "valid_probe": "load byte from 0x01c465bc; owned source only if value == 1",
                "destination": "r0 preserved in r5 and restored before owned memcpy",
                "owned_source": "r1 = 0x01c46520",
                "copy": "memcpy(r0=destination, r1=0x01c46520, r2=0x9c)",
                "stock_fallback": "non-Ch10 or valid!=1 calls original memcpy with untouched stock r0/r1/r2",
            },
            "producer_semantics": {
                "producer_calls": ["0x0201e468", "0x0201e49c"],
                "source_pointer": "r0 = 0x01c37fd0 from accepted product handler, preserved in r4",
                "trylock": "csync; testset b[0x01c465bd]; ifeq returns at 0x0201e1e6; official object says fall-through means acquired",
                "already_valid": "if valid != 0, branch to unlock without recopying",
                "copy_direction": "memcpy(r0=0x01c46520 destination, r1=r4 accepted staging source, r2=0x9c)",
                "publish_order": "store valid=1 at 0x01c465bc after memcpy; then unlock lock byte",
                "publication_assessment": "more likely than not published after the exact product packet, because lock and valid boot zero, callsites reach producer after final-F7 gates, source pointer is the same live-proven R02 staging pointer, and failure waited for first consumer rather than packet send in the recorded sequence",
            },
        },
        "delta_matrix": [
            {"topic": "consumer callsites", "r02": "both Note Off and Note On call 0x0201e13e", "r03": "Note Off calls 0x0201e13e; Note On calls 0x0201e16e", "risk": "low; ABI is preserved and R03 trace validates both calls"},
            {"topic": "channel register", "r02": "r9 -> r3, compare to 9", "r03": "same", "risk": "low"},
            {"topic": "memcpy destination", "r02": "stock dispatcher r0, preserved/restored", "r03": "same, preserved in r5", "risk": "low"},
            {"topic": "memcpy source", "r02": "0x01c37fd0 transient staging", "r03": "0x01c46520 former heap-prefix owned buffer after valid==1", "risk": "high; first live fault appears only when this new owned source is selected"},
            {"topic": "copy size", "r02": "0x9c", "r03": "0x9c", "risk": "low for direct copy overrun; no R03 copy exceeds the live-proven tone block"},
            {"topic": "producer", "r02": "no new producer; handler copy populates staging and stock packer calls are zeroed", "r03": "product calls short-call producer, then stock reload remains", "risk": "medium; publication is new but source pointer and memcpy ABI are simple"},
            {"topic": "RAM ownership", "r02": "uses official staging workspace without claiming ownership", "r03": "extends BSS and shifts HEAP_BEGIN by 0xa0", "risk": "highest; previous exact-v15 heap-boundary analysis warned no complete allocator/task/DMA no-alias proof"},
            {"topic": "0xa0 vs 0x9c tail", "r02": "consumer reads only first 0x9c from staging", "r03": "owned object is exactly 0xa0: 0x9c voice + valid + lock + 2 reserved bytes", "risk": "not a direct memcpy overrun, but it removes the earlier 0xa4/0xc0 metadata/generation margin and puts metadata at the old heap base tail"},
            {"topic": "cache/sync", "r02": "no new data publish", "r03": "csync around testset/unlock, no explicit csync between voice memcpy and valid store", "risk": "medium-low; could matter for weak ordering, DMA, or cross-context visibility, but less supported than heap/source fault"},
        ],
        "ranked_hypotheses": [
            {
                "rank": 1,
                "name": "first consumer selects a published owned source at the former heap lower bound and triggers an allocator/audio/hidden-owner fault",
                "likelihood": "high",
                "evidence_for": [
                    "R02 live success proves the same Pad Ch10 dispatcher, r9 channel test, r0 destination, r2=0x9c length, and Mooger payload can work when source is 0x01c37fd0.",
                    "R03 changes the source to 0x01c46520 only after valid==1 and also changes BSS/HEAP_BEGIN to claim 0x01c46520..0x01c465c0.",
                    "The recorded R03 failure occurs on first Pad Ch10 input after product packet, exactly when the consumer first reads valid and then copies from the new owned source.",
                    "Prior exact-v15 heap-boundary evidence explicitly blocked heap/gap ownership without complete allocator/task/DMA/high-water proof.",
                ],
                "evidence_against": [
                    "The R03 app did boot and accepted enough host traffic to send the packet, so not every use of the shifted heap boundary is immediately fatal.",
                    "The sbrk HEAP_BEGIN literal was later identified and patched consistently, reducing but not eliminating hidden consumer risk.",
                ],
                "first_fault_model": "producer publishes valid=1; Note On wrapper copies 0x9c bytes from 0x01c46520; the owned range or reduced heap collides with first-note allocator/audio state or leaves first-note allocation without required headroom, causing reboot shortly after the consumer call.",
            },
            {
                "rank": 2,
                "name": "R03 publication/order/cache visibility bug exposes malformed or partially visible owned voice to the first consumer",
                "likelihood": "medium-low",
                "evidence_for": [
                    "R03 has a new cross-context publication protocol and no explicit csync immediately between memcpy completion and valid=1.",
                    "The first post-publish consumer is the first time the voice is used by the event/audio path.",
                ],
                "evidence_against": [
                    "memcpy is an ordinary CPU call in exact traces, consumers are CPU memcpy callers too, and R03 does use csync around lock/unlock.",
                    "A visibility race would be timing-sensitive; the report says the first physical pad reliably rebooted rather than intermittent corruption.",
                ],
                "first_fault_model": "valid becomes observable before the complete owned voice is safely observable to the consumer/audio path.",
            },
            {
                "rank": 3,
                "name": "hidden 0xa0/0xa3 tail dependency not represented by R03's 0x9c-only owned copy",
                "likelihood": "low-medium",
                "evidence_for": [
                    "Factory-loader evidence shows live current snapshot has meaningful bytes at 0x9c..0xa2 and helper side effects from 0x9c..0x9f.",
                    "Earlier requirements discussed at least 0xa0 of voice plus metadata, and earlier heap-prefix design allowed 0xc0, while final R03 reserves only 0xa0 and copies only 0x9c.",
                ],
                "evidence_against": [
                    "The exact Note On/Off consumer memcpy length is 0x9c in both R02 and R03.",
                    "R02's live success proves the first 0x9c runtime Mooger payload is sufficient for the constrained audible Pad Ch10 path.",
                    "Stock per-voice event metadata after the 0x9c destination copy is written by the dispatcher, not sourced from 0x01c46520+0x9c.",
                ],
                "first_fault_model": "some downstream path, not the immediate dispatcher memcpy, dereferences source-adjacent or current-snapshot tail state that R03 did not preserve.",
            },
            {
                "rank": 4,
                "name": "producer did not publish; consumer fallback or valid probe itself faults",
                "likelihood": "low",
                "evidence_for": [
                    "No live RAM readback exists, so publication is inferred, not proven.",
                    "If the product packet was not accepted, valid would remain zero.",
                ],
                "evidence_against": [
                    "With valid=0, R03 falls back to stock memcpy with untouched stock r0/r1/r2, close to the R02/R01 live-booted primitive.",
                    "The valid byte is in the BSS-extended reserved range, and boot success argues a simple byte load from that RAM is not enough to fault.",
                ],
                "first_fault_model": "valid load or branch/fallback faults before owned memcpy, despite not selecting the owned source.",
            },
            {
                "rank": 5,
                "name": "PI32 call/ABI/register/stack mismatch in R03 consumer wrappers",
                "likelihood": "low",
                "evidence_for": ["R03 wrappers are longer and have separate entries, unlike R02."],
                "evidence_against": [
                    "Both wrappers save/restore {rets,r9..r4}; r0 destination is preserved/restored; r1/r2 are set exactly for memcpy; stock fallback preserves original r0/r1/r2.",
                    "Decoder trace and validator bind every relevant call target and instruction byte.",
                ],
                "first_fault_model": "misdecoded branch/call or clobbered register causes bad memcpy arguments, but exact bytes make this less likely.",
            },
        ],
        "safest_next_discriminating_checkpoint": {
            "name": "offline-prepare, later-live heap-only H0 before any owned-source consumer retry",
            "current_task_action": "Do not patch or flash now. Only build/review offline if requested.",
            "proposal": [
                "Create an exact v15 H0 candidate that applies only the two R03 memory-boundary patches: BSS zero length through the shifted HEAP_BEGIN and HEAP_BEGIN=0x01c465c0. Leave Note On/Off, product/SAVE calls, and the packer stock.",
                "If live testing is later authorized with rollback ready, test only normal boot, identity, and one stock Pad Ch10 Note On/Off with no product packet and no SAVE.",
                "If H0 reboots on first pad, the former-heap-prefix/allocator/audio-owner hypothesis is strongly confirmed and R03 owned-source work should stop.",
                "If H0 passes, the next lower-risk discriminator is H1: R02 live-success consumers from 0x01c37fd0 plus R03 producer present but unconsumed, still without using 0x01c46520 as a Note source.",
            ],
            "why_safest": "It removes the new owned-source memcpy and producer from the first live discriminator, testing the highest-ranked heap-prefix hypothesis with the fewest event-path changes.",
        },
        "validations": [{"name": n, "status": "PASS" if ok else "FAIL", "detail": d} for n, ok, d in validations],
    }
    return evidence


def md_table(rows: list[dict], columns: list[str]) -> str:
    out = ["| " + " | ".join(columns) + " |", "| " + " | ".join(["---"] * len(columns)) + " |"]
    for r in rows:
        out.append("| " + " | ".join(str(r.get(c, "")).replace("|", "\\|") for c in columns) + " |")
    return "\n".join(out)


def write_report(e: dict) -> None:
    r02i = e["r02_wrapper"]["instructions"]
    r03_sel = e["r03_wrapper_and_producer"]["selected_trace"]
    r03_cons = [x for x in r03_sel if str(x["address"]).startswith("0x0201e1") is False and str(x["address"]) < "0x0201e19e"]
    lines = []
    lines += [
        "# v15 R03 first Pad Ch10 reboot: first-consumer analysis",
        "",
        "Scope: exact v15 offline evidence only. No device access, patching, flashing, or binary modification was performed by this analysis.",
        "",
        "## Bottom line",
        "",
        "The most likely first fault is not an obvious PI32 call ABI bug. R02 and R03 both preserve the stock dispatcher ABI: `r9` is the channel register, `r0` is the destination voice object, `r2` is `0x9c`, and non-Ch10 fallback calls the original `memcpy` with untouched arguments.",
        "",
        "The highest-ranked fault is that R03 probably **did publish** and the first Pad Ch10 consumer then selected the new owned source at `0x01c46520`, a former heap-prefix range created by shifting `HEAP_BEGIN`. That live-only transition is absent from R02 and coincides with first-note allocator/audio activity.",
        "",
        "## Exact live evidence",
        "",
        f"- R02 PASS report: `{e['live_evidence']['r02_live_path']}`.",
        f"- R03 FAIL report: `{e['live_evidence']['r03_live_path']}`.",
        f"- Shared Mooger packet SHA-256: `{e['artifacts']['shared_mooger_packet_sha256']}`.",
        f"- R02 app/package: `{e['artifacts']['r02_app_sha256']}` / `{e['artifacts']['r02_package_sha256']}`.",
        f"- R03 app/package: `{e['artifacts']['r03_app_sha256']}` / `{e['artifacts']['r03_package_sha256']}`.",
        "",
        "R02 live succeeded after the exact packet: Pad Ch10 matched Mooger #1, Note Off worked, and Ch1 UI patch changes did not overwrite Ch10. R03 live installed, sent the exact packet, and rebooted on the first physical Pad Ch10 input.",
        "",
        "## R02 live-success consumer wrapper",
        "",
        f"Layout: `{e['r02_wrapper']['layout']}`.",
        "",
        md_table(r02i, ["address", "bytes", "text", "semantics"]),
        "",
        "R02 has no new producer. It relies on the official accepted SysEx handler to copy the product payload to `0x01c37fd0`, zeros all three stock packer calls, and has Note On and Note Off share the same wrapper/source path.",
        "",
        "## R03 consumer and producer path",
        "",
        f"Layout: `{e['r03_wrapper_and_producer']['layout']}`.",
        f"Owned RAM: `{e['r03_wrapper_and_producer']['owned_ram']}`.",
        "",
        "Selected exact decoder rows, including the documented decoder gap at `0x0201e1ac`: ",
        "",
        md_table(e["r03_wrapper_and_producer"]["selected_trace"], ["address", "bytes", "text", "function"]),
        "",
        "### R03 publication assessment",
        "",
        e["r03_wrapper_and_producer"]["producer_semantics"]["publication_assessment"],
        "",
        "Reasons: the product callsites are after the final-`F7` gates, pass `r0 = 0x01c37fd0`, lock and valid are boot-zeroed by the R03 BSS extension, the official PI32 object establishes that `testset` fall-through is the acquired path, and the reported reboot happens on first Pad input rather than during the packet send. This is still inferred because there is no live RAM readback.",
        "",
        "## Delta matrix",
        "",
        md_table(e["delta_matrix"], ["topic", "r02", "r03", "risk"]),
        "",
        "## Hidden `0xa0` versus `0x9c` tail dependency",
        "",
        "The immediate dispatcher copy is `0x9c` in both R02 and R03, so there is no direct source overread in the Note On/Off `memcpy`. Stock per-voice destination metadata follows the copied block and is written by the dispatcher at the destination, not copied from the source.",
        "",
        "However, exact factory-loader evidence shows the live current snapshot has meaningful tail bytes at `0x9c..0xa2` and loader side effects from `0x9c..0x9f`, with `0xa0/+0xa1` postprocessed from `0x86/+0x87` for the clean Mooger path. That makes tail dependency a real system concern, but it ranks below heap-prefix/source ownership for the first reboot because R02 already proved the first `0x9c` bytes are enough for the constrained Pad Ch10 audible path.",
        "",
        "## Ranked hypotheses",
        "",
    ]
    for h in e["ranked_hypotheses"]:
        lines += [
            f"### {h['rank']}. {h['name']} ({h['likelihood']})",
            "",
            "Evidence for:",
        ]
        lines += [f"- {x}" for x in h["evidence_for"]]
        lines += ["", "Evidence against:"]
        lines += [f"- {x}" for x in h["evidence_against"]]
        lines += ["", f"First-fault model: {h['first_fault_model']}", ""]
    nxt = e["safest_next_discriminating_checkpoint"]
    lines += [
        "## Safest next discriminating checkpoint",
        "",
        f"**{nxt['name']}**",
        "",
        nxt["current_task_action"],
        "",
    ]
    lines += [f"{i+1}. {x}" for i, x in enumerate(nxt["proposal"])]
    lines += ["", f"Why: {nxt['why_safest']}", ""]
    lines += [
        "## Reproduce",
        "",
        "```sh",
        "cd /Users/spectrum/Documents/SMK37ProMod",
        "PYTHONPATH=tools python3 baselines/v15/analysis/r03-owned-ram/live-failure/consumer/analyze_consumer_fault.py",
        "cd baselines/v15/analysis/r03-owned-ram/live-failure/consumer",
        "shasum -a 256 -c SHA256SUMS",
        "```",
        "",
    ]
    (OUT / "report.md").write_text("\n".join(lines), encoding="utf-8")


def write_validation(e: dict) -> None:
    lines = ["# v15 R03 first-consumer validation", ""]
    for v in e["validations"]:
        lines.append(f"{v['status']}\t{v['name']}\t{v['detail']}")
    lines += ["", "OVERALL PASS"]
    (OUT / "validation.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_sums() -> None:
    files = ["analyze_consumer_fault.py", "evidence.json", "report.md", "validation.txt"]
    lines = []
    for name in files:
        data = (OUT / name).read_bytes()
        lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
    (OUT / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    e = collect()
    (OUT / "evidence.json").write_text(json.dumps(e, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_report(e)
    write_validation(e)
    write_sums()
    print("consumer live-failure offline analysis: PASS")
    print(f"wrote {rel(OUT / 'report.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
