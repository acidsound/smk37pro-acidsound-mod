#!/usr/bin/env python3
"""v15-only runtime source trace for 0x01c34c74.

Read-only extractor. It consumes the official v15 app plus the already generated
Quarkslab/Kagaimiq TSV listings, then writes JSON and Markdown evidence under
this directory. It does not patch, flash, or use v12-derived offsets.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
QUARK = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
KAGA = LISTING_DIR / "kagaimiq-patched-exhaustive-listing.tsv.gz"
PROVENANCE = LISTING_DIR / "provenance.txt"

BASE = 0x02000000
RAM_BASE = 0x01C33260
CURRENT_OFFSET = 0x1A14
CURRENT = RAM_BASE + CURRENT_OFFSET
CURRENT_LEN_NOTE_COPY = 0x9C
CURRENT_END_NOTE_COPY = CURRENT + CURRENT_LEN_NOTE_COPY
CURRENT_PACKED_RECORD_LEN = 0xA3
RECORD_BASE_BIAS = 0x4000
VOICE_SLOT_STRIDE = 0xA0
VOICE_SLOT_COPY_OFFSET = 0xA2
MEMCPY = 0x02048CCE
STORAGE_XFER = 0x02004B02
PACK_CURRENT_TO_STORAGE = 0x0201E13E
FACTORY_LOADER = 0x02005660
DISPATCHER = 0x0201C5EC
UI_SYSEX_HANDLER = 0x0201E254

EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quarkslab_exhaustive_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kagaimiq_patched_exhaustive_sha256": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

RANGES = {
    "factory_loader_02005660": (0x02005660, 0x020057DE),
    "factory_loader_caller_bank_preset_020241e0": (0x020241E0, 0x0202423A),
    "bank_block_change_loader_caller_0202553c": (0x0202553C, 0x020255AA),
    "ui_sysex_current_patch_handler_0201e254": (0x0201E254, 0x0201E648),
    "current_patch_packer_0201e13e": (0x0201E13E, 0x0201E252),
    "current_field_setter_86_0201bbc6": (0x0201BBC6, 0x0201BBF4),
    "current_field_setter_87_0201bbf6": (0x0201BBF6, 0x0201BC24),
    "active_voice_field_propagator_0201bb80": (0x0201BB80, 0x0201BBC4),
    "ui_handler_base_anchor_02024ff8": (0x02024FF8, 0x02025008),
    "ui_mode_reset_writer_02027df6": (0x02027DF6, 0x02027E3C),
    "note_dispatcher_0201c5ec": (0x0201C5EC, 0x0201C720),
    "dispatcher_small_wrapper_0201c722": (0x0201C722, 0x0201C73A),
    "save_writer_candidate_02026d6c": (0x02026D6C, 0x02026DD8),
    "storage_transfer_wrapper_02004a54_02004b14": (0x02004A54, 0x02004B14),
    "storage_read_comparator_020047d8_02004882": (0x020047D8, 0x02004882),
    "memcpy_02048cce": (0x02048C96, 0x02048D40),
}

SEARCH_TERMS = [
    "0x1c34c74", "0x1c33260", "0x1a14", "0x1a24", "0x1a90", "0x1a9a",
    "0x1a9b", "0x1aa0", "0x1aae", "0x1ab0",
    "0x02005660", "0x0201c5ec", "0x0201e13e", "0x02004b02", "0x02048cce",
]

TARGET_CALLS = [
    FACTORY_LOADER, DISPATCHER, 0x0201C722, PACK_CURRENT_TO_STORAGE, STORAGE_XFER, MEMCPY,
    0x0201BBC6, 0x0201BBF6, 0x0201BB80,
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def h(value: int | None, width: int = 8) -> str | None:
    return None if value is None else f"0x{value:0{width}x}"


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_out(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def row_line(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"])


def rows_between(rows: list[dict[str, str]], lo: int, hi: int) -> list[dict[str, str]]:
    return [row_out(r) for r in rows if lo <= row_addr(r) <= hi]


def listing_hits(rows: list[dict[str, str]], terms: list[str], limit: int = 120) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for term in terms:
        out[term] = [row_out(r) for r in rows if term.lower() in row_line(r).lower()][:limit]
    return out


def call_xrefs(rows: list[dict[str, str]], targets: list[int]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for target in targets:
        key = h(target)
        assert key is not None
        out[key] = [row_out(r) for r in rows if r["mnemonic"] == "call" and key in r["text"].lower()]
    return out


def raw_pointer_xrefs(app: bytes, values: dict[str, int]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in values.items():
        pat = struct.pack("<I", value)
        refs: list[str] = []
        i = 0
        while True:
            j = app.find(pat, i)
            if j < 0:
                break
            refs.append(h(BASE + j) or "")
            i = j + 1
        out[name] = {"value": h(value), "count": len(refs), "refs": refs}
    return out


def validate_evidence(evidence: dict[str, Any], rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def check(name: str, condition: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})

    manifest = json.loads(MANIFEST.read_text())
    check("official-v15-app-sha256", evidence["sha256"]["app"] == EXPECTED["app_sha256"], evidence["sha256"]["app"])
    check("official-v15-package-sha256", evidence["sha256"]["package"] == EXPECTED["package_sha256"], evidence["sha256"]["package"])
    check("manifest-app-gate", manifest.get("app_sha256") == EXPECTED["app_sha256"], str(manifest.get("app_sha256")))
    check("manifest-package-gate", manifest.get("package_sha256") == EXPECTED["package_sha256"], str(manifest.get("package_sha256")))
    check("quarkslab-listing-sha256", evidence["sha256"]["quarkslab_exhaustive"] == EXPECTED["quarkslab_exhaustive_sha256"], evidence["sha256"]["quarkslab_exhaustive"])
    check("kagaimiq-listing-sha256", evidence["sha256"]["kagaimiq_patched_exhaustive"] == EXPECTED["kagaimiq_patched_exhaustive_sha256"], evidence["sha256"]["kagaimiq_patched_exhaustive"])
    check("alias-arithmetic", RAM_BASE + CURRENT_OFFSET == CURRENT, f"0x{RAM_BASE:08x}+0x{CURRENT_OFFSET:x}=0x{CURRENT:08x}")
    direct = evidence["raw_xrefs"]["current_source_buffer_0x01c34c74"]
    check("single-direct-current-immediate", direct["count"] == 1 and direct["refs"] == ["0x0201c604"], json.dumps(direct, sort_keys=True))

    expected_rows = {
        0x02005694: "add r0,r4,0x1a14",
        0x0200569A: "call 0x02048cce",
        0x0201BBE4: "sb r0,[r6 + r5]",
        0x0201BC14: "sb r0,[r6 + r5]",
        0x0201E634: "sb r1,[r0 + r2]",
        0x02024FFE: "mov r8,#0x1c33260",
        0x02027E2E: "sb r5,[r8 + r0]",
        0x0201C63E: "call 0x02048cce",
        0x0201C67C: "call 0x02048cce",
        0x02004866: "call 0x02048cce",
        0x02004B0A: "call 0x02004a7a",
    }
    by_addr = {row_addr(row): row for row in rows}
    for address, text in expected_rows.items():
        row = by_addr.get(address)
        check(f"listing-row-0x{address:08x}", row is not None and text in row["text"], row["text"] if row else "missing")

    direct_calls = evidence["direct_call_xrefs"]["quarkslab"]
    loader_callers = {int(row["address"], 16) for row in direct_calls[h(FACTORY_LOADER) or ""]}
    dispatcher_callers = {int(row["address"], 16) for row in direct_calls[h(DISPATCHER) or ""]}
    setter86_callers = {int(row["address"], 16) for row in direct_calls["0x0201bbc6"]}
    setter87_callers = {int(row["address"], 16) for row in direct_calls["0x0201bbf6"]}
    propagator_callers = {int(row["address"], 16) for row in direct_calls["0x0201bb80"]}
    check("factory-loader-callers", loader_callers == {0x02005F9C, 0x0201E46C, 0x0201E4A0, 0x0202422E, 0x020255A6}, ",".join(f"0x{x:08x}" for x in sorted(loader_callers)))
    check("dispatcher-callers", dispatcher_callers == {0x0201C736, 0x0201E644}, ",".join(f"0x{x:08x}" for x in sorted(dispatcher_callers)))
    check("bounded-setter-direct-callers", not setter86_callers and not setter87_callers, f"field86={sorted(setter86_callers)},field87={sorted(setter87_callers)}")
    check("active-voice-propagator-callers", propagator_callers == {0x0201BBF2, 0x0201BC22}, ",".join(f"0x{x:08x}" for x in sorted(propagator_callers)))

    required_roles = {
        "record_loader_to_current_snapshot",
        "packed_record_normalization_inside_current_snapshot",
        "global_tail_normalization_inside_current_snapshot",
        "single_parameter_current_patch_write",
        "bounded_setter_current_field_0x86",
        "bounded_setter_current_field_0x87",
        "ui_mode_entry_reset_current_field_0x9a",
        "bulk_ui_patch_block_to_storage_then_current_snapshot_reload",
        "bank_or_preset_selection_reload",
        "save_path_reads_current_snapshot",
        "note_off_copy_current_to_voice_slot",
        "note_on_copy_current_to_voice_slot",
    }
    roles = {item["role"] for item in evidence["current_source_trace"]["writers_and_producers"]}
    check("writer-producer-role-coverage", required_roles <= roles, ",".join(sorted(required_roles - roles)) or "complete")
    check("v12-excluded", all("v12" not in path.lower() for path in evidence["scope"]["inputs"]), json.dumps(evidence["scope"]["inputs"]))

    failed = [item for item in checks if item["status"] != "PASS"]
    if failed:
        raise SystemExit("validation failed: " + json.dumps(failed, ensure_ascii=False))
    return checks


def write_inventory(items: list[dict[str, Any]]) -> None:
    with (OUT / "writer_inventory.tsv").open("w", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(["role", "kind", "destination", "source", "length", "evidence_addresses"])
        for item in items:
            writer.writerow([
                item["role"], item["kind"], item.get("destination") or "", item.get("source") or "",
                item.get("length") or "", ",".join("0x" + row["address"] for row in item["evidence"]),
            ])


def write_validation(checks: list[dict[str, Any]]) -> None:
    lines = [f"{item['status']}\t{item['name']}\t{item['detail']}" for item in checks]
    lines.append(f"PASS\tcheck-count\t{len(checks)}")
    (OUT / "validation.txt").write_text("\n".join(lines) + "\n")


def write_sha256sums() -> None:
    names = ["trace_runtime_source.py", "runtime_source_trace.json", "report.md", "writer_inventory.tsv", "validation.txt"]
    (OUT / "SHA256SUMS").write_text("\n".join(f"{sha256(OUT / name)}  {name}" for name in names) + "\n")



def find_direct_current_writers(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Targeted alias trace for the current snapshot region.

    This is deliberately conservative and records the rows that construct a
    base+0x1a14 destination or store through a base+0x1a14 alias in the known
    v15 functions. It is not a general decompiler.
    """
    writers: list[dict[str, Any]] = []

    def add(kind: str, role: str, evidence_rows: list[int], summary: str, dest: str | None = None, src: str | None = None, length: int | None = None):
        ev = []
        for addr in evidence_rows:
            hit = next((r for r in rows if row_addr(r) == addr), None)
            if hit is None:
                raise ValueError(f"required listing row missing: 0x{addr:08x}")
            ev.append(row_out(hit))
        writers.append({
            "kind": kind,
            "role": role,
            "destination": dest,
            "source": src,
            "length": h(length, 2) if length is not None else None,
            "summary": summary,
            "evidence": ev,
        })

    add(
        "memcpy",
        "record_loader_to_current_snapshot",
        [0x02005682, 0x0200568A, 0x02005690, 0x02005694, 0x02005698, 0x0200569A],
        "0x02005660 computes (selected_bank*32+selected_preset)*0xa3 from *(0x01c33260+0x164), adds 0x4000, and memcpy()s 0xa3 bytes into 0x01c33260+0x1a14.",
        dest="0x01c33260+0x1a14 == 0x01c34c74",
        src="*(0x01c33260+0x164)+0x4000+(bank*32+preset)*0xa3",
        length=0xA3,
    )
    add(
        "field_wise_expand",
        "packed_record_normalization_inside_current_snapshot",
        [0x020056B4, 0x020056B6, 0x020056C0, 0x020056C4, 0x020056C6, 0x020056D0, 0x020056D2, 0x020056DE, 0x0200570E],
        "After the raw 0xa3 copy, 0x02005660 loops over 0x7e bytes in 0x15-byte logical operator blocks and rewrites unpacked fields into the same current snapshot area starting at +0x1a14 and +0x1a24.",
        dest="0x01c33260+0x1a14..+0x1a91 field aliases",
        src="selected packed bank record bytes",
    )
    add(
        "field_wise_expand",
        "global_tail_normalization_inside_current_snapshot",
        [0x02005712, 0x02005720, 0x02005726, 0x02005746, 0x02005764, 0x02005768],
        "0x02005660 also expands the record tail into +0x1a90/+0x1aa0 and reads +0x1ab0 flags that drive helper updates.",
        dest="0x01c33260+0x1a90 and 0x01c33260+0x1aa0",
        src="selected packed bank record tail",
    )
    add(
        "field_write",
        "single_parameter_current_patch_write",
        [0x0201E622, 0x0201E626, 0x0201E62A, 0x0201E630, 0x0201E632, 0x0201E634],
        "0x0201e254 recognizes a 7-byte F0 43 10 ... F7 message and stores msg[5] to 0x01c33260+0x1a14+(((msg[3]<<7)+msg[4]) & 0xff). It overlaps the dispatcher's source exactly when idx is 0x00..0x9b; idx 0x9c..0xff writes the following current-record tail/object bytes instead.",
        dest="0x01c33260+0x1a14+(parameter_index & 0xff)",
        src="UI/SysEx message byte msg[5]",
        length=1,
    )
    add(
        "field_write",
        "bounded_setter_current_field_0x86",
        [0x0201BBC8, 0x0201BBCC, 0x0201BBD2, 0x0201BBE0, 0x0201BBE4, 0x0201BBE8, 0x0201BBF2],
        "The setter beginning at 0x0201bbc6 clamps an input delta to 0..31, writes the result to obj+0x1a9a (current+0x86), mirrors it outside the 0x9c copy at obj+0x1ab4, and calls 0x0201bb80 to propagate the paired fields to active voice state.",
        dest="0x01c34c74+0x86 == 0x01c34cfa",
        src="clamped current field plus caller-supplied delta",
        length=1,
    )
    add(
        "field_write",
        "bounded_setter_current_field_0x87",
        [0x0201BBF8, 0x0201BBFC, 0x0201BC02, 0x0201BC10, 0x0201BC14, 0x0201BC18, 0x0201BC22],
        "The setter beginning at 0x0201bbf6 clamps an input delta to 0..7, writes the result to obj+0x1a9b (current+0x87), mirrors it outside the 0x9c copy at obj+0x1ab5, and calls 0x0201bb80 to propagate the paired fields to active voice state.",
        dest="0x01c34c74+0x87 == 0x01c34cfb",
        src="clamped current field plus caller-supplied delta",
        length=1,
    )
    add(
        "field_write",
        "ui_mode_entry_reset_current_field_0x9a",
        [0x02024FFE, 0x02027DF6, 0x02027E00, 0x02027E26, 0x02027E2C, 0x02027E2E],
        "A large UI handler anchors r8 to 0x01c33260 at 0x02024ffe. In the state==6 branch at 0x02027df6..0x02027e00 it clears obj+0x1aae, which is current+0x9a and therefore the penultimate byte of the dispatcher's 0x9c source range.",
        dest="0x01c34c74+0x9a == 0x01c34d0e",
        src="constant zero on UI mode/state entry",
        length=1,
    )
    add(
        "producer_then_reload",
        "bulk_ui_patch_block_to_storage_then_current_snapshot_reload",
        [0x0201E448, 0x0201E456, 0x0201E468, 0x0201E46C, 0x0201E488, 0x0201E494, 0x0201E49C, 0x0201E4A0, 0x0201E580, 0x0201E58C, 0x0201E592],
        "0x0201e254 copies incoming bulk patch data to staging at 0x01c37030+0xfa0, calls 0x0201e13e to pack that expanded patch to the selected backing record, then calls 0x02005660 so the backing record is reloaded into 0x01c34c74.",
        dest="selected backing record, then 0x01c34c74 via 0x02005660",
        src="UI/SysEx bulk patch payload staged at 0x01c37030+0xfa0",
    )
    add(
        "producer_then_reload",
        "bank_or_preset_selection_reload",
        [0x02024212, 0x0202422E, 0x02025592, 0x020255A2, 0x020255A6],
        "Bank/preset UI state writes update +0x3a4/+0x3a0 and call 0x02005660. They do not write 0x01c34c74 directly, but they select which packed record becomes the current runtime source buffer.",
        dest="0x01c34c74 via 0x02005660",
        src="selected bank/preset backing record",
    )
    add(
        "persistence_consumer",
        "save_path_reads_current_snapshot",
        [0x02026D9E, 0x02026DA2, 0x02026DA4, 0x02026DA6, 0x02026DAA, 0x02026DAC, 0x02004B04, 0x02004B06, 0x02004B08, 0x02004B0A, 0x02004866],
        "The SAVE path passes obj+0x1a14 and length 0xa3 to 0x02004b02, then passes the same pointer to 0x0201e13e. The v15-only persistence-direction analysis establishes 0x02004b02 as RAM/source to storage and contrasts it with the separate 0x02004870 read wrapper, whose inner path copies an allocated/read buffer to the caller destination at 0x02004866. SAVE is therefore a confirmed outbound lifecycle sink, not a current-snapshot writer. The primitive request command ID remains a decoder gap.",
        dest="selected persistent raw163 record and packed128 record (confirmed RAM-to-storage)",
        src="0x01c33260+0x1a14",
        length=0xA3,
    )
    add(
        "negative_memset_trace",
        "no_memset_or_clear_to_current_source_found",
        [0x02005694, 0x0200569A, 0x0201E634, 0x0201C63E, 0x0201C67C],
        "Quarkslab/Kagaimiq listings and raw immediate xrefs show memcpy and byte stores for 0x01c34c74/current aliases. No memset-style clear/fill call is present on the current source destination in the traced writer paths.",
        dest="0x01c34c74 / 0x01c33260+0x1a14",
    )
    add(
        "consumer_copy",
        "note_off_copy_current_to_voice_slot",
        [0x0201C602, 0x0201C630, 0x0201C636, 0x0201C63A, 0x0201C63C, 0x0201C63E],
        "0x0201c5ec Note Off-class path copies 0x9c bytes from 0x01c34c74 into a per-voice slot at engine+voice*0xa0+0xa2.",
        dest="dispatcher_r0 + voice_index*0xa0 + 0xa2",
        src="0x01c34c74",
        length=0x9C,
    )
    add(
        "consumer_copy",
        "note_on_copy_current_to_voice_slot",
        [0x0201C602, 0x0201C666, 0x0201C66C, 0x0201C674, 0x0201C678, 0x0201C67A, 0x0201C67C],
        "0x0201c5ec Note On-class path copies the same 0x9c bytes from 0x01c34c74 into the per-voice slot, then writes note/velocity/event metadata after the copied block.",
        dest="dispatcher_r0 + voice_index*0xa0 + 0xa2",
        src="0x01c34c74",
        length=0x9C,
    )
    return writers


def make_pseudocode() -> dict[str, str]:
    return {
        "0x02005660": """void load_selected_patch_to_current(void) {\n    obj = (uint8_t *)0x01c33260;\n    bank = obj[0x3a4]; if (bank > 3) return;\n    preset = obj[0x3a0 + bank]; if (preset > 31) return;\n    record = *(uint8_t **)(obj + 0x164) + 0x4000 + ((bank * 32 + preset) * 0xa3);\n    memcpy(obj + 0x1a14, record, 0xa3);\n    // expand/normalize packed operator blocks and tail fields in-place\n    expand_6_operator_blocks_and_global_tail(record, obj + 0x1a14, obj + 0x1a90, obj + 0x1aa0);\n    apply_current_patch_helper_flags(obj + 0x1ab0);\n    update_save_saved_display_from_flag(obj[0x129c + bank * 32 + preset]);\n}""",
        "0x0201e254:bulk-current-patch-paths": """void ui_sysex_bulk_patch_path(uint8_t *msg, uint32_t len) {\n    obj = (uint8_t *)0x01c33260;\n    stage = (uint8_t *)0x01c37030 + 0xfa0;\n    if (matches_bulk_patch_header_and_f7(msg, len)) {\n        memcpy(stage + current_stream_offset, msg + payload_offset, payload_len);\n        pack_expanded_current_patch_to_selected_record(stage); // 0x0201e13e\n        load_selected_patch_to_current();                    // 0x02005660\n    }\n}""",
        "0x0201e254:single-byte-current-patch-writer": """void ui_sysex_single_parameter_writer(uint8_t *msg, uint32_t len) {\n    obj = (uint8_t *)0x01c33260;\n    if (len == 7 && msg[0] == 0xf0 && msg[1] == 0x43 && msg[2] == 0x10 && msg[6] == 0xf7) {\n        uint8_t idx = ((msg[3] << 7) + msg[4]) & 0xff;\n        obj[0x1a14 + idx] = msg[5];\n        return;\n    }\n}""",
        "0x0201e13e": """void pack_expanded_current_patch_to_selected_record(uint8_t *expanded) {\n    uint8_t packed80[0x80];\n    for (int off = 0; off != 0x7e; off += 0x15) {\n        // Six 0x15-byte expanded operator blocks become compact packed bytes.\n        pack_one_operator_block(expanded + off, packed80 + operator_packed_offset(off));\n    }\n    pack_global_tail(expanded + 0x7e, packed80 + 0x66);\n    obj = (uint8_t *)0x01c33260;\n    bank = obj[0x3a4]; preset = obj[0x3a0 + bank];\n    dst = *(uint8_t **)(obj + 0x160) + bank * 0x1000 + preset * 0x80;\n    storage_transfer(packed80, dst, 0x80); // 0x02004b02\n    obj[0x129c + bank * 32 + preset] = 0;\n}""",
        "0x02026d6c": """void save_current_patch_candidate(void) {\n    obj = (uint8_t *)0x01c33260;\n    if (obj[0x1ec] != 0 || state == 0xff) goto out;\n    bank = obj[0x3a4]; preset = obj[0x3a0 + bank];\n    storage_dst = *(uint8_t **)(obj + 0x160) + 0x4000 + (bank * 32 + preset) * 0xa3;\n    storage_transfer(obj + 0x1a14, storage_dst, 0xa3);\n    pack_expanded_current_patch_to_selected_record(obj + 0x1a14);\n    obj[0x129c + bank * 32 + preset] = 0xff;\n    storage_transfer(/*save flags*/, *(uint8_t **)(obj + 0x160) + 0x9180, 0x80);\nout:\n    obj[0x1ec] = 0xff;\n}""",
        "0x0201c5ec": """void dispatch_midi_like_event(void *engine, uint8_t *msg, uint32_t len) {\n    status = msg[0]; status_hi = status >> 4; channel = status & 0x0f;\n    if (status_hi == 0x8 || status_hi == 0x9) {\n        voice = allocate_or_select_voice_index(engine);\n        slot = (uint8_t *)engine + voice * 0xa0;\n        memcpy(slot + 0xa2, (void *)0x01c34c74, 0x9c);\n        // bytes at slot+0x13e..0x141 are event metadata, outside the 0x9c tone copy.\n        write_note_velocity_and_marker(slot, msg);\n        return;\n    }\n    if ((status & 0xf0) == 0xe0 && len >= 3) {\n        *(uint16_t *)((uint8_t *)engine + 0x3e) = msg[1] | (msg[2] << 7);\n        return;\n    }\n    handle_cc_program_or_pressure_like_messages(engine, msg, len);\n}""",
    }


def make_report(evidence: dict[str, Any]) -> str:
    shas = evidence["sha256"]
    writers = evidence["current_source_trace"]["writers_and_producers"]
    raw = evidence["raw_xrefs"]
    lines: list[str] = []
    lines.append("# v15 runtime source trace for 0x01c34c74")
    lines.append("")
    lines.append("Scope: official v15 only. This pass reads `build/v15-official-app.bin` and v15 Quarkslab/Kagaimiq listings only. It performs no patching and no flashing.")
    lines.append("")
    lines.append("## SHA gates")
    lines.append("")
    lines.append(f"- app: `{shas['app']}` ({'PASS' if shas['app'] == EXPECTED['app_sha256'] else 'FAIL'})")
    lines.append(f"- official package: `{shas['package']}` ({'PASS' if shas['package'] == EXPECTED['package_sha256'] else 'FAIL'})")
    lines.append(f"- Quarkslab exhaustive listing: `{shas['quarkslab_exhaustive']}` ({'PASS' if shas['quarkslab_exhaustive'] == EXPECTED['quarkslab_exhaustive_sha256'] else 'FAIL'})")
    lines.append(f"- Kagaimiq exhaustive listing: `{shas['kagaimiq_patched_exhaustive']}` ({'PASS' if shas['kagaimiq_patched_exhaustive'] == EXPECTED['kagaimiq_patched_exhaustive_sha256'] else 'FAIL'})")
    lines.append("")
    lines.append("## 결론")
    lines.append("")
    lines.append("- `0x01c34c74`는 독립 static DX7 blob이 아니라 `0x01c33260 + 0x1a14`인 **현재 패치 runtime snapshot**이다.")
    lines.append("- direct absolute raw pointer는 `0x0201c604`의 immediate 하나뿐이며, 이는 `0x0201c5ec` consumer가 `r8=0x01c34c74`를 만드는 행이다. writer는 base alias `0x01c33260 + 0x1a14`로 나타난다.")
    lines.append("- 주 writer는 `0x02005660`이다. selected bank/preset으로 backing record를 고른 뒤 `memcpy(0x01c34c74, backing+0x4000+index*0xa3, 0xa3)`를 수행하고 packed fields를 current snapshot 안에 확장한다.")
    lines.append("- UI/current patch 변경은 `0x0201e254`가 bulk payload를 staging에 받고 `0x0201e13e`로 selected backing record에 pack한 뒤 `0x02005660`을 호출해 `0x01c34c74`를 갱신하는 경로와, 7-byte `F0 43 10 ... F7`가 `0x01c34c74+idx`에 직접 1 byte를 쓰는 경로가 있다.")
    lines.append("- 추가 direct writer는 `0x0201bbc6`의 current+`0x86` bounded setter, `0x0201bbf6`의 current+`0x87` bounded setter, 그리고 `0x02027e2e`의 current+`0x9a` zero reset이다. 두 setter는 `0x0201bb80`을 호출해 active voice state에도 paired field를 전파한다. 계산형 또는 table 기반 ingress 때문에 setter의 상위 UI 호출 지점은 정적으로 확정하지 못했다.")
    lines.append("- `0x0201c5ec`의 `0x9c` copy는 Note On/Off 시 현재 패치 snapshot의 tone/program 파라미터 부분을 per-voice slot `engine + voice*0xa0 + 0xa2`로 복제하는 소비 경로다. pitch bend는 별도 `E0` path에서 `engine+0x3e` 14-bit 값을 갱신하므로, Note On 중 pitch 하강은 static snapshot target-tone 가설의 근거가 아니다.")
    lines.append("- current source 대상 memset/fill writer는 이 trace에서 발견되지 않았다. 확인된 갱신은 `memcpy`, field-wise stores, 그리고 backing-record producer 후 reload이다.")
    lines.append("- 기존 분석 일부의 'loader destination과 `0x01c34c74`가 다르다'는 해석은 산술적으로 반증된다. `0x01c33260 + 0x1a14 = 0x01c34c74`이므로 동일 RAM byte range의 두 alias다.")
    lines.append("")
    lines.append("## Raw xref summary")
    lines.append("")
    for name, data in raw.items():
        lines.append(f"- `{name}` `{data['value']}`: count `{data['count']}`, refs {', '.join('`'+r+'`' for r in data['refs'][:12]) or 'none'}")
    lines.append("")
    lines.append("## Writers/producers/consumers")
    lines.append("")
    for item in writers:
        lines.append(f"### {item['role']}")
        lines.append("")
        lines.append(f"- kind: `{item['kind']}`")
        if item.get("destination"):
            lines.append(f"- destination: `{item['destination']}`")
        if item.get("source"):
            lines.append(f"- source: `{item['source']}`")
        if item.get("length"):
            lines.append(f"- length: `{item['length']}`")
        lines.append(f"- summary: {item['summary']}")
        lines.append("- key rows:")
        for r in item["evidence"]:
            lines.append(f"  - `{row_line(r)}`")
        lines.append("")
    lines.append("## 0x0201c5ec의 정확한 0x9c 구조 의미")
    lines.append("")
    lines.append("`0x0201c5ec`는 MIDI-like channel message dispatcher다. `msg[0] >> 4`로 status class를 분기하고, `msg[0] & 0x0f`를 channel nibble로 만든다. Note Off 및 Note On class에서 공통으로 `r8=0x01c34c74`, `r2=0x9c`, `r0=engine + voice*0xa0 + 0xa2`, `r1=r8`를 세팅한 뒤 `0x02048cce`를 호출한다. 따라서 복사되는 `0x9c`는 current patch snapshot 중 per-note voice가 필요한 tone/program parameter block이고, 뒤의 `slot+0x13e..0x141` bytes는 note, velocity, event marker 같은 runtime metadata이다. `0xa0` voice stride = `0x9c` copied tone bytes + 4 metadata bytes로 해석된다.")
    lines.append("")
    lines.append("## Lifecycle and call relation")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart TD")
    lines.append("  SEL[bank/preset state +0x3a4/+0x3a0] --> LOAD[0x02005660 selected record loader]")
    lines.append("  BACK[backing record: base+0x4000+index*0xa3] --> LOAD")
    lines.append("  BULK[bulk UI/SysEx payload] --> STAGE[0x01c37030+0xfa0 staging]")
    lines.append("  STAGE --> PACK[0x0201e13e pack to selected backing record]")
    lines.append("  PACK --> BACK")
    lines.append("  LOAD --> CUR[current snapshot 0x01c33260+0x1a14]")
    lines.append("  BYTE[0x0201e254 single-byte SysEx writer] --> CUR")
    lines.append("  SET86[0x0201bbc6 current+0x86 setter] --> CUR")
    lines.append("  SET87[0x0201bbf6 current+0x87 setter] --> CUR")
    lines.append("  RESET[0x02027e2e current+0x9a reset] --> CUR")
    lines.append("  SET86 --> PROP[0x0201bb80 active voice propagation]")
    lines.append("  SET87 --> PROP")
    lines.append("  CUR --> DISP[0x0201c5ec Note On/Off dispatcher]")
    lines.append("  DISP --> VOICE[voice slot +0xa2, 0x9c bytes]")
    lines.append("  CUR --> SAVE[0x02026d6c persistence candidate]")
    lines.append("  SAVE --> BACK")
    lines.append("```")
    lines.append("")
    lines.append("### Direct caller sets")
    lines.append("")
    lines.append("- `0x02005660`: `0x02005f9c`, `0x0201e46c`, `0x0201e4a0`, `0x0202422e`, `0x020255a6`.")
    lines.append("- `0x0201c5ec`: `0x0201c736`, `0x0201e644`.")
    lines.append("- `0x0201bbc6`/`0x0201bbf6`: direct `call` xref 없음. 계산형 또는 table dispatch ingress 가능성을 남긴다. 두 setter가 호출하는 `0x0201bb80`의 direct callers는 `0x0201bbf2`, `0x0201bc22` 두 곳이다.")
    lines.append("- 일반적인 selection reload 뒤에는 `0x020057e0` derived-state update가 이어진다. 대표 call은 `0x02005fa4`, `0x02024236`이다.")
    lines.append("")
    lines.append("## Completeness boundary and falsifiability")
    lines.append("")
    lines.append("- 이 결과는 official v15 app raw bytes와 그 앱에서 생성된 Quarkslab/Kagaimiq exhaustive listings에서 direct absolute immediate, base+literal alias, 확인된 pointer propagation을 정적으로 추적한 결과다. v12 주소, 구조체 크기, 의미 가정을 사용하지 않았다.")
    lines.append("- direct immediate sweep만으로는 완전하지 않다. `0x01c34c74` immediate가 consumer 한 곳에만 있고 대부분의 writer가 `0x01c33260+offset`으로 주소를 만들기 때문이다. 따라서 이 보고서는 base-relative stores와 known producer/reload chain을 함께 inventory한다.")
    lines.append("- 계산형 jump/table dispatch 또는 RAM에 저장된 pointer alias의 모든 동적 ingress가 listing에서 증명되는 것은 아니다. 특히 `0x0201bbc6`/`0x0201bbf6` setter의 상위 ingress와 `0x02027e2e` branch의 정확한 UI 기능명은 미확정이다.")
    lines.append("- 승인된 read-only runtime instrumentation에서 `[0x01c34c74,0x01c34d10)` write watchpoint를 걸었을 때 `writer_inventory.tsv` 밖의 PC가 관측되면 '모든 writer' 주장은 반증된다. 이번 작업은 실제 장치 접근, patch, flash를 하지 않았다.")
    lines.append("- 기존 v15 persistence-direction 분석과 read-wrapper comparator는 `0x02004b02`의 external ABI를 RAM/source to storage로 확정한다. 반증하려면 동일 official v15에서 이 wrapper가 caller RAM destination을 storage 내용으로 채우는 경로를 제시해야 한다. 현재 exhaustive caller inventory에는 그런 경로가 없고, read는 별도 `0x02004870 -> 0x020047d8` wrapper를 사용한다.")
    lines.append("- 정적 분석은 동시성, interrupt timing, DMA writer 부재를 증명하지 않는다. 이 항목들은 안전한 runtime watchpoint 또는 emulator trace로 별도 검증할 수 있다.")
    lines.append("")
    lines.append("## Conditions for the next safe patch")
    lines.append("")
    lines.append("다음 단계의 channel-separation patch는 아래 조건을 모두 만족하기 전에는 진행하지 않는다.")
    lines.append("")
    lines.append("1. shared current snapshot 자체를 channel별로 전역 변경하지 않는다. channel nibble은 `0x0201c5fe`에서 이미 계산되므로, 분리는 dispatcher의 Note On/Off copy source 선택 지점 이후에 한정한다.")
    lines.append("2. 비대상 channel은 byte-for-byte 기존 source `0x01c34c74`, destination 계산, `r2=0x9c`, `0x02048cce` 호출을 보존한다.")
    lines.append("3. 대체 source는 v15 expanded runtime layout의 첫 `0x9c` bytes여야 한다. packed `0x80` record 또는 raw `0xa3` record를 그대로 dispatcher에 전달하면 안 된다.")
    lines.append("4. 동일 voice의 Note On과 Note Off가 동일한 patch identity를 사용하도록 보장한다. Note Off에서 새로운 shared snapshot을 다시 복사하면 release 단계 파라미터가 Note On과 달라질 수 있다.")
    lines.append("5. 대체 buffer는 안정적이고 비중첩인 RAM에 두며, `0x02005660`, direct SysEx byte writer, bounded setters, UI reset과의 갱신 및 동기화 정책을 명시한다.")
    lines.append("6. 저장 동작은 stock에서 shared current snapshot을 persistent raw163 및 packed128 record로 내보낸다. channel별 copy를 도입한다면 SAVE 대상, dirty flag, 실패 처리 정책을 별도로 설계하되 기존 shared SAVE 의미를 암묵적으로 바꾸지 않는다.")
    lines.append("7. patch 전에 exact app SHA와 call-site bytes를 gate하고, register/stack ABI 및 branch reach를 static dry-run으로 검증한다. 이 작업의 산출물은 분석 전용이며 firmware image를 생성하거나 flash하지 않는다.")
    lines.append("")
    lines.append("## Address-level C pseudocode")
    lines.append("")
    for addr, code in evidence["pseudocode"].items():
        lines.append(f"### `{addr}`")
        lines.append("")
        lines.append("```c")
        lines.append(code)
        lines.append("```")
        lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/channel-separation-reanalysis/runtime-source/trace_runtime_source.py")
    lines.append("cd baselines/v15/analysis/channel-separation-reanalysis/runtime-source")
    lines.append("shasum -a 256 -c SHA256SUMS")
    lines.append("```")
    lines.append("")
    lines.append("`validation.txt`는 official package/app/listing SHA, manifest binding, alias 산술, 핵심 listing rows, exact direct caller sets, writer-role coverage, v12 경로 부재를 기록한다. `writer_inventory.tsv`는 machine-readable writer/producer/consumer 목록이다.")
    return "\n".join(lines) + "\n"


def main() -> None:
    app = APP.read_bytes()
    quark_rows = read_listing(QUARK)
    kaga_rows = read_listing(KAGA)
    evidence: dict[str, Any] = {
        "scope": {
            "firmware": "official v15 only",
            "no_v12": True,
            "no_patch_or_flash": True,
            "inputs": [str(APP.relative_to(ROOT)), str(PACKAGE.relative_to(ROOT)), str(MANIFEST.relative_to(ROOT)), str(QUARK.relative_to(ROOT)), str(KAGA.relative_to(ROOT)), str(PROVENANCE.relative_to(ROOT))],
        },
        "constants": {
            "runtime_base": h(BASE),
            "ram_object_base": h(RAM_BASE),
            "current_source_buffer": h(CURRENT),
            "current_source_alias": "0x01c33260+0x1a14",
            "note_copy_length": h(CURRENT_LEN_NOTE_COPY, 2),
            "packed_record_length": h(CURRENT_PACKED_RECORD_LEN, 2),
            "record_base_bias": h(RECORD_BASE_BIAS, 4),
            "voice_slot_stride": h(VOICE_SLOT_STRIDE, 2),
            "voice_slot_copy_offset": h(VOICE_SLOT_COPY_OFFSET, 2),
        },
        "sha256": {
            "app": sha256(APP),
            "package": sha256(PACKAGE),
            "quarkslab_exhaustive": sha256(QUARK),
            "kagaimiq_patched_exhaustive": sha256(KAGA),
        },
        "raw_xrefs": raw_pointer_xrefs(app, {
            "current_source_buffer_0x01c34c74": CURRENT,
            "ram_object_base_0x01c33260": RAM_BASE,
            "current_source_end_0x01c34d10": CURRENT_END_NOTE_COPY,
            "dispatcher_0x0201c5ec": DISPATCHER,
            "factory_loader_0x02005660": FACTORY_LOADER,
            "current_packer_0x0201e13e": PACK_CURRENT_TO_STORAGE,
            "storage_transfer_0x02004b02": STORAGE_XFER,
            "memcpy_0x02048cce": MEMCPY,
        }),
        "listing_search_hits": {
            "quarkslab": listing_hits(quark_rows, SEARCH_TERMS),
            "kagaimiq": listing_hits(kaga_rows, SEARCH_TERMS),
        },
        "direct_call_xrefs": {
            "quarkslab": call_xrefs(quark_rows, TARGET_CALLS),
            "kagaimiq": call_xrefs(kaga_rows, TARGET_CALLS),
        },
        "snippets": {
            name: {
                "range": [h(lo), h(hi)],
                "quarkslab": rows_between(quark_rows, lo, hi),
                "kagaimiq": rows_between(kaga_rows, lo, hi),
            }
            for name, (lo, hi) in RANGES.items()
        },
        "current_source_trace": {
            "identity": "0x01c34c74 == 0x01c33260 + 0x1a14",
            "writers_and_producers": find_direct_current_writers(quark_rows),
        },
        "pseudocode": make_pseudocode(),
    }

    # Hard gates: fail early if someone accidentally points the script at a non-v15 app.
    if evidence["sha256"]["app"] != EXPECTED["app_sha256"]:
        raise SystemExit(f"unexpected app sha256: {evidence['sha256']['app']}")
    if evidence["sha256"]["quarkslab_exhaustive"] != EXPECTED["quarkslab_exhaustive_sha256"]:
        raise SystemExit(f"unexpected quarkslab listing sha256: {evidence['sha256']['quarkslab_exhaustive']}")

    evidence["validation"] = validate_evidence(evidence, quark_rows)
    (OUT / "runtime_source_trace.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    (OUT / "report.md").write_text(make_report(evidence))
    write_inventory(evidence["current_source_trace"]["writers_and_producers"])
    write_validation(evidence["validation"])
    write_sha256sums()
    for name in ["runtime_source_trace.json", "report.md", "writer_inventory.tsv", "validation.txt", "SHA256SUMS"]:
        print(f"wrote {OUT / name}")


if __name__ == "__main__":
    main()
