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
    "quarkslab_exhaustive_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
}

RANGES = {
    "factory_loader_02005660": (0x02005660, 0x020057DE),
    "factory_loader_caller_bank_preset_020241e0": (0x020241E0, 0x0202423A),
    "bank_block_change_loader_caller_0202553c": (0x0202553C, 0x020255AA),
    "ui_sysex_current_patch_handler_0201e254": (0x0201E254, 0x0201E648),
    "current_patch_packer_0201e13e": (0x0201E13E, 0x0201E252),
    "note_dispatcher_0201c5ec": (0x0201C5EC, 0x0201C720),
    "dispatcher_small_wrapper_0201c722": (0x0201C722, 0x0201C73A),
    "save_writer_candidate_02026d6c": (0x02026D6C, 0x02026DD8),
    "storage_transfer_wrapper_02004a54_02004b14": (0x02004A54, 0x02004B14),
    "memcpy_02048cce": (0x02048C96, 0x02048D40),
}

SEARCH_TERMS = [
    "0x1c34c74", "0x1c33260", "0x1a14", "0x1a24", "0x1a90", "0x1aa0", "0x1ab0",
    "0x02005660", "0x0201c5ec", "0x0201e13e", "0x02004b02", "0x02048cce",
]

TARGET_CALLS = [FACTORY_LOADER, DISPATCHER, 0x0201C722, PACK_CURRENT_TO_STORAGE, STORAGE_XFER, MEMCPY]


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
            if hit:
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
        "0x0201e254 recognizes a 7-byte F0 43 10 ... F7 message and stores msg[5] to 0x01c33260+0x1a14+((msg[3]<<7)+msg[4] & 0xff). This is a direct current-patch field writer.",
        dest="0x01c33260+0x1a14+(parameter_index & 0xff)",
        src="UI/SysEx message byte msg[5]",
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
    lines.append(f"- Quarkslab exhaustive listing: `{shas['quarkslab_exhaustive']}` ({'PASS' if shas['quarkslab_exhaustive'] == EXPECTED['quarkslab_exhaustive_sha256'] else 'FAIL'})")
    lines.append(f"- Kagaimiq exhaustive listing: `{shas['kagaimiq_patched_exhaustive']}`")
    lines.append("")
    lines.append("## 결론")
    lines.append("")
    lines.append("- `0x01c34c74`는 독립 static DX7 blob이 아니라 `0x01c33260 + 0x1a14`인 **현재 패치 runtime snapshot**이다.")
    lines.append("- direct absolute raw pointer는 `0x0201c604`의 immediate 하나뿐이며, 이는 `0x0201c5ec` consumer가 `r8=0x01c34c74`를 만드는 행이다. writer는 base alias `0x01c33260 + 0x1a14`로 나타난다.")
    lines.append("- 주 writer는 `0x02005660`이다. selected bank/preset으로 backing record를 고른 뒤 `memcpy(0x01c34c74, backing+0x4000+index*0xa3, 0xa3)`를 수행하고 packed fields를 current snapshot 안에 확장한다.")
    lines.append("- UI/current patch 변경은 `0x0201e254`가 bulk payload를 staging에 받고 `0x0201e13e`로 selected backing record에 pack한 뒤 `0x02005660`을 호출해 `0x01c34c74`를 갱신하는 경로와, 7-byte `F0 43 10 ... F7`가 `0x01c34c74+idx`에 직접 1 byte를 쓰는 경로가 있다.")
    lines.append("- `0x0201c5ec`의 `0x9c` copy는 Note On/Off 시 현재 패치 snapshot의 tone/program 파라미터 부분을 per-voice slot `engine + voice*0xa0 + 0xa2`로 복제하는 소비 경로다. pitch bend는 별도 `E0` path에서 `engine+0x3e` 14-bit 값을 갱신하므로, Note On 중 pitch 하강은 static snapshot target-tone 가설의 근거가 아니다.")
    lines.append("- current source 대상 memset/fill writer는 이 trace에서 발견되지 않았다. 확인된 갱신은 `memcpy`, field-wise stores, 그리고 backing-record producer 후 reload이다.")
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
    lines.append("```")
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
            "inputs": [str(APP.relative_to(ROOT)), str(QUARK.relative_to(ROOT)), str(KAGA.relative_to(ROOT)), str(PROVENANCE.relative_to(ROOT))],
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

    (OUT / "runtime_source_trace.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")
    (OUT / "report.md").write_text(make_report(evidence))
    print(f"wrote {OUT / 'runtime_source_trace.json'}")
    print(f"wrote {OUT / 'report.md'}")


if __name__ == "__main__":
    main()
