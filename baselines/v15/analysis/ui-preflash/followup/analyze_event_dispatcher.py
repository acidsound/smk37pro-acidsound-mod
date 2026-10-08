#!/usr/bin/env python3
"""Focused static trace for the v15 0x02058248 event/callback vector.

Inputs are limited to the official v15 app image and the official Quarkslab
exhaustive listing. The script emits JSON evidence only. It does not patch,
flash, package, or commit anything.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BASE = 0x02000000
EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
DEFAULT_APP = Path("build/v15-official-app.bin")
DEFAULT_LISTING = Path("baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz")
DEFAULT_OUT = Path("baselines/v15/analysis/ui-preflash/followup/event-dispatcher.json")

TABLE = 0x02058248
TABLE_COUNT = 11
TABLE_END = TABLE + TABLE_COUNT * 4
PENDING_FIELDS = list(range(0x309, 0x310))
LIVE_FIELDS = list(range(0x39, 0x40))
ENCODER_MID_ENTRY = 0x0202439E
ENCODER_FUNCTION_ENTRIES = [0x02024368, 0x0202443E]
PENDING_HELPERS = [0x02028E46, 0x02028E64, 0x02028E86, 0x02028EA6, 0x02028EC8, 0x02028EEA]
LIVE_FIELD_WRAPPERS = [0x0202A270, 0x0202A298, 0x0202A334, 0x0202A35C, 0x0202A384, 0x0202A3AC]


@dataclass(frozen=True)
class Row:
    address: int
    bytes_: str
    length: int
    mnemonic: str
    text: str
    flow_type: str
    function: str


def h(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def hs(value: int) -> str:
    return f"0x{value:x}"


def off(addr: int) -> int:
    return addr - BASE


def va(offset: int) -> int:
    return BASE + offset


def read_listing(path: Path) -> list[Row]:
    rows: list[Row] = []
    with gzip.open(path, "rt", errors="replace") as f:
        header = next(f).rstrip("\n").split("\t")
        if header[:7] != ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"]:
            raise SystemExit(f"Unexpected listing header: {header!r}")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7:
                continue
            try:
                rows.append(Row(int(parts[0], 16), parts[1], int(parts[2]), parts[3], parts[4], parts[5], parts[6]))
            except ValueError:
                continue
    return rows


def find_bytes(app: bytes, needle: bytes) -> list[int]:
    hits: list[int] = []
    pos = 0
    while True:
        idx = app.find(needle, pos)
        if idx < 0:
            return hits
        hits.append(va(idx))
        pos = idx + 1


def word_at(app: bytes, addr: int) -> int:
    return int.from_bytes(app[off(addr):off(addr) + 4], "little")


def snippet(rows: list[Row], center: int, before: int = 8, after: int = 10) -> list[dict[str, Any]]:
    addresses = [r.address for r in rows]
    lo, hi = 0, len(addresses)
    while lo < hi:
        mid = (lo + hi) // 2
        if addresses[mid] < center:
            lo = mid + 1
        else:
            hi = mid
    idx = lo
    if idx >= len(rows) or rows[idx].address != center:
        idx = max(0, idx - 1)
    out = []
    for r in rows[max(0, idx - before): min(len(rows), idx + after + 1)]:
        out.append({
            "address": h(r.address),
            "bytes": r.bytes_,
            "mnemonic": r.mnemonic,
            "text": r.text,
            "flow_type": r.flow_type,
            "function": r.function,
        })
    return out


def rows_matching(rows: list[Row], regex: str) -> list[dict[str, Any]]:
    rx = re.compile(regex, re.IGNORECASE)
    return [
        {
            "address": h(r.address),
            "bytes": r.bytes_,
            "mnemonic": r.mnemonic,
            "text": r.text,
            "flow_type": r.flow_type,
            "function": r.function,
        }
        for r in rows
        if rx.search(r.text) or rx.search(r.bytes_)
    ]


def rows_containing_call_or_goto(rows: list[Row], target: int) -> list[dict[str, Any]]:
    needle = h(target)
    assert needle is not None
    return [
        {
            "address": h(r.address),
            "bytes": r.bytes_,
            "mnemonic": r.mnemonic,
            "text": r.text,
            "flow_type": r.flow_type,
            "function": r.function,
        }
        for r in rows
        if needle in r.text and ("call" in r.mnemonic or "goto" in r.mnemonic or "j" in r.mnemonic)
    ]


def parse_usb_descriptor_records(app: bytes, start: int, end: int) -> list[dict[str, Any]]:
    names = {
        0x01: "CS_AUDIO_CONTROL_HEADER_or_MS_UNDEFINED",
        0x02: "USB_MIDI_MS_HEADER",
        0x03: "USB_MIDI_IN_JACK",
        0x04: "USB_MIDI_OUT_JACK",
    }
    records: list[dict[str, Any]] = []
    ptr = start
    while ptr < end:
        length = app[off(ptr)]
        if length == 0:
            records.append({"address": h(ptr), "length": 0, "terminates": True})
            break
        raw = app[off(ptr):off(ptr) + length]
        if ptr + length > end or length < 2:
            records.append({"address": h(ptr), "length": length, "raw": raw.hex(), "parse_error": "invalid/truncated descriptor length"})
            break
        dtype = raw[1]
        subtype = raw[2] if len(raw) > 2 else None
        records.append({
            "address": h(ptr),
            "length": length,
            "descriptor_type": hs(dtype),
            "descriptor_type_note": "0x24 is USB CS_INTERFACE" if dtype == 0x24 else None,
            "subtype": hs(subtype) if subtype is not None else None,
            "subtype_note": names.get(subtype),
            "raw": raw.hex(),
        })
        ptr += length
    return records


def nearby_rows_for_hits(rows: list[Row], hits: list[int], before: int = 4, after: int = 4) -> list[dict[str, Any]]:
    return [{"hit": h(x), "snippet": snippet(rows, x, before=before, after=after)} for x in hits]


def analyze(app_path: Path, listing_path: Path) -> dict[str, Any]:
    app = app_path.read_bytes()
    sha = hashlib.sha256(app).hexdigest()
    if sha != EXPECTED_APP_SHA256:
        raise SystemExit(f"Refusing non-official app: got {sha}, expected {EXPECTED_APP_SHA256}")
    rows = read_listing(listing_path)

    table_bytes = app[off(TABLE):off(TABLE_END)]
    entries: list[dict[str, Any]] = []
    for slot in range(TABLE_COUNT):
        table_addr = TABLE + slot * 4
        target = word_at(app, table_addr)
        entries.append({
            "slot": slot,
            "table_address": h(table_addr),
            "target": h(target),
            "target_file_offset": hs(off(target)) if BASE <= target < BASE + len(app) else None,
            "raw_word_xrefs_to_target": [h(x) for x in find_bytes(app, target.to_bytes(4, "little"))],
            "direct_listing_control_flow_to_target": rows_containing_call_or_goto(rows, target),
            "target_snippet": snippet(rows, target, before=5, after=10),
        })

    direct_addr_hits = find_bytes(app, TABLE.to_bytes(4, "little"))
    table_file_offset_hits = find_bytes(app, off(TABLE).to_bytes(4, "little"))
    table_3byte_offset_hits = find_bytes(app, off(TABLE).to_bytes(3, "little"))
    table_seq_hits = find_bytes(app, table_bytes)
    two_entry_seq_hits = find_bytes(app, table_bytes[:8])
    three_entry_seq_hits = find_bytes(app, table_bytes[:12])

    low_fragment_hits = find_bytes(app, (TABLE & 0xFFFF).to_bytes(2, "little"))
    table_range_text_hits = rows_matching(rows, r"0x0?20582[4-7][0-9a-f]")
    broad_table_text_hits = rows_matching(rows, r"0x0?20582")

    computed_call_rows = [r for r in rows if "COMPUTED_CALL" in r.flow_type or re.search(r"\bcall\s+r\d+", r.text)]
    table_window_pattern = re.compile(r"0x0?20582|58248|8248|0x0?2029912|0x0?202439e", re.IGNORECASE)
    computed_call_table_windows = []
    for r in computed_call_rows:
        window = snippet(rows, r.address, before=12, after=2)
        if any(table_window_pattern.search(" ".join(str(v) for v in row.values())) for row in window):
            computed_call_table_windows.append({"computed_call": h(r.address), "window": window})

    indexed_memory_access_rows = [
        r for r in rows
        if re.search(r"\[(r\d+|r1[0-5]) \+ (r\d+|r1[0-5])\]", r.text)
    ]
    base_index_load_rows = [
        r for r in rows
        if (
            (re.search(r"\[(r\d+|r1[0-5]) \+ (r\d+|r1[0-5])\]", r.text) and ("lw" in r.mnemonic or "ldw" in r.mnemonic))
            or "addldw" in r.mnemonic
        )
    ]
    base_index_table_windows = []
    for r in base_index_load_rows:
        window = snippet(rows, r.address, before=8, after=4)
        if any(table_window_pattern.search(" ".join(str(v) for v in row.values())) for row in window):
            base_index_table_windows.append({"load": h(r.address), "window": window})

    branch_into_table = [
        {
            "address": h(r.address),
            "bytes": r.bytes_,
            "mnemonic": r.mnemonic,
            "text": r.text,
            "flow_type": r.flow_type,
            "function": r.function,
            "snippet": snippet(rows, r.address, before=8, after=8),
        }
        for r in rows
        for m in re.finditer(r"0x([0-9a-fA-F]{8})", r.text)
        if TABLE <= int(m.group(1), 16) < TABLE_END
    ]

    exact_pending_uses = []
    pending_write_uses = []
    for field in PENDING_FIELDS:
        rx = re.compile(rf"\+ 0x{field:x}\]", re.IGNORECASE)
        hits = []
        for r in rows:
            if rx.search(r.text):
                item = {
                    "address": h(r.address),
                    "bytes": r.bytes_,
                    "mnemonic": r.mnemonic,
                    "text": r.text,
                    "flow_type": r.flow_type,
                    "function": r.function,
                }
                hits.append(item)
                if "sb" in r.mnemonic or "sh" in r.mnemonic or "sw" in r.mnemonic:
                    pending_write_uses.append(item)
        exact_pending_uses.append({"field": hs(field), "hits": hits})

    live_field_uses = []
    for field in LIVE_FIELDS:
        rx = re.compile(rf"\+ 0x{field:x}\]", re.IGNORECASE)
        live_field_uses.append({
            "field": hs(field),
            "hits": [
                {
                    "address": h(r.address),
                    "bytes": r.bytes_,
                    "mnemonic": r.mnemonic,
                    "text": r.text,
                    "flow_type": r.flow_type,
                    "function": r.function,
                }
                for r in rows
                if rx.search(r.text)
            ],
        })

    pending_helper_callers = {h(addr): rows_containing_call_or_goto(rows, addr) for addr in PENDING_HELPERS}
    live_wrapper_callers = {h(addr): rows_containing_call_or_goto(rows, addr) for addr in LIVE_FIELD_WRAPPERS}

    encoder_exact_callers = rows_containing_call_or_goto(rows, ENCODER_MID_ENTRY)
    encoder_function_callers = {h(addr): rows_containing_call_or_goto(rows, addr) for addr in ENCODER_FUNCTION_ENTRIES}

    return {
        "schema": "smk37-v15-ui-preflash-event-dispatcher-followup-v1",
        "inputs": {
            "app_path": str(app_path),
            "app_size": len(app),
            "app_sha256": sha,
            "listing_path": str(listing_path),
            "runtime_base": h(BASE),
            "policy": "official v15 listing/raw bytes only; no patch, no flash, no commit",
        },
        "callback_vector_0x02058248": {
            "address": h(TABLE),
            "file_offset": hs(off(TABLE)),
            "entry_count": TABLE_COUNT,
            "raw_bytes": table_bytes.hex(),
            "entries": entries,
        },
        "dispatcher_search": {
            "direct_raw_word_hits_to_table_base": [h(x) for x in direct_addr_hits],
            "direct_raw_word_hits_to_table_file_offset": [h(x) for x in table_file_offset_hits],
            "direct_raw_3byte_hits_to_table_file_offset": [h(x) for x in table_3byte_offset_hits],
            "raw_full_table_sequence_hits": [h(x) for x in table_seq_hits],
            "raw_first_two_entry_sequence_hits": [h(x) for x in two_entry_seq_hits],
            "raw_first_three_entry_sequence_hits": [h(x) for x in three_entry_seq_hits],
            "listing_text_hits_for_table_range": table_range_text_hits,
            "listing_text_hits_for_0x020582_prefix": broad_table_text_hits,
            "raw_low_16bit_fragment_0x8248_hits": [h(x) for x in low_fragment_hits],
            "raw_low_16bit_fragment_context": nearby_rows_for_hits(rows, low_fragment_hits),
            "branch_or_flow_targets_into_table_range": branch_into_table,
            "computed_call_count": len(computed_call_rows),
            "computed_call_windows_with_table_evidence": computed_call_table_windows,
            "indexed_memory_access_count": len(indexed_memory_access_rows),
            "base_plus_index_word_or_addldw_count": len(base_index_load_rows),
            "base_plus_index_word_load_windows_with_table_evidence": base_index_table_windows,
            "assessment": "No reproducible dispatcher/caller for the 0x02058248 11-entry run was found. Direct base xrefs, high/low immediates, base+index word-load windows, copied-table sequence scans, and relative/control-flow references do not produce a valid computed call/jump using the table.",
        },
        "adjacent_bytes_after_vector": {
            "range": [h(TABLE_END), h(0x020582D0)],
            "raw_bytes": app[off(TABLE_END):off(0x020582D0)].hex(),
            "parsed_records": parse_usb_descriptor_records(app, TABLE_END, 0x020582D0),
            "assessment": "The 0x06/0x09 length bytes, descriptor type 0x24, and subtypes 0x02/0x03 identify the adjacent run as USB class-specific MIDI descriptors, not physical button/event IDs.",
        },
        "encoder_0x0202439e_relation": {
            "mid_entry_in_vector": h(ENCODER_MID_ENTRY),
            "vector_slot": 10,
            "direct_control_flow_to_mid_entry": encoder_exact_callers,
            "enclosing_encoder_function_entries": {
                h(addr): {
                    "direct_control_flow": encoder_function_callers[h(addr)],
                    "snippet": snippet(rows, addr, before=5, after=18),
                }
                for addr in ENCODER_FUNCTION_ENTRIES
            },
            "caller_context_0x02025dea_0x02025e06": snippet(rows, 0x02025DEA, before=18, after=18),
            "assessment": "0x0202439e is a vector slot and a mid-function delta-update entry. The normal encoder paths call 0x02024368/0x0202443e from 0x02025dea/0x02025e06, while no direct listing/raw caller to the exact 0x0202439e mid-entry was found outside the vector word itself.",
        },
        "pending_fields_0x309_0x30f": {
            "exact_pending_field_uses": exact_pending_uses,
            "writes_to_pending_fields": pending_write_uses,
            "live_field_0x39_0x3f_uses": live_field_uses,
            "pending_helper_callers": pending_helper_callers,
            "live_wrapper_callers": live_wrapper_callers,
            "state_machine_consumer_snippet_0x02029152": snippet(rows, 0x02029152, before=8, after=34),
            "long_hold_or_0x30f_snippet_0x020295e0": snippet(rows, 0x020295E0, before=0, after=25),
            "assessment": "Fields +0x309..+0x30f are consumed by the UI state path, but this listing search finds no writes to +0x309..+0x30f. Sibling wrappers at 0x0202a270..0x0202a3ac write live +0x39..+0x3e and call the same helpers, but they are not callers of the pending fields and have no direct caller/xref here.",
        },
        "promotion_decision": {
            "physical_event_ids_promoted": False,
            "reason": "The vector has ordinal slots only. The dispatcher/caller and physical event source are still absent, and adjacent byte records are USB MIDI descriptors rather than button IDs. Therefore no slot can be promoted to a physical event ID from official v15 static evidence.",
            "reproducible_blockers": [
                "No raw 32-bit, 24-bit file-offset, or listing immediate xref to 0x02058248.",
                "No copied 44-byte table sequence outside 0x02058248 itself, and no duplicate first two/three entry run outside the table.",
                "No computed-call or base+index word-load window in the exhaustive listing carries table-base/table-range evidence.",
                "The only listing control-flow target into 0x02058248..0x02058273 is 0x02055b32 -> 0x02058258, which lands in the data word for slot 4 and is treated as a false-positive/disassembly artifact, not a dispatcher.",
                "No direct caller to the exact 0x0202439e mid-entry is present outside the vector word. Only enclosing function entries are called directly.",
            ],
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", type=Path, default=DEFAULT_APP)
    ap.add_argument("--listing", type=Path, default=DEFAULT_LISTING)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    data = analyze(args.app, args.listing)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
