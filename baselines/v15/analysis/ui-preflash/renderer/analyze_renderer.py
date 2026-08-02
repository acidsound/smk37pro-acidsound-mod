#!/usr/bin/env python3
"""Static v15 UI/LCD renderer evidence extraction.

Inputs are restricted to the official v15 app bytes and existing Quarkslab
listings.  The script writes evidence.json and evidence-report.md next to this
file.  It never patches, flashes, or invokes Ghidra.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
APP = ROOT / "build/v15-official-app.bin"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
RECURSIVE = LISTING_DIR / "quarkslab-recursive-listing.tsv.gz"
EXHAUSTIVE = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
RUNTIME_BASE = 0x02000000
EXPECTED_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
FLASH_DELTA = 0x4120

SEEDS = {
    "Firmware": b"Firmware",
    "Pad Bank-": b"Pad Bank-",
    "Keys Channel-": b"Keys Channel-",
    "Pads Channel-": b"Pads Channel-",
    "SAVE": b"SAVE",
    "SAVED": b"SAVED",
    "#D9D9D9": b"#D9D9D9",
    "#F5BC27": b"#F5BC27",
    "#f5bc27": b"#f5bc27",
}

TARGET_ADDRS = {
    "Firmware_text": 0x0205D8F5,
    "Firmware_markup_full": 0x0205D8ED,
    "Pad_Bank_text": 0x0205D9C5,
    "Keys_Channel_text": 0x0205D9E9,
    "Pads_Channel_text": 0x0205D9F7,
    "SAVE_text": 0x02057298,
    "SAVED_text": 0x0205D990,
    "D9D9D9_SAVE_markup": 0x0205D97A,
    "f5bc27_SAVED_markup": 0x0205D988,
    "D9D9D9_first_markup": 0x02057730,
    "F5BC27_Clear_Pattern_markup": 0x02057CE4,
    "D9D9D9_Mono_markup": 0x02057D5C,
    "F5BC27_Mono_markup": 0x02057D78,
    "ui_pointer_table_firmware_entry": 0x02058028,
    "ui_pointer_table_pad_bank_entry": 0x02058304,
    "ui_pointer_table_keys_channel_entry": 0x02058314,
    "rodata_mixed_base_seen_in_code": 0x02057250,
    "candidate_st7789_sleep_out_entry": 0x02058AEC,
    "candidate_st7789_stride_table": 0x02058B10,
    "candidate_st7789_bb_entry_or_font_table_xref": 0x02058B50,
}

FUNCTION_WINDOWS = {
    "FUN_0200ea9a_text_extent_or_markup_candidate": (0x0200EA9A, 0x0200EC5C),
    "FUN_0200f74c_object_render_traversal_candidate": (0x0200F74C, 0x0200F8EE),
    "FUN_0201a67c_object_string_setter_candidate": (0x0201A67C, 0x0201A772),
    "FUN_02030e50_halfword_table_decoder_confirmed": (0x02030E50, 0x02030F6A),
    "FUN_02005152_12byte_state_copy_candidate": (0x02005152, 0x02005190),
    "FUN_0201bac2_signed_clamp_confirmed": (0x0201BAC2, 0x0201BAD8),
}

CALL_TARGETS = sorted({start for start, _ in FUNCTION_WINDOWS.values()} | {
    0x0200E936,
    0x0200EA18,
    0x0200EA82,
    0x0200F412,
    0x0200F734,
    0x02048E5C,
    0x02048ECA,
    0x02049B96,
    0x0202EC42,
})

ST7789_ENTRIES = [
    ("sleep_out_or_table_prefix", 0x02058AEC, 0x11, None),
    ("MADCTL", 0x02058B10, 0x36, [0x00]),
    ("COLMOD_RGB565", 0x02058B22, 0x3A, [0x05]),
    ("PORCTRL", 0x02058B34, 0xB2, [0x0C, 0x0C, 0x00, 0x33, 0x33]),
    ("GCTRL", 0x02058B46, 0xB7, [0x35]),
    ("VCOMS", 0x02058B58, 0xBB, [0x32]),
    ("VDVVRHEN", 0x02058B6A, 0xC2, [0x01]),
    ("VRHS", 0x02058B7C, 0xC3, [0x15]),
    ("VDVS", 0x02058B8E, 0xC4, [0x20]),
    ("FRCTRL2", 0x02058BA0, 0xC6, [0x0F]),
    ("PWCTRL1", 0x02058BB2, 0xD0, [0xA4, 0xA1]),
    ("PVGAMCTRL", 0x02058BC4, 0xE0, [0xD0, 0x08, 0x0E, 0x09, 0x09, 0x05, 0x31, 0x33, 0x48, 0x17, 0x14, 0x15, 0x31, 0x34]),
    ("NVGAMCTRL", 0x02058BD6, 0xE1, [0xD0, 0x08, 0x0E, 0x09, 0x09, 0x05, 0x31, 0x33, 0x48, 0x17, 0x14, 0x15, 0x31, 0x34]),
    ("INVON", 0x02058BE8, 0x21, []),
]


def hexaddr(n: int) -> str:
    return f"0x{n:08x}"


def file_off(va: int) -> int:
    return va - RUNTIME_BASE


def flash_off(va: int) -> int:
    return file_off(va) + FLASH_DELTA


def load_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def cstr(data: bytes, va: int, limit: int = 96) -> str | None:
    off = file_off(va)
    if off < 0 or off >= len(data):
        return None
    end = data.find(b"\0", off)
    if end < 0 or end > off + limit:
        end = min(len(data), off + limit)
    raw = data[off:end]
    if all(32 <= b < 127 for b in raw):
        return raw.decode("ascii", "replace")
    return None


def occurrences(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    i = data.find(needle)
    while i != -1:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def pointer_refs(data: bytes, va: int) -> list[dict[str, Any]]:
    pat = struct.pack("<I", va)
    return [
        {"file_offset": f"0x{o:06x}", "runtime_va": hexaddr(RUNTIME_BASE + o)}
        for o in occurrences(data, pat)
    ]


def listing_refs(rows: list[dict[str, str]], va: int) -> list[dict[str, str]]:
    keys = {hexaddr(va), f"0x{va:x}"}
    out = []
    for row in rows:
        txt = row["text"].lower()
        if any(k.lower() in txt for k in keys):
            out.append({k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]})
    return out


def window(rows: list[dict[str, str]], start: int, end: int) -> list[dict[str, str]]:
    out = []
    for row in rows:
        a = int(row["address"], 16)
        if start <= a < end:
            out.append({k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]})
    return out


def callers(rows: list[dict[str, str]], target: int) -> list[dict[str, str]]:
    key = hexaddr(target).lower()
    out = []
    for row in rows:
        if row["mnemonic"] == "call" and key in row["text"].lower():
            out.append({k: row[k] for k in ["address", "bytes", "text", "function"]})
    return out


def globals_in(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    out = []
    rgx = re.compile(r"#(0x1c[0-9a-fA-F]+)|\[(0x1c[0-9a-fA-F]+)")
    for row in rows:
        if rgx.search(row["text"]):
            out.append({k: row[k] for k in ["address", "bytes", "mnemonic", "text", "function"]})
    return out


def decode_st7789(data: bytes) -> list[dict[str, Any]]:
    out = []
    for name, va, cmd, expected_payload in ST7789_ENTRIES:
        off = file_off(va)
        length = data[off + 1] if off + 1 < len(data) else None
        payload = list(data[off + 2: off + 2 + (length or 0)]) if length is not None else []
        out.append({
            "label": name,
            "runtime_va": hexaddr(va),
            "file_offset": f"0x{off:06x}",
            "flash_offset": f"0x{flash_off(va):06x}",
            "command_byte": f"0x{data[off]:02x}" if 0 <= off < len(data) else None,
            "length_byte": length,
            "payload_hex": " ".join(f"{b:02x}" for b in payload),
            "expected_payload_match": expected_payload is None or payload == expected_payload,
            "entry18_hex": data[off:off+0x12].hex(),
        })
    return out


def main() -> None:
    data = APP.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA256:
        raise SystemExit(f"unexpected app sha256: {sha}")
    recursive = load_listing(RECURSIVE)
    exhaustive = load_listing(EXHAUSTIVE)

    seed_hits = {}
    for label, needle in SEEDS.items():
        hits = []
        for off in occurrences(data, needle):
            va = RUNTIME_BASE + off
            hits.append({
                "file_offset": f"0x{off:06x}",
                "runtime_va": hexaddr(va),
                "flash_offset": f"0x{off + FLASH_DELTA:06x}",
                "ascii_at_hit": cstr(data, va),
            })
        seed_hits[label] = hits

    target_evidence = {}
    for label, va in TARGET_ADDRS.items():
        target_evidence[label] = {
            "runtime_va": hexaddr(va),
            "file_offset": f"0x{file_off(va):06x}",
            "flash_offset": f"0x{flash_off(va):06x}",
            "ascii_at_target": cstr(data, va),
            "raw_little_endian_pointer_refs": pointer_refs(data, va),
            "recursive_listing_refs": listing_refs(recursive, va),
            "exhaustive_listing_refs": listing_refs(exhaustive, va),
        }

    function_evidence = {}
    for label, (start, end) in FUNCTION_WINDOWS.items():
        snippet = window(exhaustive, start, end)
        function_evidence[label] = {
            "address": hexaddr(start),
            "listing_window_exhaustive": snippet,
            "callers_exhaustive": callers(exhaustive, start),
            "direct_calls_from_window": [r for r in snippet if r["mnemonic"] == "call"],
            "global_or_ram_immediates_in_window": globals_in(snippet),
        }

    call_xrefs = {hexaddr(t): callers(exhaustive, t) for t in CALL_TARGETS}

    st_entries = decode_st7789(data)

    classifications = {
        "confirmed": [
            "Input app is build/v15-official-app.bin, size 617012, SHA-256 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055.",
            "UI text/color bytes exist in the official app at the recorded offsets; Firmware/Pad Bank-/Keys Channel- occur once.",
            "Firmware, Pad Bank-, and Keys Channel- have raw little-endian pointer-table entries at 0x02058028, 0x02058304, and 0x02058314 respectively.",
            "FUN_0201a67c manipulates an object at r0/r4, a string pointer at r1/r5, stores/replaces [r4+0x24], and calls zero-terminated length/copy helpers at 0x02048eca/0x02048e5c. This supports an object string setter role, not a full renderer name.",
            "FUN_02030e50 is a real recursive-listing function and directly loads 0x02058b50, treating it as a halfword table. This is independent contradictory evidence against blindly naming the overlapping ST-like bytes an LCD init table.",
        ],
        "candidate": [
            "FUN_0200ea9a is a text extent or markup parser candidate: r0 is checked as a byte-string pointer; the function iterates bytes, handles NUL/CR/LF, calls helper 0x0200e936, and returns r0 as an accumulated length/count. The exact renderer ABI remains candidate.",
            "FUN_0200f74c is an object traversal/render dispatch candidate: r0-r3 are saved, fields from r1 are read, computed callbacks are invoked, and 0x0200f412/0x0200f734 are callees. Its direct UI role is not independently proven.",
            "The 0x02058aec..0x02058be8 byte run matches a ST7789V-like command list including 0x11, 0x36, 0x3a/0x05, 0xb2, 0xb7, 0xbb, 0xc2, 0xe0, 0xe1, 0x21. It is only a byte-pattern candidate because no LCD write caller was recovered and a recursive function references the overlapping region as a halfword table.",
        ],
        "unresolved": [
            "No defensible LCD command/data write function, bus mode, panel resolution routine, or framebuffer owner was recovered from the current listings.",
            "No direct caller/callee chain from the UI string pointer entries to a final pixel/LCD write routine was recovered.",
            "No function receives a stable name unless at least two independent evidence classes support it; therefore this report keeps candidate roles instead of names for renderer/LCD functions.",
        ],
    }

    abi_notes = {
        "FUN_0201a67c_object_string_setter_candidate": {
            "registers": "r0/r4 object pointer; r1/r5 source C string; returns via r0 from allocation/copy path; clobbers r4-r7 saved by prologue.",
            "field_accesses": ["[r4+0x24] string/backing pointer", "[r4+0x48] flags byte"],
            "callees": ["0x0200a7b2", "0x02048eca", "0x0200a28c", "0x02009f98", "0x02009f70", "0x02048e5c", "0x0201a1bc"],
        },
        "FUN_0200ea9a_text_extent_or_markup_candidate": {
            "registers": "r0/r10 input byte string; r1 must be nonzero but exact role unresolved; r2 contributes flags via stack extra arg [sp+0x58]; returns r0/r12 count or advance.",
            "evidence": ["NUL/CR/LF checks", "byte iteration through [r6+r11]", "calls 0x0200e936/0x0200ea18/0x0200ea82", "uses 0x0205d8e8 immediate but this points into a string and is not treated as a name"],
        },
        "FUN_0200f74c_object_render_traversal_candidate": {
            "registers": "r0/r13 context or object; r1/r14 descriptor/object; r2/r12 and r3/r6 rectangle or render args candidate; exact ABI unresolved.",
            "field_accesses": ["[r1+0x08]", "[r1+0x09]", "[r1+0x0b]", "[r1+0x10]", "[r13+0x18] computed callback"],
            "callees": ["0x0200afe8", "0x0200a1f2", "computed callbacks", "0x0200f412", "0x0200f734"],
        },
        "FUN_02030e50_halfword_table_decoder_confirmed": {
            "registers": "r0/r4 destination buffer; r1/r11 input halfword stream; returns after writing [r4+0x24] through 0x0202ec42.",
            "data_accesses": ["r8=0x02058b50", "r9=r8+0x1ee", "lh.s/lh.z table reads", "writes bytes under r4 and halfword via 0x0202ec42"],
        },
    }

    evidence = {
        "format": "smk37-v15-ui-renderer-static-evidence-v1",
        "scope": {
            "static_only": True,
            "no_patch_no_flash_no_commit": True,
            "runtime_base": hexaddr(RUNTIME_BASE),
            "app_path": str(APP.relative_to(ROOT)),
            "app_size": len(data),
            "app_sha256": sha,
            "manifest_path": str(MANIFEST.relative_to(ROOT)),
            "recursive_listing": str(RECURSIVE.relative_to(ROOT)),
            "exhaustive_listing": str(EXHAUSTIVE.relative_to(ROOT)),
            "listing_false_positive_policy": "Exhaustive disassembly may decode data. Function roles require independent evidence; raw byte-pattern tables are not enough.",
        },
        "seed_hits": seed_hits,
        "target_evidence": target_evidence,
        "st7789_like_sequence": {
            "classification": "candidate_or_data_false_positive_not_confirmed_lcd_path",
            "entries": st_entries,
            "positive_evidence": ["canonical command bytes and payloads including COLMOD 0x3a/0x05 and gamma 0xe0/0xe1"],
            "contradictory_evidence": ["no literal pointer or listing xref to table start", "recursive function FUN_02030e50 loads 0x02058b50 and treats overlapping bytes as a halfword table"],
        },
        "function_evidence": function_evidence,
        "call_xrefs": call_xrefs,
        "abi_notes": abi_notes,
        "classifications": classifications,
    }

    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False) + "\n")

    report = render_report(evidence)
    (OUT / "evidence-report.md").write_text(report)


def render_report(e: dict[str, Any]) -> str:
    scope = e["scope"]
    lines: list[str] = []
    lines.append("# v15 UI renderer/LCD static evidence report")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append(f"- App: `{scope['app_path']}`")
    lines.append(f"- SHA-256: `{scope['app_sha256']}`")
    lines.append(f"- Runtime base: `{scope['runtime_base']}`")
    lines.append(f"- Listings: `{scope['recursive_listing']}`, `{scope['exhaustive_listing']}`")
    lines.append("- Static only. No patching, flashing, or commit was performed by this analysis.")
    lines.append("- Exhaustive listing data false-positives are treated as a known hazard.")
    lines.append("")
    lines.append("## Classification summary")
    lines.append("")
    for cls in ["confirmed", "candidate", "unresolved"]:
        title = {"confirmed": "확정", "candidate": "후보", "unresolved": "미확정"}[cls]
        lines.append(f"### {title}")
        for item in e["classifications"][cls]:
            lines.append(f"- {item}")
        lines.append("")

    lines.append("## Seed strings and colors")
    lines.append("")
    lines.append("| Seed | hits | offsets / VAs |")
    lines.append("|---|---:|---|")
    for label, hits in e["seed_hits"].items():
        parts = [f"`{h['file_offset']}` / `{h['runtime_va']}`" for h in hits]
        lines.append(f"| `{label}` | {len(hits)} | {'<br>'.join(parts)} |")
    lines.append("")
    lines.append("Key pointer-table evidence:")
    for label in ["Firmware_text", "Pad_Bank_text", "Keys_Channel_text"]:
        te = e["target_evidence"][label]
        refs = te["raw_little_endian_pointer_refs"]
        lines.append(f"- `{label}` at `{te['runtime_va']}` has raw pointer refs: {json.dumps(refs, ensure_ascii=False)}")
    lines.append("")

    lines.append("## ST7789-like byte sequence")
    lines.append("")
    lines.append("The sequence is retained as a byte-pattern candidate, not a confirmed LCD path.")
    lines.append("")
    lines.append("| Label | VA | command | len | payload | payload match |")
    lines.append("|---|---:|---:|---:|---|---|")
    for r in e["st7789_like_sequence"]["entries"]:
        lines.append(f"| {r['label']} | `{r['runtime_va']}` | `{r['command_byte']}` | `{r['length_byte']}` | `{r['payload_hex']}` | `{r['expected_payload_match']}` |")
    lines.append("")
    lines.append("Contradiction: `FUN_02030e50` is present in the recursive listing and loads `0x02058b50`, then reads it with `lh.s/lh.z` as a halfword table. That overlaps the ST-like run, so the LCD identity cannot be promoted without another independent xref to an LCD write routine.")
    lines.append("")

    lines.append("## Candidate function evidence")
    lines.append("")
    for label, notes in e["abi_notes"].items():
        fe = e["function_evidence"][label]
        lines.append(f"### `{fe['address']}` `{label}`")
        lines.append("")
        lines.append(f"- ABI note: {notes.get('registers', '')}")
        if notes.get("field_accesses"):
            lines.append("- Field accesses: " + ", ".join(f"`{x}`" for x in notes["field_accesses"]))
        if notes.get("data_accesses"):
            lines.append("- Data accesses: " + ", ".join(f"`{x}`" for x in notes["data_accesses"]))
        if notes.get("callees"):
            lines.append("- Callees: " + ", ".join(f"`{x}`" for x in notes["callees"]))
        callers = fe["callers_exhaustive"]
        lines.append("- Direct callers recovered: " + (", ".join(f"`{c['address']}`" for c in callers) if callers else "none in listing export"))
        g = fe["global_or_ram_immediates_in_window"]
        if g:
            lines.append("- RAM/global immediates:")
            for row in g[:12]:
                lines.append(f"  - `{row['address']}` `{row['text']}`")
        lines.append("- Listing excerpt:")
        lines.append("```text")
        for row in fe["listing_window_exhaustive"][:36]:
            lines.append(f"{row['address']} {row['bytes']} {row['text']} {row['flow_type']} {row['function']}")
        if len(fe["listing_window_exhaustive"]) > 36:
            lines.append(f"... {len(fe['listing_window_exhaustive']) - 36} more rows in evidence.json")
        lines.append("```")
        lines.append("")

    lines.append("## Reproduction")
    lines.append("")
    lines.append("```bash")
    lines.append("python3 baselines/v15/analysis/ui-preflash/renderer/analyze_renderer.py")
    lines.append("python3 -m json.tool baselines/v15/analysis/ui-preflash/renderer/evidence.json >/dev/null")
    lines.append("```")
    lines.append("")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
