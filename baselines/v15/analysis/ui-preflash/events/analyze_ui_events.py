#!/usr/bin/env python3
"""Static UI/event evidence extractor for the official SMK-37 Pro v15 app.

Inputs are intentionally limited to the official v15 app image and the
Quarkslab TSV listing generated from that same image.  The script writes a
machine-readable JSON report plus a compact markdown report in this directory.
It does not patch, package, flash, or commit anything.
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
OUTDIR = Path("baselines/v15/analysis/ui-preflash/events")

CALLBACK_TABLE = 0x02058248
CALLBACK_COUNT = 11
UI_STATE_MACHINE = 0x02029290
RAM_UI = 0x1C33260
RAM_ALT = 0x1C34894
REDRAW_CANDIDATE = 0x0201E06C
CELL_RENDER_CANDIDATE = 0x02004E8E

MANUAL_CALLBACK_NOTES = {
    0: {
        "classification": "candidate",
        "semantic": "entry inside 0x0202990e clears UI flag [0x1c33260+0x1672] to 0",
        "ram_offsets": ["0x1672"],
    },
    1: {
        "classification": "candidate",
        "semantic": "cycles byte [0x1c33260+0x03a6] through 0..0x18, mirrors through pointer [0x1c33260+0x15c]+0x40, starts 0xc8 timer",
        "ram_offsets": ["0x03a6", "0x015c", "0x00c0"],
    },
    2: {
        "classification": "candidate",
        "semantic": "mid-function/goto entry associated with sibling [0x03a7] path and state-machine branch; decoder boundary not stable",
        "ram_offsets": ["0x03a7", "0x015c", "0x00c0"],
    },
    3: {
        "classification": "candidate",
        "semantic": "increments/decrements coarse selector [0x1636] in range 0..2 and clears fine selector [0x1637]",
        "ram_offsets": ["0x1636", "0x1637"],
    },
    4: {
        "classification": "candidate",
        "semantic": "bounded increment of fine selector [0x1637], max read from table 0x0205dda0 indexed by [0x1636]",
        "ram_offsets": ["0x1636", "0x1637"],
    },
    5: {
        "classification": "candidate",
        "semantic": "bounded decrement of fine selector [0x1637]",
        "ram_offsets": ["0x1637"],
    },
    6: {
        "classification": "candidate",
        "semantic": "edits RAM block 0x1c34894 byte +1 with clamp 0..0x0b and calls 0x02005152 to apply selection",
        "ram_offsets": ["alt+0x0001"],
    },
    7: {
        "classification": "candidate",
        "semantic": "mid-body entry in 0x1c34894 renderer/update path; pfetch boundary makes callback start uncertain",
        "ram_offsets": ["alt+0x0000", "alt+0x0001"],
    },
    8: {
        "classification": "candidate",
        "semantic": "edits RAM block 0x1c34894 byte +0 with clamp 0..0x09 and calls 0x02005152 to apply selection",
        "ram_offsets": ["alt+0x0000", "alt+0x0001"],
    },
    9: {
        "classification": "candidate",
        "semantic": "mid-entry into 0x02029a8c grid/state synchronizer using [0x1639], [0x1642], [0x168a]",
        "ram_offsets": ["0x1639", "0x1642", "0x168a"],
    },
    10: {
        "classification": "confirmed-internal-callee-candidate-ui-encoder",
        "semantic": "encoder-like delta handler around center 0x3f; clamps 0..0x7f, stores [0x00c6], raises dirty bytes [0x16e7]/[0x16e9], sets timer [0x00c4]=0x0a",
        "ram_offsets": ["0x00c6", "0x00c8", "0x0200", "0x0208", "0x0300", "0x16a0", "0x16e7", "0x16e9", "0x00c4"],
    },
}

IMPORTANT_STRINGS = [
    b"SAVE",
    b"PARA",
    b"Please select a bank to save",
    b"#D9D9D9 SAVE#",
    b"#f5bc27 SAVED#",
    b"Pad Bank-",
    b"Keys Channel-",
    b"Pads Channel-",
    b"Step-",
    b"Gate-",
    b"Swing-",
    b"Tempo-",
    b"Rate-",
    b"Arpeggiator-",
    b"Note Repeat-",
    b"Preset-",
    b"Cut Off-",
    b"Distortion-",
    b"Algorithm-",
    b"Feedback-",
    b"Scroll MOD to middle\nScroll PITCH to top",
    b"Scroll MOD to top",
    b"Scroll MOD to bottom",
    b"Scroll PITCH to bottom",
]

@dataclass
class Row:
    addr: int
    bytes_: str
    length: int
    mnemonic: str
    text: str
    flow_type: str
    function: str


def va(off: int) -> int:
    return BASE + off


def off(addr: int) -> int:
    return addr - BASE


def h(addr: int | None) -> str | None:
    return None if addr is None else f"0x{addr:08x}"


def hshort(n: int) -> str:
    return f"0x{n:x}"


def read_listing(path: Path) -> list[Row]:
    rows: list[Row] = []
    with gzip.open(path, "rt", errors="replace") as f:
        header = next(f).rstrip("\n").split("\t")
        assert header[:7] == ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"], header
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 7:
                continue
            try:
                rows.append(Row(int(parts[0], 16), parts[1], int(parts[2]), parts[3], parts[4], parts[5], parts[6]))
            except ValueError:
                continue
    return rows


def row_index(rows: list[Row]) -> dict[int, int]:
    return {r.addr: i for i, r in enumerate(rows)}


def snippet(rows: list[Row], center: int, before: int = 6, after: int = 12) -> list[dict[str, Any]]:
    idx = row_index(rows)
    if center in idx:
        i = idx[center]
    else:
        # nearest row at or before center
        addrs = [r.addr for r in rows]
        lo = 0
        hi = len(addrs)
        while lo < hi:
            mid = (lo + hi) // 2
            if addrs[mid] <= center:
                lo = mid + 1
            else:
                hi = mid
        i = max(0, lo - 1)
    out = []
    for r in rows[max(0, i - before): min(len(rows), i + after + 1)]:
        out.append({
            "address": h(r.addr),
            "bytes": r.bytes_,
            "mnemonic": r.mnemonic,
            "text": r.text,
            "flow_type": r.flow_type,
            "function": r.function,
        })
    return out


def word_at(app: bytes, addr: int) -> int:
    return int.from_bytes(app[off(addr):off(addr)+4], "little")


def find_word_xrefs(app: bytes, value: int) -> list[int]:
    pat = value.to_bytes(4, "little")
    out = []
    i = 0
    while True:
        j = app.find(pat, i)
        if j < 0:
            return out
        out.append(va(j))
        i = j + 1


def cstr(app: bytes, addr: int, limit: int = 160) -> str | None:
    if not (BASE <= addr < BASE + len(app)):
        return None
    start = off(addr)
    end = app.find(b"\0", start, min(len(app), start + limit))
    if end < 0 or end == start:
        return None
    try:
        return app[start:end].decode("utf-8")
    except UnicodeDecodeError:
        return app[start:end].decode("utf-8", "replace")


def find_strings(app: bytes) -> list[dict[str, Any]]:
    found = []
    for term in IMPORTANT_STRINGS:
        pos = 0
        hits = []
        while True:
            j = app.find(term, pos)
            if j < 0:
                break
            hits.append({
                "address": h(va(j)),
                "file_offset": hshort(j),
                "text_at_address": cstr(app, va(j)) or term.decode("utf-8", "replace"),
                "word_xrefs": [h(x) for x in find_word_xrefs(app, va(j))],
            })
            pos = j + 1
        found.append({"needle": term.decode("utf-8", "replace"), "hits": hits})
    return found


def dump_words(app: bytes, start: int, count: int) -> list[dict[str, Any]]:
    out = []
    for n in range(count):
        addr = start + n * 4
        value = word_at(app, addr)
        text = cstr(app, value)
        out.append({"slot": n, "address": h(addr), "value": h(value), "target_text": text})
    return out


def extract_ram_offsets(rows: list[Row], start: int, end: int) -> list[str]:
    offs: set[int] = set()
    for r in rows:
        if not (start <= r.addr < end):
            continue
        # Immediate add/mov offsets and bracket offsets are both useful here.
        for m in re.finditer(r"\+ 0x([0-9a-f]+)\]", r.text):
            offs.add(int(m.group(1), 16))
        for m in re.finditer(r"#0x([0-9a-f]+)", r.text):
            v = int(m.group(1), 16)
            if v < 0x2000:
                offs.add(v)
    return [hshort(x) for x in sorted(offs)]


def calls_in_range(rows: list[Row], start: int, end: int) -> list[dict[str, Any]]:
    calls = []
    for r in rows:
        if start <= r.addr < end and "call" in r.mnemonic:
            m = re.search(r"0x[0-9a-fA-F]+", r.text)
            calls.append({"address": h(r.addr), "text": r.text, "target": m.group(0).lower() if m else None})
    return calls


def analyze(app_path: Path, listing_path: Path) -> dict[str, Any]:
    app = app_path.read_bytes()
    sha = hashlib.sha256(app).hexdigest()
    if sha != EXPECTED_APP_SHA256:
        raise SystemExit(f"Refusing non-official app: got {sha}, expected {EXPECTED_APP_SHA256}")
    rows = read_listing(listing_path)

    callbacks = []
    for i in range(CALLBACK_COUNT):
        table_addr = CALLBACK_TABLE + i * 4
        target = word_at(app, table_addr)
        notes = MANUAL_CALLBACK_NOTES.get(i, {})
        callbacks.append({
            "index": i,
            "table_address": h(table_addr),
            "target": h(target),
            "target_file_offset": hshort(off(target)) if BASE <= target < BASE + len(app) else None,
            "classification": notes.get("classification", "candidate"),
            "semantic": notes.get("semantic"),
            "ram_offsets": notes.get("ram_offsets", []),
            "raw_word_xrefs_to_target": [h(x) for x in find_word_xrefs(app, target)],
            "target_listing_snippet": snippet(rows, target, before=5, after=14),
        })

    state_machine_ranges = [
        (0x02028E00, 0x02028E42, "redraw/timer prologue using calls to 0x0201e100"),
        (0x02029152, 0x020291CC, "pending short-event bytes 0x30a..0x30f copied to live bytes 0x3a..0x3f and helper calls"),
        (0x02029290, 0x02029640, "main state-machine and render/update routine"),
        (0x02029528, 0x0202953C, "screen/submode jump table for [0x1c33260+0x302] values 2..6"),
        (0x020295B2, 0x02029612, "timers and long-hold candidate path"),
        (0x02029642, 0x020297B2, "three 16-slot grid case renderers"),
        (0x020297F2, 0x02029B80, "callback target cluster immediately after state machine"),
    ]
    sm = []
    for start, end, desc in state_machine_ranges:
        sm.append({
            "range": [h(start), h(end)],
            "description": desc,
            "ram_offsets_seen": extract_ram_offsets(rows, start, end),
            "calls": calls_in_range(rows, start, end),
            "listing_excerpt": snippet(rows, start, before=0, after=24),
        })

    string_tables = [
        {
            "name": "modal/save/sequence label table candidate",
            "start": h(0x02057C00),
            "classification": "candidate-string-table",
            "words": dump_words(app, 0x02057C00, 20),
            "notes": "Contains On, SAVE/SAVED colored substrings, Step/Gate/Swing labels, but several pointers intentionally land inside markup/string tails. Use as xref evidence, not a renderer ABI.",
        },
        {
            "name": "Pad Bank/channel label table candidate",
            "start": h(0x02058300),
            "classification": "candidate-string-table-with-confirmed-pointers",
            "words": dump_words(app, 0x02058300, 12),
            "notes": "Direct word pointers to Pad Bank- at 0x02058304 and Keys Channel- at 0x02058314 are confirmed. Neighbor entries include suffix/mid-string pointers and require renderer ABI before patching.",
        },
        {
            "name": "screen/function pointer cluster before save labels",
            "start": h(0x02057BEC),
            "classification": "candidate-screen-dispatch-table",
            "words": dump_words(app, 0x02057BEC, 8),
            "notes": "Code pointers near labels, including 0x02029e7c/0x02029eb4/0x02029f1c/0x02029f62/0x02029fee. Likely screen action/render handlers, but direct caller is not resolved by raw word xref.",
        },
    ]

    conclusions = {
        "confirmed": [
            "Official app identity is fixed by SHA-256 and runtime base 0x02000000.",
            "0x02058248 is an 11-word table of internal v15 code pointers, not a plain UI text pointer table.",
            "The target cluster 0x020297f2..0x02029aaa and 0x0202439e mutates RAM bases 0x1c33260 and 0x1c34894, proving these are internal UI/state callees rather than SDK-only hints.",
            "0x02029290 is a state-machine/render-update candidate using RAM base 0x1c33260, with screen/submode byte [0x302], screen byte [0x200], timers [0xc0]/[0xbe], and pending event bytes [0x309]..[0x30f].",
            "0x02029528 dispatches [0x302]-2 through a tbh jump table for values 2..6, producing separate 16-slot grid/render paths.",
            "0x0201e06c is called from UI/event paths with small IDs such as 0x19 and 0x14 after dirty flags/timers are set, making it an internal redraw/event-trigger candidate.",
        ],
        "candidates": [
            "0x02058248 is a button/encoder callback vector candidate. It has no raw direct pointer xref to the table base, so the dispatcher/caller remains unresolved.",
            "0x0202439e is the strongest encoder handler candidate because it interprets a centered 0x3f delta, clamps 0..0x7f, stores 0x00c6, and raises redraw/timer fields.",
            "Short press appears to enter through one-shot bytes [0x309]..[0x30f] copied to [0x39]..[0x3f] with helper calls at 0x02028e46/64/86/a6/ec8/eea.",
            "Long press/hold candidate uses [0xbe] countdown gated by [0xb4] bit mask and 0x1c08b10+1, then sets [0x1fc]=1 and calls 0x0201e06c(0x14).",
            "Pad Bank/SAVE labels are confirmed in app-resident string pools and pointer tables, but exact physical button-to-screen transition labels require caller resolution.",
        ],
        "unresolved": [
            "No literal 'Patch' or mixed-case 'Para/Fx' screen names were found. 'PARA' exists at 0x0205729d, and FX-like parameter labels exist, but screen names are not confirmed by string evidence.",
            "The caller of the 0x02058248 vector and exact physical short/long button IDs are not resolved by current static evidence.",
            "The renderer ABI for mid-string/markup pointers around 0x02057c00 and 0x02058300 remains unresolved. These tables are evidence for state/UI labels, not safe patch schemas.",
            "Public SDK key/ui APIs were not used as proof. No public-SDK function name is promoted without v15 caller/callee/RAM evidence.",
        ],
    }

    return {
        "schema": "smk37-v15-ui-preflash-events-static-v1",
        "inputs": {
            "app_path": str(app_path),
            "app_size": len(app),
            "app_sha256": sha,
            "listing_path": str(listing_path),
            "runtime_base": h(BASE),
            "policy": "official v15 app only; no patch, no flash, no commit; public SDK/UI names are search hints only",
        },
        "callback_table_0x02058248": {
            "address": h(CALLBACK_TABLE),
            "file_offset": hshort(off(CALLBACK_TABLE)),
            "classification": "candidate button/encoder callback vector, internally proven code-pointer run, caller unresolved",
            "raw_word_xrefs_to_table_base": [h(x) for x in find_word_xrefs(app, CALLBACK_TABLE)],
            "entries": callbacks,
            "nearby_context": {
                "before": dump_words(app, 0x020581C8, 12),
                "after_string_and_usb_descriptor_boundary": dump_words(app, 0x020582C8, 16),
            },
        },
        "state_machine": {
            "primary_candidate": h(UI_STATE_MACHINE),
            "classification": "confirmed internal UI/screen state-machine candidate; semantic labels partial",
            "ram_base": h(RAM_UI),
            "alt_ram_base": h(RAM_ALT),
            "redraw_trigger_candidate": h(REDRAW_CANDIDATE),
            "cell_render_candidate": h(CELL_RENDER_CANDIDATE),
            "evidence_ranges": sm,
            "screen_case_map_candidate": [
                {"ram_0x302_value": 2, "target": h(0x0202953E), "meaning": "case with [0x1639]/[0x168a] mask rendering, exact screen unresolved"},
                {"ram_0x302_value": 3, "target": h(0x02029642), "meaning": "16-slot grid renderer case, selected low-nibble path candidate"},
                {"ram_0x302_value": 4, "target": h(0x020296EA), "meaning": "16-slot grid renderer case, selected upper/uextra nibble path candidate"},
                {"ram_0x302_value": 5, "target": h(0x0202953C), "meaning": "falls/defaults back toward common render/update path"},
                {"ram_0x302_value": 6, "target": h(0x0202974E), "meaning": "16-slot grid renderer case, low-nibble highlight path candidate"},
            ],
            "short_long_press_candidates": {
                "short_press": "[0x1c33260+0x309..0x30f] pending bytes are copied to [0x39..0x3f] and invoke helpers 0x02028e46/64/86/a6/c8/ea. Exact button IDs unresolved.",
                "long_press": "[0xbe] countdown plus [0xb4] bit mask and 0x1c08b10+1 gate sets [0x1fc]=1 and calls 0x0201e06c(0x14). Candidate hold/long-press trigger.",
                "encoder": "0x0202439e centered-delta path around 0x3f, clamp 0..0x7f, dirty flag/timer writes. Strongest encoder event candidate.",
            },
        },
        "ui_strings_and_tables": {
            "important_string_hits": find_strings(app),
            "tables": string_tables,
            "screen_transition_labels": {
                "Patch": {"classification": "unresolved", "evidence": "literal Patch/PATCH not found in official app string scan; patch/preset selection may be icon/abbrev/resource-coded"},
                "Para": {"classification": "candidate", "evidence": "PARA at 0x0205729d, parameter labels Cut Off-/Distortion-/Algorithm-/Feedback- in text pool, but no caller-confirmed screen transition"},
                "Fx": {"classification": "candidate", "evidence": "FX-like parameter labels exist, no literal Fx screen string and no physical event mapping"},
                "Pad Bank": {"classification": "confirmed-string-candidate-screen", "evidence": "Pad Bank- at 0x0205d9c5, direct pointer at 0x02058304, state-machine grid paths candidate"},
                "SAVE": {"classification": "confirmed-string-candidate-screen", "evidence": "SAVE at 0x02057298 and colored #D9D9D9 SAVE#/#f5bc27 SAVED# in UI text pool; save-bank prompt at 0x02057f84; exact button transition unresolved"},
            },
        },
        "conclusions": conclusions,
    }


def write_markdown(data: dict[str, Any], path: Path) -> None:
    c = data["conclusions"]
    lines = []
    lines.append("# 공식 v15 UI preflash event/static analysis")
    lines.append("")
    lines.append("Status: 정적 분석 전용. Patch/flash/commit 미수행.")
    lines.append("")
    lines.append("## 입력")
    lines.append("")
    lines.append(f"- App: `{data['inputs']['app_path']}`")
    lines.append(f"- SHA-256: `{data['inputs']['app_sha256']}`")
    lines.append(f"- Runtime base: `{data['inputs']['runtime_base']}`")
    lines.append(f"- Listing: `{data['inputs']['listing_path']}`")
    lines.append("")
    lines.append("## 확정")
    lines.extend(f"- {x}" for x in c["confirmed"])
    lines.append("")
    lines.append("## 후보")
    lines.extend(f"- {x}" for x in c["candidates"])
    lines.append("")
    lines.append("## 미확정")
    lines.extend(f"- {x}" for x in c["unresolved"])
    lines.append("")
    lines.append("## 0x02058248 callback/vector 후보")
    lines.append("")
    cb = data["callback_table_0x02058248"]
    lines.append(f"Classification: **{cb['classification']}**")
    lines.append(f"Raw xrefs to table base: `{cb['raw_word_xrefs_to_table_base']}`. Absence of a raw word xref is why the dispatcher/caller is not confirmed.")
    lines.append("")
    lines.append("| slot | table VA | target | classification | RAM evidence / semantic |")
    lines.append("|---:|---:|---:|---|---|")
    for e in cb["entries"]:
        lines.append(f"| {e['index']} | `{e['table_address']}` | `{e['target']}` | {e['classification']} | {e['semantic']} |")
    lines.append("")
    lines.append("## 화면 state machine 및 event timing")
    lines.append("")
    sm = data["state_machine"]
    lines.append(f"Primary candidate: `{sm['primary_candidate']}` with RAM base `{sm['ram_base']}`.")
    lines.append(f"Redraw/event trigger candidate: `{sm['redraw_trigger_candidate']}`. Cell render/update candidate: `{sm['cell_render_candidate']}`.")
    lines.append("")
    lines.append("| `[0x1c33260+0x302]` | target | current interpretation |")
    lines.append("|---:|---:|---|")
    for case in sm["screen_case_map_candidate"]:
        lines.append(f"| `{case['ram_0x302_value']}` | `{case['target']}` | {case['meaning']} |")
    lines.append("")
    lines.append("Short/long/encoder 후보:")
    for k, v in sm["short_long_press_candidates"].items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Patch/Para/Fx/Pad Bank/SAVE 분류")
    lines.append("")
    labels = data["ui_strings_and_tables"]["screen_transition_labels"]
    lines.append("| 화면 | 분류 | 근거 |")
    lines.append("|---|---|---|")
    for name, info in labels.items():
        lines.append(f"| {name} | {info['classification']} | {info['evidence']} |")
    lines.append("")
    lines.append("## 재현")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/ui-preflash/events/analyze_ui_events.py")
    lines.append("```")
    lines.append("")
    lines.append("스크립트는 공식 v15 app hash를 확인한 뒤 `ui_events.json`과 이 보고서를 재생성한다. Hash가 다르면 실행을 거부한다.")
    path.write_text("\n".join(lines) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", type=Path, default=DEFAULT_APP)
    ap.add_argument("--listing", type=Path, default=DEFAULT_LISTING)
    ap.add_argument("--outdir", type=Path, default=OUTDIR)
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)
    data = analyze(args.app, args.listing)
    (args.outdir / "ui_events.json").write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    write_markdown(data, args.outdir / "report.md")
    print(f"wrote {args.outdir / 'ui_events.json'}")
    print(f"wrote {args.outdir / 'report.md'}")


if __name__ == "__main__":
    main()
