#!/usr/bin/env python3
"""Final-pass v15 UI renderer indirect-path audit.

Official v15 only. This script consumes the official app bytes plus existing
ui-preflash/followup artifacts and Quarkslab/Kagaimiq listing artifacts. It does
not patch, flash, invoke Ghidra, or write outside this directory.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import struct
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent
APP = ROOT / "build/v15-official-app.bin"
RESULTS = ROOT / "baselines/v15/analysis/quarkslab/results"
ARTIFACTS = ROOT / "baselines/v15/analysis/ui-preflash"
EXPECTED_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
RUNTIME_BASE = 0x02000000

LISTINGS = {
    "quarkslab_recursive": RESULTS / "quarkslab-recursive-listing.tsv.gz",
    "quarkslab_exhaustive": RESULTS / "quarkslab-exhaustive-listing.tsv.gz",
    "kagaimiq_patched_recursive": RESULTS / "kagaimiq-patched-recursive-listing.tsv.gz",
    "kagaimiq_patched_exhaustive": RESULTS / "kagaimiq-patched-exhaustive-listing.tsv.gz",
}

EXISTING_INPUTS = {
    "renderer_evidence_json": ARTIFACTS / "renderer/evidence.json",
    "renderer_evidence_report": ARTIFACTS / "renderer/evidence-report.md",
    "followup_renderer_xref_json": ARTIFACTS / "followup/renderer-xref.json",
    "followup_renderer_xref_report": ARTIFACTS / "followup/renderer-xref.md",
    "followup_event_dispatcher_json": ARTIFACTS / "followup/event-dispatcher.json",
    "followup_event_dispatcher_report": ARTIFACTS / "followup/event-dispatcher.md",
}

STARTS = {
    "builder_02020376": 0x02020376,
    "string_setter_0201a67c": 0x0201A67C,
}
TARGETS = {
    "render_traversal_0200f74c": 0x0200F74C,
    "redraw_dirty_queue_0201e06c": 0x0201E06C,
}
LOWER_RENDER_HELPERS = {
    "render_emit_or_clip_0200f412": 0x0200F412,
    "post_render_cleanup_0200f734": 0x0200F734,
    "child_callback_cleanup_0200f710": 0x0200F710,
    "field14_callback_wrapper_0200f73a": 0x0200F73A,
    "layout_draw_core_0200ee0a": 0x0200EE0A,
}
OTHER_FOCUS = {
    "string_invalidation_0201a1bc": 0x0201A1BC,
    "object_tree_walk_0201ea80": 0x0201EA80,
    "object_link_callback_0201ea94": 0x0201EA94,
    "render_state_dispatch_02023376": 0x02023376,
    "mode_transition_redraw_020233f6": 0x020233F6,
}
DESCRIPTOR_BASE = 0x02057250
RAW_TABLES = {
    "Firmware_descriptor_entry": (0x02058028, 8, "word"),
    "Pad_Bank_descriptor_entry": (0x02058304, 8, "word"),
    "Keys_Channel_descriptor_entry": (0x02058314, 8, "word"),
    "FUN_02023376_base_plus_0xbe0_computed_call_slots": (0x02057E30, 7, "word"),
    "FUN_02023376_base_plus_0x1f0_byte_map": (0x02057440, 32, "byte"),
    "ST7789_like_02058aec_prefix": (0x02058AEC, 0x100, "byte"),
}

CALL_RE = re.compile(r"\bcall\s+(0x[0-9a-fA-F]+)")
GOTO_RE = re.compile(r"\b(?:goto|j[a-z.]*|je|jne|jz|jnz|jb|jbe|ja|jg|jl|jmz|jmnz)\b.*?(0x[0-9a-fA-F]{8})")
CALL_REG_RE = re.compile(r"\bcall\s+(r(?:1[0-5]|[0-9]))\b")
LOAD_FIELD_RE = re.compile(r"(?:lw|ldw|_lw)\s+(r(?:1[0-5]|[0-9])),\[(r(?:1[0-5]|[0-9]))\s*(?:\+\s*(0x[0-9a-fA-F]+))?\]")
LOAD_INDEX_RE = re.compile(r"(?:lw|ldw|_lw)\s+(r(?:1[0-5]|[0-9])),\[(r(?:1[0-5]|[0-9]))\+(r(?:1[0-5]|[0-9]))<<2\]")
MOV_IMM_RE = re.compile(r"^movz?\s+(r(?:1[0-5]|[0-9])),#?(0x[0-9a-fA-F]+)$")


def h(n: int | None) -> str | None:
    return None if n is None else f"0x{n:08x}"


def off(va: int) -> int:
    return va - RUNTIME_BASE


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cstr(app: bytes, va: int, limit: int = 96) -> str | None:
    o = off(va)
    if o < 0 or o >= len(app):
        return None
    end = app.find(b"\0", o, min(len(app), o + limit))
    if end < 0 or end == o:
        return None
    raw = app[o:end]
    if all(b in (9, 10, 13) or 32 <= b < 127 for b in raw):
        return raw.decode("ascii", "replace")
    return None


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def slim(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def build_indexes(rows: list[dict[str, str]]) -> dict[str, Any]:
    addr_to_function: dict[int, str] = {}
    function_rows: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        a = row_addr(row)
        fn = row["function"]
        addr_to_function[a] = fn
        if fn != "-":
            function_rows[fn].append(row)
    function_ranges = {}
    for fn, rs in function_rows.items():
        addrs = [row_addr(r) for r in rs]
        function_ranges[fn] = (min(addrs), max(addrs))
    return {"addr_to_function": addr_to_function, "function_rows": function_rows, "function_ranges": function_ranges}


def direct_call_edges(rows: list[dict[str, str]], idx: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        if row["function"] == "-" or row["mnemonic"] != "call":
            continue
        m = CALL_RE.search(row["text"])
        if not m:
            continue
        target = int(m.group(1), 16)
        out[row["function"]].append({
            "callsite": h(row_addr(row)),
            "target": h(target),
            "target_function": idx["addr_to_function"].get(target, "-"),
            "row": slim(row),
        })
    return out


def bfs_paths(graph: dict[str, list[dict[str, Any]]], start_fn: str, target_fns: set[str], max_depth: int = 6, max_paths: int = 20) -> list[list[dict[str, Any]]]:
    found: list[list[dict[str, Any]]] = []
    q: deque[tuple[str, list[dict[str, Any]], set[str]]] = deque([(start_fn, [], {start_fn})])
    while q and len(found) < max_paths:
        fn, path, seen = q.popleft()
        if len(path) >= max_depth:
            continue
        for edge in graph.get(fn, []):
            tfn = edge["target_function"]
            if tfn == "-":
                continue
            new_path = path + [edge]
            if tfn in target_fns:
                found.append(new_path)
                continue
            if tfn not in seen:
                q.append((tfn, new_path, seen | {tfn}))
    return found


def window(rows: list[dict[str, str]], center: int, before: int = 8, after: int = 10) -> list[dict[str, str]]:
    pos = None
    for i, row in enumerate(rows):
        if row_addr(row) >= center:
            pos = i
            break
    if pos is None:
        pos = len(rows)
    return [slim(r) for r in rows[max(0, pos - before): min(len(rows), pos + after + 1)]]


def direct_callers(rows: list[dict[str, str]], target: int) -> list[dict[str, Any]]:
    key = h(target)
    assert key
    out = []
    for row in rows:
        if row["mnemonic"] == "call" and key in row["text"].lower():
            out.append({"callsite": h(row_addr(row)), "function": row["function"], "row": slim(row), "context": window(rows, row_addr(row), 5, 5)})
    return out


def infer_computed_call_source(rows: list[dict[str, str]], i: int) -> dict[str, Any]:
    row = rows[i]
    m = CALL_REG_RE.search(row["text"])
    call_reg = m.group(1) if m else None
    evidence = []
    if not call_reg:
        return {"call_register": None, "source_guess": None, "evidence": []}
    for prev in reversed(rows[max(0, i - 10):i]):
        text = prev["text"].strip()
        lm = LOAD_FIELD_RE.search(text)
        if lm and lm.group(1) == call_reg:
            offset = int(lm.group(3), 16) if lm.group(3) else 0
            evidence.append(slim(prev))
            return {
                "call_register": call_reg,
                "source_guess": {
                    "kind": "object_field_load",
                    "dst": lm.group(1),
                    "base_register": lm.group(2),
                    "field_offset": f"0x{offset:x}",
                    "load_address": h(row_addr(prev)),
                },
                "evidence": evidence,
            }
        im = LOAD_INDEX_RE.search(text)
        if im and im.group(1) == call_reg:
            evidence.append(slim(prev))
            return {
                "call_register": call_reg,
                "source_guess": {
                    "kind": "indexed_word_load",
                    "dst": im.group(1),
                    "base_register": im.group(2),
                    "index_register": im.group(3),
                    "load_address": h(row_addr(prev)),
                },
                "evidence": evidence,
            }
        mm = MOV_IMM_RE.match(text)
        if mm and mm.group(1) == call_reg:
            evidence.append(slim(prev))
            return {
                "call_register": call_reg,
                "source_guess": {"kind": "immediate_function_pointer", "value": h(int(mm.group(2), 16)), "load_address": h(row_addr(prev))},
                "evidence": evidence,
            }
    return {"call_register": call_reg, "source_guess": None, "evidence": [slim(r) for r in rows[max(0, i - 4):i]]}


def computed_calls(rows: list[dict[str, str]], focus_functions: set[str] | None = None) -> list[dict[str, Any]]:
    out = []
    for i, row in enumerate(rows):
        if "COMPUTED_CALL" not in row["flow_type"] and not CALL_REG_RE.search(row["text"]):
            continue
        if focus_functions and row["function"] not in focus_functions:
            continue
        src = infer_computed_call_source(rows, i)
        out.append({
            "callsite": h(row_addr(row)),
            "function": row["function"],
            "row": slim(row),
            **src,
            "context": window(rows, row_addr(row), 6, 4),
        })
    return out


def callback_registrations(rows: list[dict[str, str]], idx: dict[str, Any], helper: int = 0x0200A104) -> list[dict[str, Any]]:
    key = h(helper)
    assert key
    out = []
    for i, row in enumerate(rows):
        if row["mnemonic"] != "call" or key not in row["text"].lower():
            continue
        reg_values: dict[str, int] = {}
        for prev in rows[max(0, i - 8):i]:
            mm = MOV_IMM_RE.match(prev["text"].strip())
            if mm:
                reg_values[mm.group(1)] = int(mm.group(2), 16)
        if "r1" in reg_values:
            val = reg_values["r1"]
            out.append({
                "callsite": h(row_addr(row)),
                "function": row["function"],
                "registered_r1_value": h(val),
                "registered_r1_function": idx["addr_to_function"].get(val, "-"),
                "classification": "callback registration candidate only; helper semantics are inferred from r0/r1 matching and global list traversal, not promoted to a concrete vtable slot",
                "context": window(rows, row_addr(row), 6, 3),
            })
    return out


def raw_word_refs(app: bytes, value: int) -> list[str]:
    pat = struct.pack("<I", value)
    refs = []
    i = 0
    while True:
        j = app.find(pat, i)
        if j < 0:
            return refs
        refs.append(h(RUNTIME_BASE + j))
        i = j + 1


def decode_raw_table(app: bytes, idx: dict[str, Any], name: str, va: int, count: int, kind: str) -> dict[str, Any]:
    o = off(va)
    if kind == "byte":
        raw = app[o:o + count]
        return {"address": h(va), "kind": kind, "bytes_hex": raw.hex(), "bytes_dec": list(raw)}
    entries = []
    for slot in range(count):
        addr = va + slot * 4
        value = struct.unpack_from("<I", app, o + slot * 4)[0]
        in_app = RUNTIME_BASE <= value < RUNTIME_BASE + len(app)
        fn = idx["addr_to_function"].get(value, "-") if in_app else "-"
        entries.append({
            "slot": slot,
            "entry_va": h(addr),
            "value": h(value),
            "ascii_if_string": cstr(app, value),
            "points_into_app": in_app,
            "target_function": fn,
            "promotion": "code-pointer-candidate" if fn != "-" else "not-promoted",
        })
    return {"address": h(va), "kind": kind, "entries": entries}


def listing_refs_to(rows: list[dict[str, str]], va: int) -> list[dict[str, str]]:
    key = h(va)
    assert key
    return [slim(r) for r in rows if key in r["text"].lower()]


def summarize_existing_inputs() -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, path in EXISTING_INPUTS.items():
        entry: dict[str, Any] = {"path": str(path.relative_to(ROOT)), "sha256": sha256(path), "exists": path.exists()}
        if path.suffix == ".json":
            try:
                data = json.loads(path.read_text())
                if name == "followup_renderer_xref_json":
                    entry["selected_summary"] = {
                        "builder_direct_to_render": data.get("builder_02020376", {}).get("contains_direct_call_to_render_traversal_0200f74c"),
                        "builder_direct_to_redraw": data.get("builder_02020376", {}).get("contains_direct_call_to_redraw_0201e06c"),
                        "direct_chain_found": data.get("conclusion", {}).get("direct_chain_found"),
                    }
                elif name == "renderer_evidence_json":
                    entry["selected_summary"] = {"format": data.get("format"), "scope": data.get("scope", {})}
                elif name == "followup_event_dispatcher_json":
                    entry["selected_summary"] = {"promotion_decision": data.get("promotion_decision")}
            except Exception as exc:  # defensive, still hash the artifact
                entry["json_read_error"] = str(exc)
        out[name] = entry
    return out


def target_function_names(idx: dict[str, Any], addrs: dict[str, int]) -> dict[str, str]:
    return {name: idx["addr_to_function"].get(addr, "-") for name, addr in addrs.items()}


def direct_graph_result(rows: list[dict[str, str]], idx: dict[str, Any]) -> dict[str, Any]:
    graph = direct_call_edges(rows, idx)
    starts = target_function_names(idx, STARTS)
    targets = target_function_names(idx, TARGETS)
    target_fns = set(targets.values()) - {"-"}
    return {
        "start_functions": starts,
        "target_functions": targets,
        "paths": {
            start_name: bfs_paths(graph, start_fn, target_fns)
            for start_name, start_fn in starts.items()
            if start_fn != "-"
        },
        "policy": "Only named listing functions and direct call rows are traversed. Rows with function '-' and computed calls are recorded separately, not promoted into a path.",
    }


def main() -> None:
    app = APP.read_bytes()
    app_sha = hashlib.sha256(app).hexdigest()
    if app_sha != EXPECTED_SHA256:
        raise SystemExit(f"Refusing non-official v15 app: got {app_sha}, expected {EXPECTED_SHA256}")

    listing_rows = {name: read_listing(path) for name, path in LISTINGS.items()}
    primary_rows = listing_rows["quarkslab_exhaustive"]
    primary_idx = build_indexes(primary_rows)
    focus_addrs = {**STARTS, **TARGETS, **LOWER_RENDER_HELPERS, **OTHER_FOCUS}
    focus_functions = set(target_function_names(primary_idx, focus_addrs).values()) - {"-"}

    per_listing = {}
    for lname, rows in listing_rows.items():
        idx = build_indexes(rows)
        graph = direct_graph_result(rows, idx)
        per_listing[lname] = {
            "row_count": len(rows),
            "sha256_gzip": sha256(LISTINGS[lname]),
            "start_functions": graph["start_functions"],
            "target_functions": graph["target_functions"],
            "direct_paths_start_to_render_or_redraw": graph["paths"],
            "direct_callers": {
                target_name: direct_callers(rows, target_addr)
                for target_name, target_addr in TARGETS.items()
            },
            "computed_call_count": len(computed_calls(rows)),
        }

    raw_tables = {
        name: decode_raw_table(app, primary_idx, name, va, count, kind)
        for name, (va, count, kind) in RAW_TABLES.items()
    }
    raw_refs = {name: raw_word_refs(app, addr) for name, addr in {**STARTS, **TARGETS, **LOWER_RENDER_HELPERS, **OTHER_FOCUS}.items()}

    focus_computed = computed_calls(primary_rows, focus_functions)
    all_computed = computed_calls(primary_rows)
    field_offsets: dict[str, int] = defaultdict(int)
    for item in all_computed:
        guess = item.get("source_guess") or {}
        if guess.get("kind") == "object_field_load":
            field_offsets[guess["field_offset"]] += 1
        elif guess.get("kind") == "indexed_word_load":
            field_offsets["indexed_word_load"] += 1
        else:
            field_offsets["unresolved"] += 1

    report_data: dict[str, Any] = {
        "format": "smk37-v15-ui-renderer-final-pass-v1",
        "scope": {
            "official_v15_only": True,
            "static_only": True,
            "no_patch_no_flash": True,
            "runtime_base": h(RUNTIME_BASE),
            "app_path": str(APP.relative_to(ROOT)),
            "app_size": len(app),
            "app_sha256": app_sha,
            "output_dir": str(OUT.relative_to(ROOT)),
        },
        "existing_ui_preflash_inputs": summarize_existing_inputs(),
        "per_listing_results": per_listing,
        "primary_quarkslab_exhaustive_deep_dive": {
            "direct_graph": direct_graph_result(primary_rows, primary_idx),
            "target_direct_callers": {name: direct_callers(primary_rows, addr) for name, addr in TARGETS.items()},
            "focus_computed_calls": focus_computed,
            "computed_call_source_offset_histogram": dict(sorted(field_offsets.items())),
            "callback_registration_candidates_0200a104": callback_registrations(primary_rows, primary_idx)[:200],
            "raw_pointer_refs_to_key_functions": raw_refs,
            "raw_tables": raw_tables,
            "specific_listing_refs": {
                "st7789_like_02058aec": listing_refs_to(primary_rows, 0x02058AEC),
                "st7789_overlap_02058b50": listing_refs_to(primary_rows, 0x02058B50),
                "computed_table_02057e30": listing_refs_to(primary_rows, 0x02057E30),
                "descriptor_keys_02058314": listing_refs_to(primary_rows, 0x02058314),
            },
        },
        "conclusions": {
            "direct_or_named_indirect_path_from_02020376_to_0200f74c_or_0201e06c": False,
            "direct_or_named_indirect_path_from_0201a67c_to_0200f74c_or_0201e06c": False,
            "evidence_backed_partial_paths": [
                "0x02020376 computes descriptor-base-relative 0x10c4 and calls 0x0201a67c with r1=0x02058314 for Keys Channel- (from existing followup, re-used here as input).",
                "0x0201a67c updates object field +0x24 and calls 0x0201a1bc after a successful string replacement, but no direct/named indirect path from that helper to 0x0200f74c or 0x0201e06c is recovered in the checked listings.",
                "0x0200f74c has internal computed callbacks from object/context fields +0x18, +0x0, +0x4 and then calls 0x0200f412/0x0200f734; this is a render traversal candidate but not reached from the requested starts by evidence-backed graph traversal.",
                "0x0201e06c manipulates a RAM linked list at 0x01c33260+0x158 and is reached by multiple UI state/update routines, but not by 0x02020376 or 0x0201a67c in the direct/named call graph.",
            ],
            "lcd_or_final_pixel_write_status": "not recovered",
            "lcd_blockers": [
                "No raw 32-bit pointer refs to 0x0200f74c, 0x0201e06c, 0x0200f412, or 0x0200f734 exist in the official app bytes.",
                "The ST7789-like byte run at 0x02058aec remains byte-pattern-only; listing references include the known overlap around 0x02058b50, so it is not promoted to an LCD init table or write path.",
                "Computed calls are recorded with source offsets, but their runtime targets are not statically resolved to final LCD/draw functions without additional evidence.",
            ],
            "promotion_policy": "No row with function '-' and no computed-call target is promoted to a caller chain. Raw table entries are promoted only when the word points into a named listing function; otherwise they remain not-promoted.",
        },
    }

    (OUT / "renderer-trace.json").write_text(json.dumps(report_data, indent=2, sort_keys=True) + "\n")
    write_report(report_data)


def md_table(rows: list[list[str]]) -> str:
    if not rows:
        return ""
    head, *body = rows
    out = ["| " + " | ".join(head) + " |", "| " + " | ".join(["---"] * len(head)) + " |"]
    out += ["| " + " | ".join(r) + " |" for r in body]
    return "\n".join(out)


def path_count(paths_obj: dict[str, list[Any]]) -> int:
    return sum(len(v) for v in paths_obj.values())


def write_report(data: dict[str, Any]) -> None:
    primary = data["primary_quarkslab_exhaustive_deep_dive"]
    per = data["per_listing_results"]
    lines: list[str] = []
    lines.append("# v15 final-pass renderer indirect-call graph audit")
    lines.append("")
    lines.append("## Scope")
    s = data["scope"]
    lines.append(f"- Official app: `{s['app_path']}`")
    lines.append(f"- SHA-256 gate: `{s['app_sha256']}`")
    lines.append("- Static only. Firmware patch/flash was not performed.")
    lines.append("- Inputs include existing `ui-preflash/renderer` and `ui-preflash/followup` artifacts plus Quarkslab/Kagaimiq recursive/exhaustive listings.")
    lines.append("")
    lines.append("## Result")
    lines.append("- **No evidence-backed direct or named indirect path** was recovered from `0x02020376` or `0x0201a67c` to `0x0200f74c` or `0x0201e06c` in any checked listing.")
    lines.append("- The known partial chain remains: `0x02020376` computes `0x02058314` (`Keys Channel-` descriptor entry) and calls `0x0201a67c` as a string/object setter.")
    lines.append("- `0x0201a67c` can call `0x0201a1bc` after replacing `[object+0x24]`, but this final pass does not find a defensible continuation from that helper to `0x0200f74c` or `0x0201e06c`.")
    lines.append("- `0x0200f74c` still looks like an object render traversal candidate because it invokes callbacks loaded from object/context fields and then calls `0x0200f412`/`0x0200f734`; it is not reached from the requested starts by evidence-backed graph traversal.")
    lines.append("- Final LCD/pixel write remains **not recovered**. The ST7789-like byte run is not promoted because independent write-path xrefs are absent and the known `0x02058b50` overlap remains contradictory.")
    lines.append("")
    lines.append("## Cross-listing path counts")
    rows = [["listing", "rows", "paths from starts to targets", "computed calls"]]
    for name, item in per.items():
        rows.append([name, str(item["row_count"]), str(path_count(item["direct_paths_start_to_render_or_redraw"])), str(item["computed_call_count"])])
    lines.append(md_table(rows))
    lines.append("")
    lines.append("## Direct target callers in primary exhaustive listing")
    rows = [["target", "caller count", "caller functions"]]
    for target, callers in primary["target_direct_callers"].items():
        funcs = sorted({c["function"] for c in callers})
        rows.append([target, str(len(callers)), "<br>".join(funcs[:18]) + ("<br>..." if len(funcs) > 18 else "")])
    lines.append(md_table(rows))
    lines.append("")
    lines.append("## Focus computed-call sources")
    rows = [["callsite", "function", "source", "classification"]]
    for item in primary["focus_computed_calls"][:40]:
        guess = item.get("source_guess") or {}
        if guess.get("kind") == "object_field_load":
            src = f"{guess.get('base_register')}+{guess.get('field_offset')} -> {item.get('call_register')}"
            klass = "object/vtable-field callback candidate"
        elif guess.get("kind") == "indexed_word_load":
            src = f"{guess.get('base_register')} + {guess.get('index_register')}<<2 -> {item.get('call_register')}"
            klass = "indexed raw-table callback candidate"
        else:
            src = "unresolved"
            klass = "not promoted"
        rows.append([item["callsite"], item["function"], src, klass])
    lines.append(md_table(rows))
    lines.append("")
    lines.append("Computed-call source histogram in all primary exhaustive rows:")
    lines.append("```json")
    lines.append(json.dumps(primary["computed_call_source_offset_histogram"], indent=2, sort_keys=True))
    lines.append("```")
    lines.append("")
    lines.append("## Raw table checks")
    table = primary["raw_tables"]["FUN_02023376_base_plus_0xbe0_computed_call_slots"]
    rows = [["slot", "entry", "value", "target function", "promotion"]]
    for entry in table["entries"]:
        rows.append([str(entry["slot"]), entry["entry_va"], entry["value"], entry["target_function"], entry["promotion"]])
    lines.append("### `0x02023376` computed-call table candidate at `0x02057e30`")
    lines.append(md_table(rows))
    lines.append("")
    lines.append("Only slots that point into named listing functions are code-pointer candidates. Other slots are not promoted.")
    lines.append("")
    lines.append("### Descriptor entries")
    rows = [["entry", "slot0", "slot1", "slot2", "slot3"]]
    for name in ["Firmware_descriptor_entry", "Pad_Bank_descriptor_entry", "Keys_Channel_descriptor_entry"]:
        entries = primary["raw_tables"][name]["entries"]
        rows.append([name] + [f"{e['value']} {e.get('ascii_if_string') or ''}" for e in entries[:4]])
    lines.append(md_table(rows))
    lines.append("")
    lines.append("## LCD/final draw status")
    for blocker in data["conclusions"]["lcd_blockers"]:
        lines.append(f"- {blocker}")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/ui-preflash/final-pass/renderer/trace_renderer_paths.py")
    lines.append("python3 - <<'PY'")
    lines.append("import json")
    lines.append("from pathlib import Path")
    lines.append("p=Path('baselines/v15/analysis/ui-preflash/final-pass/renderer/renderer-trace.json')")
    lines.append("d=json.loads(p.read_text())")
    lines.append("print(d['conclusions']['direct_or_named_indirect_path_from_02020376_to_0200f74c_or_0201e06c'])")
    lines.append("print(d['conclusions']['lcd_or_final_pixel_write_status'])")
    lines.append("PY")
    lines.append("```")
    lines.append("")
    lines.append("Machine-readable output: `renderer-trace.json`.")
    (OUT / "report.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
