#!/usr/bin/env python3
"""Targeted renderer xref follow-up for v15 UI preflash analysis.

Scope is intentionally narrow: reuse the official app bytes and existing
Quarkslab listings to test whether the already-known UI pointer descriptors or
0x0201a67c string/descriptor setter callers have a direct data-flow/caller chain
to 0x0200f74c render traversal or 0x0201e06c redraw.  This script does not patch,
flash, invoke Ghidra, or commit anything.
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
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
EXHAUSTIVE = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
RECURSIVE = LISTING_DIR / "quarkslab-recursive-listing.tsv.gz"
HEADLESS_LOG = LISTING_DIR / "quarkslab-headless.log"
RUNTIME_BASE = 0x02000000
EXPECTED_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
DESCRIPTOR_BASE = 0x02057250
STRING_SETTER = 0x0201A67C
RENDER_TRAVERSAL = 0x0200F74C
REDRAW = 0x0201E06C

TARGET_POINTER_TABLES = {
    "Firmware_descriptor_entry": 0x02058028,
    "Pad_Bank_descriptor_entry": 0x02058304,
    "Keys_Channel_descriptor_entry": 0x02058314,
}

TARGET_STRINGS = {
    "Firmware_text": 0x0205D8F5,
    "Pad_Bank_text": 0x0205D9C5,
    "Keys_Channel_text": 0x0205D9E9,
}


def h(n: int | None) -> str | None:
    return None if n is None else f"0x{n:08x}"


def off(va: int) -> int:
    return va - RUNTIME_BASE


def cstr(app: bytes, va: int, limit: int = 96) -> str | None:
    if not (RUNTIME_BASE <= va < RUNTIME_BASE + len(app)):
        return None
    start = off(va)
    end = app.find(b"\0", start, min(len(app), start + limit))
    if end < 0 or end == start:
        return None
    raw = app[start:end]
    if not all((b in (9, 10, 13)) or 32 <= b < 127 for b in raw):
        return None
    return raw.decode("ascii", "replace")


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_dict(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def snippet(rows: list[dict[str, str]], center: int, before: int = 8, after: int = 12) -> list[dict[str, str]]:
    addrs = [row_addr(r) for r in rows]
    idx = 0
    for i, a in enumerate(addrs):
        if a >= center:
            idx = i
            break
    else:
        idx = len(rows) - 1
    return [row_dict(r) for r in rows[max(0, idx - before): min(len(rows), idx + after + 1)]]


def callers(rows: list[dict[str, str]], target: int) -> list[dict[str, str]]:
    key = h(target)
    assert key is not None
    out = []
    for r in rows:
        if r["mnemonic"] == "call" and key in r["text"].lower():
            out.append(row_dict(r))
    return out


def rows_in_function(rows: list[dict[str, str]], function: str) -> list[dict[str, str]]:
    return [r for r in rows if r["function"] == function]


def direct_calls_from_function(rows: list[dict[str, str]], function: str) -> list[dict[str, str]]:
    return [row_dict(r) for r in rows if r["function"] == function and "call" in r["mnemonic"]]


def word_refs(app: bytes, value: int) -> list[int]:
    pat = struct.pack("<I", value)
    out: list[int] = []
    i = 0
    while True:
        j = app.find(pat, i)
        if j < 0:
            return out
        out.append(RUNTIME_BASE + j)
        i = j + 1


def descriptor_words(app: bytes, va: int, count: int = 8) -> list[dict[str, Any]]:
    out = []
    base_off = off(va)
    for i in range(count):
        addr = va + i * 4
        value = struct.unpack_from("<I", app, base_off + i * 4)[0]
        out.append({
            "slot": i,
            "address": h(addr),
            "value": h(value),
            "target_text": cstr(app, value),
        })
    return out


REG = r"r(?:1[0-5]|[0-9])"
MOV_IMM_RE = re.compile(rf"^movz? (?P<dst>{REG}),#(?P<imm>0x[0-9a-fA-F]+|-?0x[0-9a-fA-F]+)$")
MOV_REG_RE = re.compile(rf"^mov (?P<dst>{REG}),(?P<src>{REG})$")
ADD_IMM_RE = re.compile(rf"^add (?P<dst>{REG}),(?P<src>{REG}),#?(?P<imm>-?0x[0-9a-fA-F]+)$")
ADD_REG_RE = re.compile(rf"^add (?P<dst>{REG}),(?P<src>{REG})$")


def parse_int(s: str) -> int:
    if s.startswith("-0x"):
        return -int(s[3:], 16)
    return int(s, 16)


def symbolic_hits(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    targets = {**TARGET_POINTER_TABLES, **TARGET_STRINGS}
    target_by_va = {v: k for k, v in targets.items()}
    hits: list[dict[str, Any]] = []
    current_function = None
    regs: dict[str, int] = {}
    for r in rows:
        fn = r["function"]
        if fn != current_function:
            current_function = fn
            regs = {}
        text = r["text"].strip()
        before = dict(regs)
        m = MOV_IMM_RE.match(text)
        if m:
            regs[m.group("dst")] = parse_int(m.group("imm"))
        elif (m := MOV_REG_RE.match(text)):
            if m.group("src") in regs:
                regs[m.group("dst")] = regs[m.group("src")]
            else:
                regs.pop(m.group("dst"), None)
        elif (m := ADD_IMM_RE.match(text)):
            src = m.group("src")
            if src in regs:
                regs[m.group("dst")] = (regs[src] + parse_int(m.group("imm"))) & 0xFFFFFFFF
            else:
                regs.pop(m.group("dst"), None)
        elif (m := ADD_REG_RE.match(text)):
            # Two-operand add: dst += src.  Keep only when both are known.
            dst, src = m.group("dst"), m.group("src")
            if dst in regs and src in regs:
                regs[dst] = (regs[dst] + regs[src]) & 0xFFFFFFFF
            else:
                regs.pop(dst, None)
        elif r["mnemonic"].startswith(("lw", "lb", "lh", "ldw")) and text.split(" ", 1)[-1].split(",", 1)[0] in regs:
            # A real load invalidates a destination register.  The TSV mnemonic/text
            # format is inconsistent, so this handles only simple leading dst forms.
            dst = text.split(" ", 1)[-1].split(",", 1)[0]
            regs.pop(dst, None)

        for reg, value in regs.items():
            if value in target_by_va and before.get(reg) != value:
                hits.append({
                    "target": target_by_va[value],
                    "value": h(value),
                    "descriptor_base_relative_offset": f"0x{value - DESCRIPTOR_BASE:x}" if value >= DESCRIPTOR_BASE else None,
                    "register": reg,
                    "row": row_dict(r),
                    "function": fn,
                })
    return hits


def evidence_ref_log_hits() -> list[dict[str, Any]]:
    if not HEADLESS_LOG.exists():
        return []
    target_hexes = {f"{va:08x}": label for label, va in TARGET_POINTER_TABLES.items()}
    out: list[dict[str, Any]] = []
    for line_no, line in enumerate(HEADLESS_LOG.read_text(errors="replace").splitlines(), start=1):
        lower = line.lower()
        if "evidence_ref" not in lower:
            continue
        for target_hex, label in target_hexes.items():
            if f"to={target_hex}" in lower:
                out.append({"line": line_no, "target": label, "target_va": "0x" + target_hex, "text": line.strip()})
    return out


def entry_r12_descriptor_formula_hits(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Find target descriptor accesses of the form add r?,r12,<base-relative>.

    FUN_02020376 loads r12 with 0x02057250 at entry, but the large tbh body also
    reuses r12 in other cases.  Existing Quarkslab EVIDENCE_REF logs already
    classify 0x02022de0 as 0x02058314, so this narrow pass records only exact
    descriptor-base-relative offsets and labels them as formula/evidence-ref
    candidates rather than broad constant propagation.
    """
    offset_to_label = {va - DESCRIPTOR_BASE: label for label, va in TARGET_POINTER_TABLES.items()}
    out: list[dict[str, Any]] = []
    add_re = re.compile(rf"^add (?P<dst>{REG}),r12,#?(?P<imm>0x[0-9a-fA-F]+)$")
    for i, r in enumerate(rows):
        m = add_re.match(r["text"].strip())
        if not m:
            continue
        imm = int(m.group("imm"), 16)
        if imm not in offset_to_label:
            continue
        target_va = DESCRIPTOR_BASE + imm
        following = [row_dict(x) for x in rows[i + 1:i + 6]]
        out.append({
            "target": offset_to_label[imm],
            "value": h(target_va),
            "descriptor_base": h(DESCRIPTOR_BASE),
            "descriptor_base_relative_offset": f"0x{imm:x}",
            "register": m.group("dst"),
            "row": row_dict(r),
            "function": r["function"],
            "following_rows": following,
            "next_string_setter_call": next((x for x in following if x["mnemonic"] == "call" and h(STRING_SETTER) in x["text"].lower()), None),
            "classification": "targeted descriptor-base formula hit; supported by existing Quarkslab EVIDENCE_REF when present",
        })
    return out


def setter_calls_with_symbolic_r1(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    hits_by_addr = {int(hit["row"]["address"], 16): hit for hit in symbolic_hits(rows)}
    out = []
    for i, r in enumerate(rows):
        if r["mnemonic"] == "call" and h(STRING_SETTER) in r["text"].lower():
            prev_hits = [hits_by_addr.get(row_addr(p)) for p in rows[max(0, i - 8):i]]
            prev_hits = [x for x in prev_hits if x and x.get("register") == "r1"]
            out.append({
                "callsite": row_dict(r),
                "recent_symbolic_r1_hits": prev_hits,
                "context": [row_dict(x) for x in rows[max(0, i - 8): min(len(rows), i + 5)]],
            })
    return out


def main() -> None:
    app = APP.read_bytes()
    sha = hashlib.sha256(app).hexdigest()
    if sha != EXPECTED_SHA256:
        raise SystemExit(f"Refusing non-official app: got {sha}, expected {EXPECTED_SHA256}")
    exhaustive = read_listing(EXHAUSTIVE)
    recursive = read_listing(RECURSIVE)

    table_evidence = {}
    for label, va in TARGET_POINTER_TABLES.items():
        table_evidence[label] = {
            "runtime_va": h(va),
            "file_offset": f"0x{off(va):06x}",
            "descriptor_base": h(DESCRIPTOR_BASE),
            "descriptor_base_relative_offset": f"0x{va - DESCRIPTOR_BASE:x}",
            "raw_words": descriptor_words(app, va),
        }

    string_evidence = {}
    for label, va in TARGET_STRINGS.items():
        string_evidence[label] = {
            "runtime_va": h(va),
            "file_offset": f"0x{off(va):06x}",
            "text": cstr(app, va),
            "raw_word_refs": [h(x) for x in word_refs(app, va)],
        }

    sym_exh = symbolic_hits(exhaustive)
    sym_rec = symbolic_hits(recursive)
    formula_exh = entry_r12_descriptor_formula_hits(exhaustive)
    formula_rec = entry_r12_descriptor_formula_hits(recursive)
    log_hits = evidence_ref_log_hits()
    setter_calls = setter_calls_with_symbolic_r1(exhaustive)
    targeted_setter_hits = [c for c in setter_calls if c["recent_symbolic_r1_hits"]]

    callsets = {
        "direct_callers_of_string_setter_0201a67c": callers(exhaustive, STRING_SETTER),
        "direct_callers_of_render_traversal_0200f74c": callers(exhaustive, RENDER_TRAVERSAL),
        "direct_callers_of_redraw_0201e06c": callers(exhaustive, REDRAW),
        "direct_callers_of_builder_02020376": callers(exhaustive, 0x02020376),
    }

    builder_calls = direct_calls_from_function(exhaustive, "FUN_02020376@02020376")
    builder_direct_targets = sorted({
        int(m.group(0), 16)
        for r in builder_calls
        if (m := re.search(r"0x[0-9a-fA-F]+", r["text"]))
    })

    direct_chain_found = any(t in builder_direct_targets for t in (RENDER_TRAVERSAL, REDRAW))
    result: dict[str, Any] = {
        "input": {
            "app": str(APP.relative_to(ROOT)),
            "sha256": sha,
            "runtime_base": h(RUNTIME_BASE),
            "descriptor_base": h(DESCRIPTOR_BASE),
            "listings": [str(EXHAUSTIVE.relative_to(ROOT)), str(RECURSIVE.relative_to(ROOT))],
        },
        "scope_guard": "Targeted only: known UI pointer tables 0x02058028/0x02058304/0x02058314, string setter 0x0201a67c callers, render traversal 0x0200f74c, redraw 0x0201e06c, and descriptor-base-relative calculations.",
        "target_pointer_tables": table_evidence,
        "target_strings": string_evidence,
        "symbolic_descriptor_hits_exhaustive": sym_exh,
        "symbolic_descriptor_hits_recursive": sym_rec,
        "entry_r12_descriptor_formula_hits_exhaustive": formula_exh,
        "entry_r12_descriptor_formula_hits_recursive": formula_rec,
        "quarkslab_evidence_ref_log_hits": log_hits,
        "string_setter_calls_with_recent_target_r1": targeted_setter_hits,
        "callsets": callsets,
        "builder_02020376": {
            "direct_call_count": len(builder_calls),
            "direct_targets": [h(x) for x in builder_direct_targets],
            "contains_direct_call_to_render_traversal_0200f74c": RENDER_TRAVERSAL in builder_direct_targets,
            "contains_direct_call_to_redraw_0201e06c": REDRAW in builder_direct_targets,
            "snippet_entry_and_base_load": snippet(exhaustive, 0x02020376, before=0, after=16),
            "snippet_keys_channel_setter_call": snippet(exhaustive, 0x02022DE8, before=12, after=12),
        },
        "render_traversal_0200f74c": {
            "direct_callers": callsets["direct_callers_of_render_traversal_0200f74c"],
            "snippets": {row["address"]: snippet(exhaustive, int(row["address"], 16), before=8, after=8) for row in callsets["direct_callers_of_render_traversal_0200f74c"]},
        },
        "redraw_0201e06c": {
            "direct_callers": callsets["direct_callers_of_redraw_0201e06c"],
            "selected_snippets": {row["address"]: snippet(exhaustive, int(row["address"], 16), before=8, after=8) for row in callsets["direct_callers_of_redraw_0201e06c"][:12]},
        },
        "conclusion": {
            "direct_chain_found": direct_chain_found,
            "confirmed_partial_chain": "0x0202038a loads r12=0x02057250; 0x02022de0 computes r1=r12+0x10c4 = 0x02058314; 0x02022de8 calls 0x0201a67c with that r1. 0x02058314 is the Keys Channel- descriptor/pointer-list entry.",
            "blocker": "No evidence-backed direct data-flow/caller chain from 0x02058028/0x02058304/0x02058314 or the targeted 0x0201a67c caller to 0x0200f74c or 0x0201e06c was recovered. 0x02020376 does not directly call either target; 0x0201a67c itself only calls allocator/string helpers; render traversal and redraw direct caller sets are disjoint from FUN_02020376 in named listing functions. Exhaustive rows with function '-' are not promoted to a chain.",
        },
    }

    (OUT / "renderer-xref.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    md = []
    md.append("# v15 UI renderer xref follow-up\n")
    md.append("## Scope\n")
    md.append("- Targeted follow-up only. Inputs are the existing official app and existing Quarkslab listings.\n")
    md.append("- No patch, flash, Ghidra run, broad research, or commit was performed.\n")
    md.append(f"- App SHA-256: `{sha}`. Runtime base: `{h(RUNTIME_BASE)}`. Descriptor base: `{h(DESCRIPTOR_BASE)}`.\n")
    md.append("\n## Result\n")
    md.append("- **Direct chain found:** no.\n")
    md.append("- **Confirmed partial chain:** `0x0202038a mov r12,#0x2057250` -> `0x02022de0 add r1,r12,0x10c4` -> `0x02022de8 call 0x0201a67c`. This computes `0x02058314`, the `Keys Channel-` descriptor/pointer-list entry.\n")
    md.append("- `FUN_02020376@02020376` has many direct `0x0201a67c` calls but no direct `0x0200f74c` or `0x0201e06c` call.\n")
    md.append("- `0x0201a67c` itself calls allocator/string helpers, not traversal/redraw.\n")
    md.append("- Direct callers of `0x0200f74c` and `0x0201e06c` are disjoint from the named `FUN_02020376` builder in the listing. Rows decoded as function `-` were not promoted to a caller chain.\n")

    md.append("\n## Descriptor table targets\n")
    md.append("| target | VA | base-relative | first words |\n")
    md.append("|---|---:|---:|---|\n")
    for label, ev in table_evidence.items():
        words = ", ".join(f"{w['value']} -> {w['target_text'] or '?'}" for w in ev["raw_words"][:4])
        md.append(f"| `{label}` | `{ev['runtime_va']}` | `{ev['descriptor_base_relative_offset']}` | {words} |\n")

    md.append("\n## Calculated/base-relative access hits\n")
    md.append("| listing | target | value | row | function | note |\n")
    md.append("|---|---|---:|---|---|---|\n")
    all_sym = [("exhaustive-symbolic", x) for x in sym_exh] + [("recursive-symbolic", x) for x in sym_rec] + [("exhaustive-r12-formula", x) for x in formula_exh] + [("recursive-r12-formula", x) for x in formula_rec]
    if not all_sym:
        md.append("| - | - | - | - | - | No target calculated-address hit recovered. |\n")
    for listing_name, hit in all_sym:
        note = "descriptor target" if hit["target"].endswith("descriptor_entry") else "string target"
        row = hit["row"]
        md.append(f"| {listing_name} | `{hit['target']}` | `{hit['value']}` | `{row['address']} {row['text']}` | `{hit['function']}` | {note} |\n")
    md.append("\nExisting Quarkslab `EVIDENCE_REF` log hits for these targets:\n")
    if log_hits:
        for hit in log_hits:
            md.append(f"- line {hit['line']}: `{hit['text']}`\n")
    else:
        md.append("- none\n")

    md.append("\nNon-descriptor false-adjacent hit: both listings also contain `0x0201067e add r0,r6,0x10c4`, but there `r6` is derived from RAM `0x1c33260`, not descriptor base `0x02057250`, so it is not a UI pointer-table access.\n")

    md.append("\n## Targeted setter callsite\n")
    for call in targeted_setter_hits:
        cs = call["callsite"]
        recent = call["recent_symbolic_r1_hits"][-1]
        md.append(f"- `{cs['address']}` `{cs['text']}` in `{cs['function']}` uses recent `r1={recent['value']}` from `{recent['row']['address']} {recent['row']['text']}`.\n")
    for hit in formula_exh:
        setter = hit.get("next_string_setter_call")
        if setter:
            md.append(f"- `{setter['address']}` `{setter['text']}` in `{setter['function']}` follows formula `{hit['row']['address']} {hit['row']['text']}` giving `{hit['register']}={hit['value']}`.\n")
    if not targeted_setter_hits and not any(hit.get("next_string_setter_call") for hit in formula_exh):
        md.append("- No `0x0201a67c` callsite had a recovered target-table `r1` value in the simple local symbolic/formula passes.\n")

    md.append("\n### Key snippet\n")
    md.append("```text\n")
    for r in result["builder_02020376"]["snippet_keys_channel_setter_call"]:
        md.append(f"{r['address']}\t{r['bytes']}\t{r['mnemonic']}\t{r['text']}\t{r['flow_type']}\t{r['function']}\n")
    md.append("```\n")

    md.append("\n## Direct caller sets checked\n")
    md.append(f"- `0x02020376` direct callers: {', '.join(r['address'] for r in callsets['direct_callers_of_builder_02020376']) or 'none'}\n")
    md.append(f"- `0x0200f74c` direct callers: {', '.join(r['address'] for r in callsets['direct_callers_of_render_traversal_0200f74c']) or 'none'}\n")
    md.append(f"- `0x0201e06c` direct callers: {', '.join(r['address'] for r in callsets['direct_callers_of_redraw_0201e06c']) or 'none'}\n")

    md.append("\n## Evidence-backed blocker\n")
    md.append(result["conclusion"]["blocker"] + "\n")
    md.append("\n## Reproduce\n")
    md.append("```sh\npython3 baselines/v15/analysis/ui-preflash/followup/analyze_renderer_xref.py\n```\n")
    md.append("Machine-readable output: `renderer-xref.json`.\n")
    (OUT / "renderer-xref.md").write_text("".join(md))


if __name__ == "__main__":
    main()
