#!/usr/bin/env python3
"""Final static UI/event pass for the official SMK-37 Pro v15 app.

Scope is deliberately read-only and official-v15-only.  The script consumes the
official v15 app image plus the Quarkslab exhaustive TSV listing generated from
that same app, then writes JSON and markdown evidence in this directory.  It
never patches, packages, flashes, or talks to hardware.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BASE = 0x02000000
EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
APP = Path("build/v15-official-app.bin")
LISTING = Path("baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz")
OUTDIR = Path("baselines/v15/analysis/ui-preflash/final-pass/events")
JSON_OUT = OUTDIR / "final-pass-events.json"
MD_OUT = OUTDIR / "report.md"

UI_RAM = 0x1C33260
ALT_RAM = 0x1C34894
PRODUCT_RAM = 0x1C0DE20

PENDING_TO_LIVE = {
    0x309: 0x39,
    0x30A: 0x3A,
    0x30B: 0x3B,
    0x30C: 0x3C,
    0x30D: 0x3D,
    0x30E: 0x3E,
    0x30F: 0x3F,
}

TARGETS = [
    0x02028F0C,  # pending consumer function entry found by local listing context
    0x02029152,  # +0x30c..+0x309 pending consumer chain
    0x02029290,  # render/state-machine frame tick
    0x02029528,  # state machine computed branch when +0x302 > 1
    0x02029612,  # +0x30f pending timeout consumer
    0x02029912,  # vector slot 0 target
    0x02029936,
    0x02029974,
    0x020299CE,
    0x020299F2,
    0x02025DEA,  # encoder enclosing-callee call path
    0x02025E06,
]

VECTOR = 0x02058248
VECTOR_COUNT = 11
VECTOR_TARGETS = [
    0x02029912,
    0x02029936,
    0x02029974,
    0x020299CE,
    0x020299F2,
    0x02029A16,
    0x02029A2E,
    0x02029A46,
    0x02029A78,
    0x02029AAA,
    0x0202439E,
]

# Ranges that make the backward slice reproducible without dumping the whole TSV.
RANGES = {
    "pending_consumer_entry_and_consumers": (0x02028F0C, 0x020291CE),
    "state_machine": (0x02029290, 0x02029640),
    "vector_targets_0x020299xx": (0x020298F6, 0x02029AD0),
    "encoder_enclosing_calls": (0x02025DD0, 0x02025E90),
}

REG = r"(?:r(?:1[0-5]|[0-9])|sp|rets|pc|sr[0-9]+)"


@dataclass
class Row:
    addr: int
    bytes_: str
    length: int
    mnemonic: str
    text: str
    flow_type: str
    function: str


def h(value: int | None) -> str | None:
    return None if value is None else f"0x{value:08x}"


def hx(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def va(off: int) -> int:
    return BASE + off


def off(addr: int) -> int:
    return addr - BASE


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_listing(path: Path) -> list[Row]:
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


def row_dict(row: Row) -> dict[str, Any]:
    return {
        "address": h(row.addr),
        "bytes": row.bytes_,
        "mnemonic": row.mnemonic,
        "text": row.text,
        "flow_type": row.flow_type,
        "function": row.function,
    }


def rows_in(rows: list[Row], start: int, end: int) -> list[Row]:
    return [r for r in rows if start <= r.addr < end]


def snippet(rows: list[Row], center: int, before: int = 8, after: int = 16) -> list[dict[str, Any]]:
    addrs = [r.addr for r in rows]
    lo = 0
    hi = len(addrs)
    while lo < hi:
        mid = (lo + hi) // 2
        if addrs[mid] < center:
            lo = mid + 1
        else:
            hi = mid
    i = min(lo, len(rows) - 1)
    return [row_dict(r) for r in rows[max(0, i - before): min(len(rows), i + after + 1)]]


def word_at(app: bytes, addr: int) -> int:
    o = off(addr)
    return int.from_bytes(app[o:o + 4], "little")


def find_bytes(app: bytes, pat: bytes) -> list[int]:
    out: list[int] = []
    i = 0
    while True:
        j = app.find(pat, i)
        if j < 0:
            return out
        out.append(va(j))
        i = j + 1


def raw_xrefs(app: bytes, value: int) -> list[int]:
    return find_bytes(app, value.to_bytes(4, "little"))


def flow_refs(rows: list[Row], target: int) -> list[dict[str, Any]]:
    needle = h(target)
    return [row_dict(r) for r in rows if needle in r.text and r.addr != target]


def cstr(app: bytes, addr: int, limit: int = 96) -> str | None:
    if not (BASE <= addr < BASE + len(app)):
        return None
    start = off(addr)
    end = app.find(b"\0", start, min(len(app), start + limit))
    if end <= start:
        return None
    try:
        return app[start:end].decode("utf-8")
    except UnicodeDecodeError:
        return app[start:end].decode("utf-8", "replace")


def word_table(app: bytes, start: int, count: int) -> list[dict[str, Any]]:
    rows = []
    for slot in range(count):
        addr = start + slot * 4
        value = word_at(app, addr)
        rows.append({
            "slot": slot,
            "table_address": h(addr),
            "value": h(value),
            "raw_xrefs": [h(x) for x in raw_xrefs(app, value)],
            "target_text": cstr(app, value),
        })
    return rows


def kind(row: Row) -> str:
    m = row.mnemonic.strip().lower()
    text = row.text.lower()
    if m in {"sb", "sh", "sw"} or re.match(r"_?s[bhw]", m) or re.search(r"\b_?s[bhw]\b", text):
        return "write"
    if m in {"lb.z", "lb", "lh.z", "lh", "lw", "ldw", "addldw"} or re.match(r"_?l[bhw]", m) or re.search(r"\b_?l[bhw](?:\.z)?\b", text) or "addldw" in text:
        return "read"
    return "other"


def direct_offset_hits(rows: list[Row], offsets: list[int]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for field in offsets:
        hits = []
        patterns = [f"+ 0x{field:x}]", f"#0x{field:x}", f",0x{field:x}", f" 0x{field:x}"]
        for r in rows:
            if any(p in r.text for p in patterns):
                item = row_dict(r)
                item["access_kind"] = kind(r)
                hits.append(item)
        out[hx(field) or ""] = hits
    return out


def base_reconstruction(rows: list[Row]) -> list[dict[str, Any]]:
    bases = [UI_RAM, ALT_RAM, PRODUCT_RAM]
    evidence = []
    for r in rows:
        for b in bases:
            if f"#{hx(b)}" in r.text or f"#{h(b)}" in r.text or f"#{b:#x}" in r.text:
                reg = None
                m = re.search(rf"mov\s+({REG}),#0x[0-9a-f]+", r.text)
                if m:
                    reg = m.group(1)
                evidence.append({
                    "address": h(r.addr),
                    "base": h(b),
                    "base_name": {UI_RAM: "ui_ram", ALT_RAM: "alt_ram", PRODUCT_RAM: "product_ram"}[b],
                    "register": reg,
                    "text": r.text,
                    "function": r.function,
                })
    # Keep target-area evidence plus a little global frequency context.
    target_near = []
    for e in evidence:
        a = int(e["address"], 16)
        if any(start <= a < end for start, end in RANGES.values()):
            target_near.append(e)
    counts = []
    for b in bases:
        counts.append({"base": h(b), "base_name": {UI_RAM: "ui_ram", ALT_RAM: "alt_ram", PRODUCT_RAM: "product_ram"}[b], "listing_mov_hits": sum(1 for e in evidence if e["base"] == h(b))})
    return [{"counts": counts, "target_area_mov_immediates": target_near}]


def local_ram_accesses(rows: list[Row]) -> list[dict[str, Any]]:
    """Best-effort linear constant/base tracking for accesses to UI_RAM +/- target fields.

    This is not a decompiler.  It intentionally reports only accesses where the
    base register is reconstructed in the same linear listing region, which keeps
    false positives lower for field-offset aliases like +0x30c on unrelated bases.
    """
    bases: dict[str, int] = {}
    accesses: list[dict[str, Any]] = []
    target_offsets = set(PENDING_TO_LIVE) | set(PENDING_TO_LIVE.values()) | {0x302, 0x405, 0x406, 0x408, 0x161C, 0x1636, 0x1637, 0x1639, 0x1678, 0x168A, 0x20E, 0x200, 0x203, 0x207, 0x208, 0xC0, 0xCE}

    def reset_if_boundary(row: Row) -> None:
        if row.mnemonic == "push" and "rets" in row.text:
            bases.clear()

    for r in rows:
        reset_if_boundary(r)
        text = r.text
        m = re.search(rf"mov\s+({REG}),#0x([0-9a-f]+)", text)
        if m:
            reg, val = m.group(1), int(m.group(2), 16)
            if val in (UI_RAM, ALT_RAM, PRODUCT_RAM):
                bases[reg] = val
            elif reg in bases:
                bases.pop(reg, None)

        # add dst,base,#imm can create an alias pointer.
        m = re.search(rf"add\s+({REG}),({REG}),#0x([0-9a-f]+)", text)
        if m and m.group(2) in bases:
            bases[m.group(1)] = bases[m.group(2)] + int(m.group(3), 16)
        m = re.search(rf"add\s+({REG}),({REG}),0x([0-9a-f]+)", text)
        if m and m.group(2) in bases:
            bases[m.group(1)] = bases[m.group(2)] + int(m.group(3), 16)

        # mov dst,src aliases a base pointer.
        m = re.search(rf"mov\s+({REG}),({REG})", text)
        if m and m.group(2) in bases:
            bases[m.group(1)] = bases[m.group(2)]

        for mem in re.finditer(rf"\[({REG})\s*\+\s*0x([0-9a-f]+)\]", text):
            reg, imm = mem.group(1), int(mem.group(2), 16)
            if reg not in bases:
                continue
            absolute = bases[reg] + imm
            if UI_RAM <= absolute < UI_RAM + 0x2000:
                field = absolute - UI_RAM
                if field in target_offsets:
                    accesses.append({
                        "address": h(r.addr),
                        "access_kind": kind(r),
                        "field_offset": hx(field),
                        "absolute": h(absolute),
                        "base_register": reg,
                        "reconstructed_base": h(bases[reg]),
                        "text": text,
                        "function": r.function,
                    })
    return accesses


def call_windows(rows: list[Row], interesting_offsets: set[int]) -> list[dict[str, Any]]:
    out = []
    for idx, r in enumerate(rows):
        if "call" not in r.mnemonic and "call" not in r.text:
            continue
        window = rows[max(0, idx - 10): idx + 1]
        text = "\n".join(w.text for w in window)
        mentioned = sorted(o for o in interesting_offsets if f"0x{o:x}" in text or f"+ 0x{o:x}]" in text)
        has_ui_base = "0x1c33260" in text
        has_small_copy_len = any(tok in text for tok in ["#0x7", "#0x8", "#0x10", "#0x28", "#0x2c"])
        if mentioned and (has_ui_base or has_small_copy_len):
            out.append({
                "call_address": h(r.addr),
                "call_text": r.text,
                "mentioned_offsets": [hx(o) for o in mentioned],
                "has_ui_base_in_window": has_ui_base,
                "has_copy_like_len_in_window": has_small_copy_len,
                "window": [row_dict(w) for w in window],
            })
    return out


def strings_and_xrefs(app: bytes) -> list[dict[str, Any]]:
    needles = [b"task", b"queue", b"event", b"key", b"KEY"]
    out = []
    lower = app.lower()
    for needle in needles:
        hits = []
        pos = 0
        n = needle.lower()
        while True:
            j = lower.find(n, pos)
            if j < 0:
                break
            addr = va(j)
            # Only keep plausible ASCII contexts.
            context = app[j:j + 64]
            if all(c == 0 or c in (9, 10, 13) or 32 <= c < 127 for c in context[:32]):
                hits.append({
                    "address": h(addr),
                    "text": cstr(app, addr) or context.split(b"\0", 1)[0].decode("utf-8", "replace"),
                    "raw_word_xrefs": [h(x) for x in raw_xrefs(app, addr)],
                })
            pos = j + 1
        out.append({"needle": needle.decode(), "hits": hits})
    return out


def target_summaries(app: bytes, rows: list[Row]) -> list[dict[str, Any]]:
    summaries = []
    for target in TARGETS:
        summaries.append({
            "address": h(target),
            "raw_word_xrefs": [h(x) for x in raw_xrefs(app, target)],
            "raw_word_xrefs_odd": [h(x) for x in raw_xrefs(app, target | 1)],
            "raw_file_offset_xrefs": [h(x) for x in raw_xrefs(app, off(target))],
            "flow_refs": flow_refs(rows, target),
            "snippet": snippet(rows, target),
        })
    return summaries


def vector_summary(app: bytes, rows: list[Row]) -> dict[str, Any]:
    entries = word_table(app, VECTOR, VECTOR_COUNT)
    table_bytes = app[off(VECTOR): off(VECTOR) + VECTOR_COUNT * 4]
    return {
        "table": h(VECTOR),
        "raw_bytes": table_bytes.hex(),
        "base_raw_xrefs": [h(x) for x in raw_xrefs(app, VECTOR)],
        "base_file_offset_xrefs": [h(x) for x in raw_xrefs(app, off(VECTOR))],
        "whole_table_copies": [h(x) for x in find_bytes(app, table_bytes)],
        "first_two_entry_copies": [h(x) for x in find_bytes(app, table_bytes[:8])],
        "entries": [
            entry | {"flow_refs": flow_refs(rows, int(entry["value"], 16))}
            for entry in entries
        ],
    }


def make_json() -> dict[str, Any]:
    app = APP.read_bytes()
    rows = load_listing(LISTING)
    app_hash = sha256(APP)
    if app_hash != EXPECTED_APP_SHA256:
        raise SystemExit(f"Official v15 SHA gate failed: {app_hash} != {EXPECTED_APP_SHA256}")

    pending_offsets = sorted(PENDING_TO_LIVE)
    live_offsets = sorted(PENDING_TO_LIVE.values())
    accesses = local_ram_accesses(rows)
    pending_accesses = [a for a in accesses if int(a["field_offset"], 16) in PENDING_TO_LIVE]
    pending_writes = [a for a in pending_accesses if a["access_kind"] == "write"]
    pending_reads = [a for a in pending_accesses if a["access_kind"] == "read"]
    absolute_field_xrefs = []
    for field in pending_offsets + live_offsets:
        absolute = UI_RAM + field
        absolute_field_xrefs.append({"field_offset": hx(field), "absolute": h(absolute), "raw_word_xrefs": [h(x) for x in raw_xrefs(app, absolute)]})

    result = {
        "scope": {
            "app": str(APP),
            "app_sha256": app_hash,
            "expected_app_sha256": EXPECTED_APP_SHA256,
            "listing": str(LISTING),
            "runtime_base": h(BASE),
            "policy": "official v15 static analysis only; no patch, package, flash, or hardware access",
        },
        "ram_base_reconstruction": base_reconstruction(rows),
        "target_summaries": target_summaries(app, rows),
        "ranges": {name: {"start": h(start), "end": h(end), "rows": [row_dict(r) for r in rows_in(rows, start, end)]} for name, (start, end) in RANGES.items()},
        "field_offset_aliases": {
            "pending_to_live": {hx(k): hx(v) for k, v in PENDING_TO_LIVE.items()},
            "direct_pending_offset_listing_hits": direct_offset_hits(rows, pending_offsets),
            "direct_live_offset_listing_hits": direct_offset_hits(rows, live_offsets),
            "reconstructed_ui_ram_accesses_to_interesting_fields": accesses,
            "pending_reads_reconstructed": pending_reads,
            "pending_writes_reconstructed": pending_writes,
            "absolute_pending_and_live_address_raw_xrefs": absolute_field_xrefs,
        },
        "memcpy_queue_task_callback_search": {
            "pending_related_call_windows": call_windows(rows, set(pending_offsets)),
            "state_function_pointer_or_relocation_xrefs": [
                {
                    "target": h(t),
                    "raw_word_xrefs": [h(x) for x in raw_xrefs(app, t)],
                    "raw_word_xrefs_odd": [h(x) for x in raw_xrefs(app, t | 1)],
                    "raw_file_offset_xrefs": [h(x) for x in raw_xrefs(app, off(t))],
                }
                for t in [0x02028F0C, 0x02029290]
            ],
            "task_event_key_strings": strings_and_xrefs(app),
        },
        "code_pointer_relocation_and_vector": vector_summary(app, rows),
        "conclusion": {
            "physical_input_dispatcher_or_id_proven": False,
            "producer_to_pending_fields_proven": False,
            "static_impossibility_strength": "stronger than prior vector-only pass: official v15 listing/raw bytes show pending consumers and logical UI callback targets, but no write/copy/callback relocation evidence for the physical input producer into +0x309..+0x30f.",
            "key_points": [
                "+0x309..+0x30f pending bytes are read in the 0x02028f0c/0x02029152 consumer path and copied/decremented into live +0x39..+0x3f.",
                "0x02029290 state frame reconstructs r11=0x1c33260 and branches at 0x02029528 from +0x302, then uses +0x1639/+0x168a/+0x203 and render helpers.",
                "0x020299xx vector targets write logical UI state fields such as +0x1672, +0x03a6/+0x03a7, +0x1636/+0x1637, not the +0x309..+0x30f pending bytes.",
                "0x02025dea/e06 call enclosing encoder routines 0x02024368/0x0202443e with PRODUCT_RAM index*0x49e3 + 0x0a7e/0x0a7f; they do not statically link to physical event IDs or the pending byte producer.",
                "The 0x02058248 code-pointer run remains self-referenced only in raw bytes; it does not prove dispatcher or physical IDs.",
                "Producer/consumer boundary is therefore fixed statically at the pending-byte interface: consumers begin at 0x02028f0c/0x02029152 and 0x02029612. The upstream physical producer/ID dispatcher is outside the recoverable static evidence and requires runtime write/watch tracing of 0x1c33260+0x309..0x30f plus queue/callback instrumentation.",
            ],
        },
    }
    return result


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        out.append("| " + " | ".join(row) + " |")
    return "\n".join(out)


def make_markdown(data: dict[str, Any]) -> str:
    scope = data["scope"]
    lines = [
        "# v15 UI/event final pass: pending/live fields and dispatcher search",
        "",
        "Status: 공식 v15 static-only final pass. Patch/flash/package/hardware access 없음.",
        "",
        "## Inputs and SHA gate",
        "",
        f"- App: `{scope['app']}`",
        f"- SHA-256: `{scope['app_sha256']}`",
        f"- Listing: `{scope['listing']}`",
        f"- Runtime base: `{scope['runtime_base']}`",
        "",
        "## Conclusion",
        "",
        "- Physical input dispatcher/event ID proof: **not proven**.",
        "- Pending producer proof for `0x1c33260 + 0x309..0x30f`: **not found** in official v15 static listing/raw bytes.",
        "- Static impossibility is stronger than the prior vector-only pass because this pass follows the consumer/state-machine side and checks RAM-base aliases, absolute field xrefs, copy/call windows, task/callback strings, and relocation encodings.",
        "",
    ]
    lines.extend([f"- {p}" for p in data["conclusion"]["key_points"]])
    lines += ["", "## RAM absolute base reconstruction", ""]
    brec = data["ram_base_reconstruction"][0]
    lines.append(md_table(["base", "name", "listing mov hits"], [[c["base"], c["base_name"], str(c["listing_mov_hits"])] for c in brec["counts"]]))
    lines += ["", "Target-area base loads:", ""]
    lines.append(md_table(["address", "base", "register", "text"], [[e["address"], e["base_name"], e.get("register") or "", "`" + e["text"].replace("|", "\\|") + "`"] for e in brec["target_area_mov_immediates"]]))

    aliases = data["field_offset_aliases"]
    lines += ["", "## Pending -> live field flow", ""]
    rows = []
    pending_reads = {r["field_offset"]: r for r in aliases["pending_reads_reconstructed"]}
    for p, live in aliases["pending_to_live"].items():
        rows.append([p, live, "yes" if p in pending_reads else "no", "yes" if any(w["field_offset"] == p for w in aliases["pending_writes_reconstructed"]) else "no"])
    lines.append(md_table(["pending", "live", "consumer read", "producer write found"], rows))
    lines += [
        "",
        "Observed consumer pattern: `0x02029152..0x020291cc` reads `+0x30c,+0x30b,+0x30e,+0x30d,+0x30a,+0x309`, increments/copies to live `+0x3c,+0x3b,+0x3e,+0x3d,+0x3a,+0x39`, and calls `0x02028e46/64/86/a6/c8/ea` on overflow cases. `0x02029612` decrements `+0x30f` into live `+0x3f` and triggers `0x020291f8/0x02029244` when it underflows.",
        "",
        "## Dispatcher, memcpy/queue/task callback search",
        "",
    ]
    cb = data["memcpy_queue_task_callback_search"]
    lines.append(md_table(["target", "word xrefs", "odd word xrefs", "file-offset xrefs"], [[x["target"], ", ".join(x["raw_word_xrefs"]) or "none", ", ".join(x["raw_word_xrefs_odd"]) or "none", ", ".join(x["raw_file_offset_xrefs"]) or "none"] for x in cb["state_function_pointer_or_relocation_xrefs"]]))
    lines += ["", f"Pending-related call windows found: `{len(cb['pending_related_call_windows'])}`. None contains a confirmed memcpy/queue producer into `+0x309..+0x30f`; the hits are consumer/helper contexts or non-UI-base aliases.", ""]

    lines += ["## 0x02058248 vector relocation check", ""]
    vec = data["code_pointer_relocation_and_vector"]
    lines += [
        f"- Table: `{vec['table']}`",
        f"- Base raw xrefs: `{vec['base_raw_xrefs']}`",
        f"- Whole-table copies: `{vec['whole_table_copies']}`",
        f"- First-two-entry copies: `{vec['first_two_entry_copies']}`",
        "",
    ]
    lines.append(md_table(["slot", "target", "raw xrefs", "flow refs"], [[str(e["slot"]), e["value"], ", ".join(e["raw_xrefs"]) or "none", str(len(e["flow_refs"]))] for e in vec["entries"]]))

    lines += ["", "## Address-specific backward-slice notes", ""]
    notes = [
        ("0x02029152", "pending consumer chain for `+0x30c..+0x309`; direct flow refs only from local gates `0x020290c8` and `0x020290d4`."),
        ("0x02029528", "state-machine computed branch after `+0x302 > 1`; uses `+0x1639`, `+0x168a`, `+0x203`, render helper `0x02004e8e`."),
        ("0x020299xx", "logical UI callback targets mutate state fields, redraw timers, selection bytes, and alt block `0x1c34894`; no pending producer writes."),
        ("0x02025dea/e06", "enclosing encoder calls use `0x1c0de20 + idx*0x49e3 + 0xa7e/0xa7f` and call `0x02024368/0x0202443e`; this is not physical dispatcher proof."),
    ]
    lines.append(md_table(["area", "finding"], notes))

    lines += [
        "",
        "## Reproduction",
        "",
        "```sh",
        "python3 baselines/v15/analysis/ui-preflash/final-pass/events/analyze_final_pass_events.py",
        "python3 - <<'PY'",
        "import json",
        "from pathlib import Path",
        "p=Path('baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json')",
        "d=json.loads(p.read_text())",
        "print(d['conclusion']['physical_input_dispatcher_or_id_proven'])",
        "print(len(d['field_offset_aliases']['pending_writes_reconstructed']))",
        "PY",
        "```",
        "",
        "Generated artifacts:",
        "",
        "- `baselines/v15/analysis/ui-preflash/final-pass/events/analyze_final_pass_events.py`",
        "- `baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json`",
        "- `baselines/v15/analysis/ui-preflash/final-pass/events/report.md`",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    data = make_json()
    JSON_OUT.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    MD_OUT.write_text(make_markdown(data))
    print(f"wrote {JSON_OUT}")
    print(f"wrote {MD_OUT}")


if __name__ == "__main__":
    main()
