#!/usr/bin/env python3
"""Exact v15/S1C5 audit for exhaustive-listing gap 0x02039be6..0x02039e2a.

Offline-only evidence generator. It reads existing binaries/listings and emits no
firmware, FWSC, OTA sender, rollback, or device-access path.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = 0x02000000
APP_FLASH_DATA_START = 0x4120
GAP_START = 0x02039BE6
GAP_END = 0x02039E2A
TBH_ADDR = 0x020399A2
TBH_TABLE_BASE = 0x020399A4
TBH_ENTRY_COUNT = 7
PRE_EXHAUSTIVE_GOTO = 0x02039BE4
S1C5_SELECTOR_START = 0x0201E13E
S1C5_SELECTOR_END = 0x0201E196
S1C5_PRODUCER_START = 0x0201E196
S1C5_PRODUCER_END = 0x0201E252
S1C5_OWNED_END = 0x0201E254
POST_STORAGE_CALLSITE = 0x02005FA4
POST_STORAGE_CALLEE = 0x020057E0
FIRST_NOTE_HOOKS = [0x0201C63E, 0x0201C67C]

S1C5_DIR = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return"
INPUTS = {
    "s1c5_app": (S1C5_DIR / "app.bin", "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189"),
    "s1c5_manifest": (S1C5_DIR / "app-manifest.json", "e5c66d6e93e30904c61a4bcb22ae4ec4639a3f60381da99f3fc801a1aba03f34"),
    "s1c5_package_manifest": (S1C5_DIR / "package-manifest.json", "a07fe8fbeead59fbc56190d5570af16060b036e349c2991c99e03c97f9afa746"),
    "quark_exhaustive": (ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz", "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"),
    "quark_recursive": (ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz", "c1d2f3f1369720c3d934acb468d6ddb79b4f0d9c65af5b9583225df610c253a9"),
    "kagaimiq_exhaustive": (ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz", "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013"),
    "sdk_report": (ROOT / "baselines/v15/analysis/sdk-signatures/report.json", "e9f02dfe9ba1987353df14c82b18b321f960960fcd66d987db183fe71b0f75fe"),
    "factory_loader_report": (ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/report.md", "1cd72971bf4db3bdf1dcdf113d5c795e0bb54f27af735b4ecda1319ef6b90d0d"),
}
EXPECTED = {
    "gap_sha256": "a1825cf3261b2ce8fd20f820bcd4a843b36e2f290b97be1e0e078b652efe5bfe",
    "selector_sha256": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "producer_sha256": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "combined_sha256": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "pre_exhaustive_goto_bytes": "0584",
    "tbh_bytes": "1101",
    "post_storage_call_bytes": "bfea1cfc",
}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hx(v: int) -> str:
    return f"0x{v:08x}"


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def off(addr: int) -> int:
    return addr - BASE


def hexdump(data: bytes, start: int) -> list[str]:
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{start + i:08x}  {chunk.hex(' '):<47}  {asc}")
    return out


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum((data.count(b) / len(data)) * math.log2(data.count(b) / len(data)) for b in set(data))


def load_rows(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def rows_in(rows: list[dict[str, str]], start: int, end: int) -> list[dict[str, str]]:
    out = []
    for row in rows:
        try:
            a = int(row["address"], 16)
        except Exception:
            continue
        if start <= a < end:
            out.append(row)
    return out


def compact_row(row: dict[str, str]) -> dict[str, Any]:
    return {
        "address": "0x" + row.get("address", ""),
        "bytes": row.get("bytes", ""),
        "length": int(row.get("length", "0") or 0),
        "mnemonic": row.get("mnemonic", ""),
        "text": row.get("text", ""),
        "flow_type": row.get("flow_type", ""),
        "function": row.get("function", ""),
    }


def row_at(rows: list[dict[str, str]], addr: int) -> dict[str, str]:
    want = f"{addr:08x}"
    for row in rows:
        if row.get("address", "").lower() == want:
            return row
    raise SystemExit(f"FAIL: missing row {hx(addr)}")


def text_targets(row: dict[str, str]) -> list[int]:
    return [int(x, 16) for x in re.findall(r"0x020[0-9a-fA-F]{5}", row.get("text", ""))]


def xrefs_to_range(rows: list[dict[str, str]], start: int, end: int) -> list[dict[str, Any]]:
    out = []
    for row in rows:
        for target in text_targets(row):
            if start <= target < end:
                item = compact_row(row)
                item["target"] = hx(target)
                out.append(item)
    return out


def pointer_hits(blob: bytes, scan_start: int, scan_end: int, target_start: int, target_end: int) -> list[dict[str, Any]]:
    hits = []
    for o in range(off(scan_start), off(scan_end) - 3, 2):
        v = int.from_bytes(blob[o:o + 4], "little")
        if target_start <= v < target_end:
            hits.append({"source": hx(BASE + o), "value": hx(v), "alignment": (BASE + o) & 3})
    return hits


def internal_pointer_like_words(data: bytes, start: int) -> list[dict[str, Any]]:
    ranges = [
        ("app_runtime", BASE, BASE + 617012),
        ("hot_ram", 0x01C00000, 0x01D00000),
        ("flash_mapped_or_mmio", 0x00000000, 0x01000000),
    ]
    hits = []
    for i in range(0, len(data) - 3, 2):
        v = int.from_bytes(data[i:i + 4], "little")
        for name, lo, hi in ranges:
            if lo <= v < hi and (name != "flash_mapped_or_mmio" or v >= 0x1000):
                hits.append({"offset_in_gap": i, "source": hx(start + i), "value": hx(v), "range": name})
                break
    return hits


def ascii_runs(data: bytes, start: int) -> list[dict[str, Any]]:
    out = []
    cur = bytearray()
    start_idx = None
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if start_idx is None:
                start_idx = i
            cur.append(b)
        else:
            if len(cur) >= 4:
                out.append({"offset": start_idx, "address": hx(start + start_idx), "text": cur.decode("ascii", "replace")})
            cur = bytearray(); start_idx = None
    if len(cur) >= 4:
        out.append({"offset": start_idx, "address": hx(start + start_idx), "text": cur.decode("ascii", "replace")})
    return out


def sdk_matches_near(report: dict[str, Any], start: int, end: int) -> dict[str, Any]:
    exact = report.get("sdk_elf_exact", {}).get("all_matches", [])
    overlaps = []
    nearest_before = None
    nearest_after = None
    for m in exact:
        a = int(m["app_address"])
        e = a + int(m["size"])
        item = {"name": m["name"], "start": hx(a), "end_exclusive": hx(e), "bytes": m["size"], "sha256": m.get("body_sha256")}
        if a < end and e > start:
            overlaps.append(item)
        if e <= start:
            dist = start - e
            if nearest_before is None or dist < nearest_before["distance_bytes"]:
                nearest_before = {**item, "distance_bytes": dist}
        if a >= end:
            dist = a - end
            if nearest_after is None or dist < nearest_after["distance_bytes"]:
                nearest_after = {**item, "distance_bytes": dist}
    return {
        "policy": report.get("policy"),
        "overlapping_exact_sdk_matches": overlaps,
        "nearest_exact_sdk_match_before": nearest_before,
        "nearest_exact_sdk_match_after": nearest_after,
        "decision": "No public SDK exact match owns or names the gap; SDK evidence neither promotes nor frees it.",
    }


def byte_coverage(rows: list[dict[str, str]], start: int, end: int) -> dict[str, Any]:
    covered = set()
    overlaps = []
    for row in rows:
        try:
            a = int(row["address"], 16)
            n = int(row.get("length", "0") or 0)
        except Exception:
            continue
        if a < end and a + n > start:
            overlaps.append(compact_row(row))
            for x in range(max(a, start), min(a + n, end)):
                covered.add(x)
    return {"covered_bytes": len(covered), "total_bytes": end - start, "uncovered_byte_count": (end - start) - len(covered), "overlap_rows": overlaps}


def tbh_evidence(app: bytes, qs: list[dict[str, str]], qr: list[dict[str, str]]) -> dict[str, Any]:
    instr = row_at(qr, TBH_ADDR)
    req(instr["bytes"] == EXPECTED["tbh_bytes"], "recursive TBH bytes")
    entries = []
    for idx in range(TBH_ENTRY_COUNT):
        o = off(TBH_TABLE_BASE) + idx * 2
        value = int.from_bytes(app[o:o + 2], "little")
        target = TBH_TABLE_BASE + value * 2
        entries.append({"index": idx, "entry_halfword": f"0x{value:04x}", "target": hx(target), "inside_requested_gap": GAP_START <= target < GAP_END})
    req(any(e["target"] == hx(GAP_START) for e in entries), "TBH table targets gap start")
    return {
        "instruction_recursive": compact_row(instr),
        "table_base": hx(TBH_TABLE_BASE),
        "entry_formula": "target = table_base + little_endian_halfword * 2",
        "entries": entries,
        "classification": "Positive branch-reach evidence: entry 3 resolves exactly to requested gap start 0x02039be6, so the region is a switch arm, not owned/free storage.",
    }


def helper_return_evidence(qr: list[dict[str, str]], call_rows: list[dict[str, str]]) -> dict[str, Any]:
    call_targets = []
    for row in call_rows:
        if "call" not in row.get("mnemonic", ""):
            continue
        for target in text_targets(row):
            call_targets.append(target)
    out = []
    for target in sorted(set(call_targets)):
        rows = rows_in(qr, target, target + 0x100)
        terms = []
        for row in rows[:80]:
            if row.get("mnemonic") in {"pop", "rts"} or row.get("flow_type") == "TERMINATOR" or "pc" in row.get("text", ""):
                terms.append(compact_row(row))
        out.append({"callee": hx(target), "terminators_first_100h": terms[:10]})
    return {"called_helpers": out, "classification": "Called helper terminators show ordinary returning helper shapes; any restore overwrite would also destroy live call/fall-through switch arms."}


def build_evidence() -> dict[str, Any]:
    gates = {}
    for name, (path, expected) in INPUTS.items():
        actual = shaf(path)
        req(actual == expected, f"input hash {name}")
        gates[name] = {"path": rel(path), "sha256": actual, "status": "PASS"}

    app = INPUTS["s1c5_app"][0].read_bytes()
    gap = app[off(GAP_START):off(GAP_END)]
    req(len(gap) == 580, "gap length 580")
    req(sha(gap) == EXPECTED["gap_sha256"], "gap sha256")
    req(sha(app[off(S1C5_SELECTOR_START):off(S1C5_SELECTOR_END)]) == EXPECTED["selector_sha256"], "selector hash")
    req(sha(app[off(S1C5_PRODUCER_START):off(S1C5_PRODUCER_END)]) == EXPECTED["producer_sha256"], "producer hash")
    req(sha(app[off(S1C5_SELECTOR_START):off(S1C5_OWNED_END)]) == EXPECTED["combined_sha256"], "selector/producer combined hash")

    qs = load_rows(INPUTS["quark_exhaustive"][0])
    qr = load_rows(INPUTS["quark_recursive"][0])
    kg = load_rows(INPUTS["kagaimiq_exhaustive"][0])
    sdk_report = json.loads(INPUTS["sdk_report"][0].read_text())

    pre_goto = row_at(qs, PRE_EXHAUSTIVE_GOTO)
    req(pre_goto["bytes"] == EXPECTED["pre_exhaustive_goto_bytes"], "pre-exhaustive goto bytes")
    post_storage = row_at(qs, POST_STORAGE_CALLSITE)
    req(post_storage["bytes"] == EXPECTED["post_storage_call_bytes"], "post-storage call bytes")

    q_gap_rows = [compact_row(r) for r in rows_in(qs, GAP_START, GAP_END)]
    qr_gap_raw = rows_in(qr, GAP_START, GAP_END)
    qr_gap_rows = [compact_row(r) for r in qr_gap_raw]
    kg_gap_rows = [compact_row(r) for r in rows_in(kg, GAP_START, GAP_END)]
    req(len(q_gap_rows) == 0, "quark exhaustive gap source")
    req(len(qr_gap_rows) >= 180, "recursive decode rows inside gap")
    req(len(kg_gap_rows) >= 130, "Kagaimiq decode rows inside gap")

    q_context_before = [compact_row(r) for r in rows_in(qs, GAP_START - 0x90, GAP_START)][-24:]
    q_context_after = [compact_row(r) for r in rows_in(qs, GAP_END, GAP_END + 0x90)][:24]
    qr_context_before = [compact_row(r) for r in rows_in(qr, GAP_START - 0x260, GAP_START)][-40:]
    qr_context_after = [compact_row(r) for r in rows_in(qr, GAP_END, GAP_END + 0x90)][:24]

    q_xrefs = xrefs_to_range(qs, GAP_START, GAP_END)
    qr_xrefs = xrefs_to_range(qr, GAP_START, GAP_END)
    kg_xrefs = xrefs_to_range(kg, GAP_START, GAP_END)
    app_to_gap_ptrs = pointer_hits(app, BASE, BASE + len(app), GAP_START, GAP_END)
    req(len(qr_xrefs) >= 20, "recursive direct xrefs into gap")
    req(len(app_to_gap_ptrs) == 0, "raw pointer xref count stable")

    data_sig = {
        "sha256": sha(gap),
        "bytes": len(gap),
        "zero_bytes": gap.count(0),
        "ff_bytes": gap.count(0xFF),
        "unique_byte_values": len(set(gap)),
        "shannon_entropy_bits_per_byte": round(entropy(gap), 4),
        "printable_ascii_bytes": sum(32 <= b < 127 for b in gap),
        "printable_ascii_runs_len_ge_4": ascii_runs(gap, GAP_START),
        "internal_pointer_like_words": internal_pointer_like_words(gap, GAP_START),
        "assessment": "dense non-erased bytes with branch/call/store forms; not 00/ff padding and not a resource signature proving free space",
    }

    tbh = tbh_evidence(app, qs, qr)
    returns = helper_return_evidence(qr, qr_gap_raw)
    recursive_coverage = byte_coverage(qr, GAP_START, GAP_END)
    kagaimiq_coverage = byte_coverage(kg, GAP_START, GAP_END)

    lifecycle = {
        "post_storage_0x02005fa4": {
            "site": hx(POST_STORAGE_CALLSITE),
            "listing": compact_row(post_storage),
            "callee": hx(POST_STORAGE_CALLEE),
            "stock_lifecycle": "after stock storage reads/loader in the same boot initializer; factory-loader evidence says only this path and UI bank/preset path call 0x020057e0 immediately after loader",
            "wrapper_requirement": "a hook must call 0x020057e0 exactly, preserve its argument/return ABI and caller frame, then return to 0x02005fa8",
            "gap_use_result": "REFUTED because the proposed 580-byte body range is live switch-arm/control-flow code, not owned placement",
            "safety_result": "still BLOCK without separate live post-USB proof; no device access was used here",
        },
        "first_note_lazy_path": {
            "existing_hooks": [hx(x) for x in FIRST_NOTE_HOOKS],
            "selector_producer_window": f"{hx(S1C5_SELECTOR_START)}..{hx(S1C5_OWNED_END)}",
            "selector_producer_sha256": EXPECTED["combined_sha256"],
            "preservation": "exact S1C5 selector/producer bytes are retained; inserting restore code there would violate the requested baseline",
            "minimum_safe_contract": "RAM-only, no loader/storage/UI mutation in the note event, preserve Note On velocity, reload 0x9c length after calls, publish each slot valid last and ARMED last",
            "gap_use_result": "no approved code placement after refuting 0x02039be6..0x02039e2a; lifecycle remains design-only",
        },
    }

    ownership = {
        "decision": "REFUTED_FOR_PROMOTION",
        "reason": "The apparent hole is only a Quarkslab exhaustive-listing gap after 0x02039be4 jumps to 0x02039fee in a neighboring decode. Quarkslab recursive decodes 186 rows inside the requested range, recursive direct branches enter it, and the 0x020399a2 TBH branch table entry 3 resolves exactly to 0x02039be6. That is positive executable branch-reach evidence and negative ownership/free evidence.",
        "pre_gap_exhaustive_row": compact_row(pre_goto),
        "branch_table_reach": tbh,
        "recursive_helper_return_evidence": returns,
        "quarkslab_gap_rows_inside": len(q_gap_rows),
        "quarkslab_recursive_gap_rows_inside": len(qr_gap_rows),
        "kagaimiq_patched_gap_rows_inside": len(kg_gap_rows),
        "recursive_byte_coverage": recursive_coverage,
        "kagaimiq_byte_coverage": kagaimiq_coverage,
        "quarkslab_recursive_first_50_gap_rows": qr_gap_rows[:50],
        "quarkslab_recursive_last_50_gap_rows": qr_gap_rows[-50:],
        "kagaimiq_patched_first_40_gap_rows": kg_gap_rows[:40],
        "direct_text_xrefs_into_gap": {
            "quarkslab_exhaustive": q_xrefs,
            "quarkslab_recursive": qr_xrefs,
            "kagaimiq_patched_exhaustive": kg_xrefs,
            "classification": "Recursive xrefs include external conditional/unconditional branches from 0x020399c6, 0x020399d0, 0x02039a4e, and internal branches/calls. Kagaimiq independently finds internal branches/calls. Quarkslab exhaustive has no trusted direct xref only because its linear path follows the 0x02039be4 jump over the switch arms.",
        },
        "raw_pointer_xrefs_into_gap": {
            "count": len(app_to_gap_ptrs),
            "hits_first_50": app_to_gap_ptrs[:50],
            "classification": "little-endian pointer scan is heuristic; exact branch-table halfwords and branch encodings are not raw 32-bit pointers",
        },
    }

    runtime_map = {
        "runtime_base": hx(BASE),
        "gap_runtime_range": f"{hx(GAP_START)}..{hx(GAP_END)}",
        "gap_app_offset_range": f"0x{off(GAP_START):05x}..0x{off(GAP_END):05x}",
        "gap_fwsc_app_data_flash_offset_range": f"0x{APP_FLASH_DATA_START + off(GAP_START):05x}..0x{APP_FLASH_DATA_START + off(GAP_END):05x}",
        "package_manifest_layout": {"app_data_start": "0x04120", "app_area_start": "0x04000", "app_data_size": 617012},
        "nearby_function_boundary_evidence": {
            "quarkslab_exhaustive_before_gap_tail": q_context_before,
            "quarkslab_exhaustive_after_gap_head": q_context_after,
            "quarkslab_recursive_before_gap_tail": qr_context_before,
            "quarkslab_recursive_after_gap_head": qr_context_after,
            "interpretation": "0x02039be6 is a TBH switch-arm target, not an allocation boundary. 0x02039e2a is where exhaustive listing resumes, not proof that the preceding 580 bytes are dead/free.",
        },
    }

    return {
        "format": "smk37-v15-s1c5-gap-02039be6-audit-v1",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "fwsc_emitted": False},
        "basis": gates,
        "exact_s1c5_identity": {
            "selector": {"range": f"{hx(S1C5_SELECTOR_START)}..{hx(S1C5_SELECTOR_END)}", "sha256": EXPECTED["selector_sha256"]},
            "producer": {"range": f"{hx(S1C5_PRODUCER_START)}..{hx(S1C5_PRODUCER_END)}", "sha256": EXPECTED["producer_sha256"]},
            "combined_selector_producer_tail": {"range": f"{hx(S1C5_SELECTOR_START)}..{hx(S1C5_OWNED_END)}", "sha256": EXPECTED["combined_sha256"], "preserved": True},
        },
        "runtime_address_map": runtime_map,
        "target_gap_bytes": {"range": f"{hx(GAP_START)}..{hx(GAP_END)}", "bytes": len(gap), "sha256": sha(gap), "hex": gap.hex(), "hexdump": hexdump(gap, GAP_START)},
        "data_signatures": data_sig,
        "decode_evidence": {
            "quarkslab_exhaustive_gap_rows": q_gap_rows,
            "quarkslab_recursive_gap_row_count": len(qr_gap_rows),
            "quarkslab_recursive_gap_rows": qr_gap_rows,
            "kagaimiq_patched_gap_row_count": len(kg_gap_rows),
            "kagaimiq_patched_gap_rows": kg_gap_rows,
        },
        "sdk_exact_matches": sdk_matches_near(sdk_report, GAP_START, GAP_END),
        "ownership_and_executability": ownership,
        "lifecycle_audit": lifecycle,
        "decision": {
            "result": "REFUTE_PROMOTION",
            "promoted": False,
            "minimal_manifest_restore_body_assembled": False,
            "reason": "No manifest-gated restore body is assembled because the requested 580-byte region is executable switch-arm/control-flow code with direct branch-table reach and recursive branches; overwriting it would corrupt stock/S1C5 behavior while exact S1C5 selector/producer must remain preserved.",
        },
    }


def render_report(ev: dict[str, Any]) -> str:
    gap = ev["target_gap_bytes"]
    own = ev["ownership_and_executability"]
    sdk = ev["sdk_exact_matches"]
    data = ev["data_signatures"]
    tbh = own["branch_table_reach"]
    kg_xrefs = own["direct_text_xrefs_into_gap"]["kagaimiq_patched_exhaustive"]
    qr_xrefs = own["direct_text_xrefs_into_gap"]["quarkslab_recursive"]
    return f"""# v15/S1C5 gap 0x02039be6 audit: REFUTED

## Decision

**REFUTE PROMOTION.** The exact `{gap['range']}` region is 580 bytes (`{gap['sha256']}`), but it is not owned/free. The Quarkslab exhaustive gap is bypassed by `0x02039be4: goto 0x02039fee`, yet Quarkslab recursive decodes `{own['quarkslab_recursive_gap_rows_inside']}` rows inside the same range and the `0x020399a2` TBH table has entry 3 resolving exactly to `0x02039be6`. No firmware/FWSC/OTA/device artifact was emitted.

## Exact bytes and signatures

- Runtime range: `{ev['runtime_address_map']['gap_runtime_range']}`
- App offsets: `{ev['runtime_address_map']['gap_app_offset_range']}`
- FWSC app-data flash offsets: `{ev['runtime_address_map']['gap_fwsc_app_data_flash_offset_range']}`
- Byte profile: `{data['zero_bytes']}` zero bytes, `{data['ff_bytes']}` `ff` bytes, `{data['unique_byte_values']}` unique byte values, entropy `{data['shannon_entropy_bits_per_byte']}` bits/byte.
- ASCII runs >=4: `{data['printable_ascii_runs_len_ge_4']}`
- Pointer-like words inside gap: `{len(data['internal_pointer_like_words'])}` heuristic hits; first five `{data['internal_pointer_like_words'][:5]}`.

The full byte string is in `evidence.json`; the reproducible `gap-02039be6.bin` and `gap-02039be6.hex` artifacts are emitted beside this report.

## Decode, xrefs, branch reach, and boundaries

- Quarkslab exhaustive rows inside target: `{own['quarkslab_gap_rows_inside']}`. This is the source of the apparent hole.
- Quarkslab recursive rows inside target: `{own['quarkslab_recursive_gap_rows_inside']}` with `{own['recursive_byte_coverage']['covered_bytes']}/{own['recursive_byte_coverage']['total_bytes']}` target bytes covered by overlapping rows.
- Kagaimiq patched exhaustive rows inside target: `{own['kagaimiq_patched_gap_rows_inside']}` with `{own['kagaimiq_byte_coverage']['covered_bytes']}/{own['kagaimiq_byte_coverage']['total_bytes']}` target bytes covered by overlapping rows.
- Quarkslab exhaustive trusted direct text xrefs into target: `{len(own['direct_text_xrefs_into_gap']['quarkslab_exhaustive'])}`.
- Quarkslab recursive text xrefs into target: `{len(qr_xrefs)}`. First five `{qr_xrefs[:5]}`.
- Kagaimiq patched text xrefs into target: `{len(kg_xrefs)}`. First five `{kg_xrefs[:5]}`.
- Raw little-endian pointer hits to target in app: `{own['raw_pointer_xrefs_into_gap']['count']}`.

Exhaustive-listing boundary before gap:

```text
{own['pre_gap_exhaustive_row']['address']} {own['pre_gap_exhaustive_row']['bytes']} {own['pre_gap_exhaustive_row']['text']} {own['pre_gap_exhaustive_row']['flow_type']}
```

TBH branch-table reach:

```text
{tbh['instruction_recursive']['address']} {tbh['instruction_recursive']['bytes']} {tbh['instruction_recursive']['text']} {tbh['instruction_recursive']['flow_type']}
entries: {tbh['entries']}
```

`0x02039be6` is therefore a switch-arm target, not an allocation boundary. `0x02039e2a` is where exhaustive listing resumes, not proof that the preceding 580 bytes are dead/free.

## Public SDK exact matches

Overlapping SDK exact matches: `{sdk['overlapping_exact_sdk_matches']}`. Nearest exact SDK matches are `{sdk['nearest_exact_sdk_match_before']}` and `{sdk['nearest_exact_sdk_match_after']}`. Result: {sdk['decision']}

## Lifecycle audit

- `0x02005fa4` remains a blocked post-storage wrapper point for this body. It must preserve and call stock `0x020057e0`, then return to `0x02005fa8`, but the proposed body placement is live switch-arm code and the path still lacks post-USB/live safety proof.
- First-note lazy restore remains design-only. Exact S1C5 selector/producer `{ev['exact_s1c5_identity']['combined_selector_producer_tail']['range']}` is preserved with SHA-256 `{ev['exact_s1c5_identity']['combined_selector_producer_tail']['sha256']}`; no insertion point is approved without changing that producer/selector.
- Helper calls inside the candidate range have ordinary terminators/returns recorded in `evidence.json`, so treating call-containing arms as disposable restore storage would corrupt normal continuation behavior.

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/gap-02039be6-audit/analyze_gap_02039be6.py --check
python3 baselines/v15/analysis/persistence-s2/gap-02039be6-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/gap-02039be6-audit && shasum -a 256 -c SHA256SUMS)
```
"""


def write_outputs(ev: dict[str, Any]) -> None:
    gap = bytes.fromhex(ev["target_gap_bytes"]["hex"])
    (HERE / "gap-02039be6.bin").write_bytes(gap)
    (HERE / "gap-02039be6.hex").write_text("\n".join(ev["target_gap_bytes"]["hexdump"]) + "\n", encoding="utf-8")
    (HERE / "evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(render_report(ev), encoding="utf-8")
    (HERE / "README.md").write_text("# Gap 0x02039be6 audit\n\nOffline refutation for v15/S1C5 exhaustive-listing gap 0x02039be6..0x02039e2a.\n\nRun `python3 analyze_gap_02039be6.py --check` and `python3 validate.py`.\n", encoding="utf-8")
    (HERE / "validation.txt").write_text(
        "PASS exact 580-byte gap bytes and S1C5 selector/producer hashes\n"
        "PASS TBH branch table at 0x020399a2 resolves entry 3 to 0x02039be6\n"
        "PASS Quarkslab recursive and Kagaimiq decode rows inside target\n"
        "REFUTE 0x02039be6..0x02039e2a as owned/free restore placement\n",
        encoding="utf-8",
    )
    names = ["README.md", "analyze_gap_02039be6.py", "evidence.json", "gap-02039be6.bin", "gap-02039be6.hex", "report.md", "validate.py", "validation.txt"]
    sums = [f"{shaf(HERE / n)}  {n}" for n in names]
    (HERE / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    ev = build_evidence()
    if args.check:
        req(ev["decision"]["result"] == "REFUTE_PROMOTION", "refute decision")
        req(ev["target_gap_bytes"]["bytes"] == 580, "580 bytes")
        req(any(e["target"] == hx(GAP_START) for e in ev["ownership_and_executability"]["branch_table_reach"]["entries"]), "TBH reaches target start")
        req(ev["ownership_and_executability"]["quarkslab_recursive_gap_rows_inside"] >= 180, "recursive decode rows")
        req(ev["ownership_and_executability"]["kagaimiq_patched_gap_rows_inside"] >= 130, "Kagaimiq decode rows")
        print("PASS gap 0x02039be6 exact audit checks")
        print("REFUTE promotion: branch-table/recursive decode proves live executable switch arms")
        return
    write_outputs(ev)
    print("gap 0x02039be6 audit outputs rebuilt; REFUTE promotion")


if __name__ == "__main__":
    main()
