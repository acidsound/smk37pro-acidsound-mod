#!/usr/bin/env python3
"""S1-C2 executable-placement audit for official v15, H2, and live-PASS S1-C1.

This script is intentionally read-only with respect to firmware artifacts. It
hash-gates the exact apps/packages/listings that already exist in the repository
and emits a BLOCK/PASS placement evidence package. It never creates an app, FWSC,
rollback, OTA payload, device command, reset command, or flash write.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import struct
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[5]
sys.path.insert(0, str(REPO / "tools"))

from build_v15_r01_hand_drum import call32, off  # noqa: E402
from build_v15_r03_fixed_prefix import short_call  # noqa: E402

RUNTIME_BASE = 0x02000000
SECTOR = 0x1000

PATHS = {
    "official_app": REPO / "build" / "v15-official-app.bin",
    "official_fwsc": REPO / "build" / "SMK-37_Pro_015.fwsc",
    "h2_app": REPO / "build" / "SMK37Pro-v15-H2-owned-source-corrected-fallback" / "app.bin",
    "h2_fwsc": REPO / "build" / "SMK37Pro-v15-H2-owned-source-corrected-fallback" / "SMK37Pro-v15-H2-owned-source-corrected-fallback.fwsc",
    "s1c1_app": REPO / "build" / "SMK37Pro-v15-S1C1-boundary-only" / "app.bin",
    "s1c1_fwsc": REPO / "build" / "SMK37Pro-v15-S1C1-boundary-only" / "SMK37Pro-v15-S1C1-boundary-only.fwsc",
    "h2_manifest": REPO / "baselines" / "v15" / "analysis" / "flash-candidates" / "H2-owned-source-corrected-fallback" / "app-manifest.json",
    "s1c1_manifest": REPO / "baselines" / "v15" / "analysis" / "flash-candidates" / "S1C1-boundary-only" / "app-manifest.json",
    "prior_s1c2_evidence": REPO / "baselines" / "v15" / "analysis" / "flash-candidates" / "S1C2-two-slot-selector" / "evidence.json",
    "prior_s1c2_report": REPO / "baselines" / "v15" / "analysis" / "flash-candidates" / "S1C2-two-slot-selector" / "report.md",
    "s1c1_code_evidence": REPO / "baselines" / "v15" / "analysis" / "patch-set-ui" / "s1c1" / "code" / "evidence.json",
    "s1c1_code_report": REPO / "baselines" / "v15" / "analysis" / "patch-set-ui" / "s1c1" / "code" / "report.md",
    "s1c1_ingress_evidence": REPO / "baselines" / "v15" / "analysis" / "patch-set-ui" / "s1c1" / "ingress" / "evidence.json",
    "s1c1_ingress_report": REPO / "baselines" / "v15" / "analysis" / "patch-set-ui" / "s1c1" / "ingress" / "report.md",
    "app_tail_evidence": REPO / "baselines" / "v15" / "analysis" / "r03-owned-ram" / "app-tail-placement" / "evidence.json",
    "app_tail_report": REPO / "baselines" / "v15" / "analysis" / "r03-owned-ram" / "app-tail-placement" / "report.md",
    "quarkslab_recursive_listing": REPO / "baselines" / "v15" / "analysis" / "quarkslab" / "results" / "quarkslab-recursive-listing.tsv.gz",
    "quarkslab_exhaustive_listing": REPO / "baselines" / "v15" / "analysis" / "quarkslab" / "results" / "quarkslab-exhaustive-listing.tsv.gz",
    "kagaimiq_exhaustive_listing": REPO / "baselines" / "v15" / "analysis" / "quarkslab" / "results" / "kagaimiq-patched-exhaustive-listing.tsv.gz",
    "quarkslab_comparison": REPO / "baselines" / "v15" / "analysis" / "quarkslab" / "results" / "comparison.md",
}

EXPECTED_HASHES = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "h2_app": "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    "h2_fwsc": "c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011",
    "s1c1_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "s1c1_fwsc": "ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d",
    "quarkslab_exhaustive_listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kagaimiq_exhaustive_listing": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

CANDIDATE_RANGES = {
    "residual_h2_packer_tail": (0x0201E1EC, 0x0201E254),
    "selector_internal_gap": (0x0201E19E, 0x0201E1A2),
    "unchanged_h2_producer": (0x0201E1A2, 0x0201E1EC),
    "official_completed_handler_entry": (0x0201E254, 0x0201E4A4),
    "completed_message_callsite_neighborhood": (0x0202D1D0, 0x0202D220),
    "app_area_tail_if_contiguous_runtime": (0x02096A34, 0x02096BB3),
}

WATCH_TARGETS = [
    "0x0201e13e", "0x0201e19e", "0x0201e1a2", "0x0201e1ec", "0x0201e254", "0x0202d202", "0x02096a34"
]

PRIVATE_PARSER_REQUIREMENTS = [
    "replace completed-message call at 0x0202d202 or equivalent with exact branch/call reach",
    "preserve original r0/r1 for non-private traffic and delegate unchanged to H2 0x0201e254",
    "check private prefix F0 7D 53 4D 4B 0F 01 before consuming traffic",
    "check exact total length and terminal F7 before command-specific body indexing",
    "enforce byte range <0x80 except F0/F7, TX 1..127, FLAGS==0, exact LEN field",
    "compute and compare packet CRC-16/CCITT-FALSE for each message",
    "compute and compare full-set CRC binding both 0x9c runtime payloads and both notes",
    "acquire/release H2 nonblocking lock and release it on every reject path",
    "copy slot0 and slot1 payloads, set valid bytes and ARMED state with csync/publication order",
    "reject duplicate/out-of-range notes, wrong state/TX, lock busy, and mutation after ARMED without slot mutation",
]


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(REPO))


def hx(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}x}"


def addr_to_offset(addr: int) -> int | None:
    offv = addr - RUNTIME_BASE
    if 0 <= offv < PATHS["official_app"].stat().st_size:
        return offv
    return None


def bytes_range(blob: bytes, start: int, end: int) -> str | None:
    start_off = addr_to_offset(start)
    end_off = addr_to_offset(end)
    if start_off is None or end_off is None:
        return None
    return blob[start_off:end_off].hex()


def read_listing_rows(path: Path, start: int | None = None, end: int | None = None, contains: list[str] | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        for row in reader:
            try:
                addr = int(row["address"], 16)
            except Exception:
                continue
            in_range = start is not None and end is not None and start <= addr < end
            has_text = contains is not None and any(token in row.get("text", "") for token in contains)
            if in_range or has_text:
                rows.append(row)
    return rows


def compact_row(row: dict[str, str]) -> dict[str, str]:
    return {key: row.get(key, "") for key in ("address", "bytes", "length", "mnemonic", "text", "flow_type", "function")}


def short_call_info(at: int, target: int) -> dict[str, Any]:
    try:
        enc = short_call(at, target).hex()
        return {"at": hx(at), "target": hx(target), "fits": True, "encoding": enc}
    except Exception as exc:
        return {"at": hx(at), "target": hx(target), "fits": False, "error": str(exc)}


def call32_info(at: int, target: int) -> dict[str, Any]:
    return {"at": hx(at), "target": hx(target), "fits": True, "encoding": call32(at, target).hex()}


def uniform_runs(blob: bytes, min_len: int = 32, limit: int = 20) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    i = 0
    while i < len(blob):
        j = i + 1
        while j < len(blob) and blob[j] == blob[i]:
            j += 1
        if j - i >= min_len and blob[i] in (0x00, 0xFF):
            runs.append({
                "runtime_start": hx(RUNTIME_BASE + i),
                "runtime_end_exclusive": hx(RUNTIME_BASE + j),
                "file_offset_start": i,
                "size": j - i,
                "byte": f"0x{blob[i]:02x}",
                "classification": "generic uniform run only; not executable ownership proof",
            })
        i = j
    runs.sort(key=lambda item: item["size"], reverse=True)
    return runs[:limit]


def sector_span_for_app_offsets(start_off: int, end_off: int) -> list[str]:
    # app.bin is stored at flash offset 0x04120 in the v15 JLFS app area.
    flash_start = 0x04120 + start_off
    flash_end = 0x04120 + end_off
    sectors: list[str] = []
    cur = (flash_start // SECTOR) * SECTOR
    while cur < flash_end:
        sectors.append(hx(cur, 5))
        cur += SECTOR
    return sectors


def make_evidence() -> dict[str, Any]:
    input_records = []
    checks: list[dict[str, Any]] = []
    for key, path in PATHS.items():
        record = {"id": key, "path": rel(path), "exists": path.exists()}
        if path.exists():
            record.update({"size": path.stat().st_size, "sha256": sha256_path(path)})
            if key in EXPECTED_HASHES:
                checks.append({
                    "check": f"input-hash-{key}",
                    "status": "PASS" if record["sha256"] == EXPECTED_HASHES[key] else "FAIL",
                    "detail": record["sha256"],
                    "expected": EXPECTED_HASHES[key],
                })
        else:
            checks.append({"check": f"input-exists-{key}", "status": "FAIL", "detail": rel(path)})
        input_records.append(record)

    official = PATHS["official_app"].read_bytes()
    h2 = PATHS["h2_app"].read_bytes()
    s1c1 = PATHS["s1c1_app"].read_bytes()
    h2_manifest = json.loads(PATHS["h2_manifest"].read_text(encoding="utf-8"))
    s1c1_manifest = json.loads(PATHS["s1c1_manifest"].read_text(encoding="utf-8"))
    s1c1_code = json.loads(PATHS["s1c1_code_evidence"].read_text(encoding="utf-8"))
    s1c1_ingress = json.loads(PATHS["s1c1_ingress_evidence"].read_text(encoding="utf-8"))
    prior_s1c2 = json.loads(PATHS["prior_s1c2_evidence"].read_text(encoding="utf-8"))
    app_tail = json.loads(PATHS["app_tail_evidence"].read_text(encoding="utf-8"))

    candidates: list[dict[str, Any]] = []
    for name, (start, end) in CANDIDATE_RANGES.items():
        start_off = addr_to_offset(start)
        end_off = addr_to_offset(end)
        item: dict[str, Any] = {
            "name": name,
            "range": f"{hx(start)}..{hx(end)}",
            "size": end - start,
            "inside_app_bin": start_off is not None and end_off is not None,
            "short_call_from_completed_message_0x0202d202": short_call_info(0x0202D202, start),
            "call32_from_completed_message_0x0202d202": call32_info(0x0202D202, start),
        }
        if start_off is not None and end_off is not None:
            item["file_offsets"] = [start_off, end_off]
            item["flash_sectors_if_changed"] = sector_span_for_app_offsets(start_off, end_off)
            item["official_sha256"] = hashlib.sha256(official[start_off:end_off]).hexdigest()
            item["h2_sha256"] = hashlib.sha256(h2[start_off:end_off]).hexdigest()
            item["s1c1_sha256"] = hashlib.sha256(s1c1[start_off:end_off]).hexdigest()
            item["h2_equals_s1c1"] = h2[start_off:end_off] == s1c1[start_off:end_off]
        if name == "residual_h2_packer_tail":
            item.update({
                "decision": "BLOCK_AS_S1C2_PARSER_PLACEMENT",
                "positive_facts": [
                    "inside the already audited 0x0201e13e..0x0201e254 stock-packer replacement body",
                    "after the exact H2 producer return at 0x0201e1ea and before official handler entry 0x0201e254",
                    "short-call reach from completed-message callsite is encodable",
                ],
                "blocking_facts": [
                    "only 104 contiguous bytes are available here",
                    "S1-C2 private parser has no exact assembled PI32 byte size",
                    "no evidence proves the complete prefix/length/CRC/state/copy/reject/delegation parser fits in 104 bytes",
                    "using this tail alone still requires a new 0x0202d202 ingress hook and exact H2 delegation proof",
                ],
            })
        elif name == "selector_internal_gap":
            item.update({
                "decision": "BLOCK",
                "blocking_facts": ["only 4 bytes", "not contiguous with residual tail because unchanged H2 producer occupies 0x0201e1a2..0x0201e1ec"],
            })
        elif name == "unchanged_h2_producer":
            item.update({
                "decision": "BLOCK",
                "blocking_facts": [
                    "exact H2/S1-C1 reachable behavior uses this producer from accepted Yamaha product packet callsites",
                    "overwriting it would remove H2 live-PASS producer behavior and violates preservation",
                ],
            })
        elif name == "official_completed_handler_entry":
            item.update({
                "decision": "BLOCK",
                "blocking_facts": [
                    "this is the official/H2 completed-message handler entry and body",
                    "direct callers at 0x0202d1fa and 0x0202d202 must continue to reach unchanged H2 behavior for non-private traffic",
                ],
            })
        elif name == "completed_message_callsite_neighborhood":
            item.update({
                "decision": "BLOCK",
                "blocking_facts": [
                    "0x0202d202 is only a 4-byte call slot inside reachable function FUN_0202d15a",
                    "adjacent 0x0202d206 store and subsequent control-flow remain reachable",
                    "cannot grow a parser in-place at the hook without deleting stock reachable instructions",
                ],
            })
        elif name == "app_area_tail_if_contiguous_runtime":
            item.update({
                "decision": "BLOCK",
                "blocking_facts": [
                    "not inside logical app.bin, so current application-only patcher cannot own it",
                    "prior JLFS evidence proves the 383-byte app-area tail is cfg_tool.bin, not free padding",
                    "overwriting it would remove a named official JLFS file without consumer/loading proof",
                ],
                "app_tail_prior_decision": app_tail.get("decisions", [{}])[0].get("decision") if isinstance(app_tail.get("decisions"), list) else "BLOCK",
            })
        candidates.append(item)

    listing_extracts: dict[str, Any] = {}
    for key in ("quarkslab_recursive_listing", "quarkslab_exhaustive_listing", "kagaimiq_exhaustive_listing"):
        path = PATHS[key]
        listing_extracts[key] = {
            "completed_message_callsite_rows": [compact_row(r) for r in read_listing_rows(path, 0x0202D1D0, 0x0202D220)],
            "stock_packer_and_handler_rows": [compact_row(r) for r in read_listing_rows(path, 0x0201E120, 0x0201E520)],
            "watch_target_text_hits": [compact_row(r) for r in read_listing_rows(path, contains=WATCH_TARGETS)],
        }

    # Known positive xrefs/calls that make overwriting unsafe.
    qx_hits = listing_extracts["quarkslab_exhaustive_listing"]["watch_target_text_hits"]
    positive_reachability = {
        "h2_product_calls_to_producer": [
            {"callsite": "0x0201e468", "h2_encoding": "bfea9bfe", "target": "0x0201e1a2"},
            {"callsite": "0x0201e49c", "h2_encoding": "bfea81fe", "target": "0x0201e1a2"},
        ],
        "official_calls_to_stock_packer": [compact_row(r) for r in qx_hits if r.get("text") == "call 0x0201e13e"],
        "completed_message_calls_to_handler": [compact_row(r) for r in qx_hits if r.get("text") == "call 0x0201e254"],
        "branch_to_completed_message_callsite": [compact_row(r) for r in qx_hits if "0x0202d202" in r.get("text", "")],
    }

    h2_layout = h2_manifest["layout"]
    s1c1_code_budget = s1c1_code["byte_budget"]
    ingress_code = s1c1_ingress["code"]

    checks.extend([
        {"check": "s1c1-is-h2-plus-boundary-only", "status": "PASS" if s1c1_manifest["invariants"]["h2_code_byte_identical"] else "FAIL", "detail": s1c1_manifest["invariants"]},
        {"check": "h2-producer-range", "status": "PASS" if h2_layout["producer"] == "0x0201e1a2" and h2_layout["producer_return"] == "0x0201e1ea" else "FAIL", "detail": h2_layout},
        {"check": "prior-s1c2-blocked-on-executable-placement", "status": "PASS" if prior_s1c2["decision"] == "BLOCK" else "FAIL", "detail": prior_s1c2.get("blockers")},
        {"check": "residual-tail-size-104", "status": "PASS" if CANDIDATE_RANGES["residual_h2_packer_tail"][1] - CANDIDATE_RANGES["residual_h2_packer_tail"][0] == 104 else "FAIL", "detail": CANDIDATE_RANGES["residual_h2_packer_tail"]},
        {"check": "no-second-owned-executable-region-prior", "status": "PASS" if not ingress_code["second_owned_executable_region"] else "FAIL", "detail": ingress_code},
        {"check": "app-tail-prior-block", "status": "PASS" if "cfg_tool.bin" in PATHS["app_tail_report"].read_text(encoding="utf-8") else "FAIL", "detail": "cfg_tool.bin occupies naive app tail"},
    ])

    pass_candidate = None
    for item in candidates:
        if item.get("decision") == "PASS_AS_S1C2_PARSER_PLACEMENT":
            pass_candidate = item
            break

    decision = "PASS" if pass_candidate else "BLOCK"
    block_reasons = []
    if decision == "BLOCK":
        block_reasons = [
            "No concrete executable range is proven to hold the S1-C2 private atomic parser/selector without removing exact S1-C1/H2 reachable behavior.",
            "The only residual executable tail with any ownership argument is 0x0201e1ec..0x0201e254, 104 contiguous bytes, and there is no exact assembled PI32 parser proving the required prefix/length/CRC/state/copy/reject/delegation logic fits there.",
            "The unchanged H2 producer at 0x0201e1a2..0x0201e1ec has positive callsite reach and cannot be overwritten.",
            "The completed-message handler and callsite neighborhood are reachable stock/H2 behavior, not free placement.",
            "The app-area tail is cfg_tool.bin per JLFS evidence, not executable padding ownership.",
            "Uniform zero/0xff runs in app.bin are generic data-cave candidates only and are expressly not ownership proof.",
        ]

    next_runtime_evidence = [
        "Only after an exact static parser is assembled and fits a proven range: authorize a no-mutation ingress smoke build that changes only the 0x0202d202 call target and the candidate range, delegates every non-private packet to H2 0x0201e254, and proves the live H2 Yamaha packet plus Ch1/Ch10 fallback still work with no reboot.",
        "If using residual tail 0x0201e1ec..0x0201e254, the smoke must prove execution enters that tail and returns/delegates correctly while the H2 producer at 0x0201e1a2..0x0201e1ec remains byte-for-byte unchanged.",
        "Only after the no-mutation ingress smoke passes should a mutating two-message parser be considered for live evidence.",
    ]

    evidence = {
        "format": "smk37-v15-s1c2-executable-placement-audit-v1",
        "scope": {
            "official_v15_only": True,
            "parents": ["official v15", "live-PASS H2", "live-PASS S1-C1 boundary-only"],
            "read_only_static_analysis": True,
            "firmware_candidate_created": False,
            "device_accessed": False,
            "flash_or_ota_or_reset": False,
            "generic_data_cave_promoted": False,
        },
        "decision": decision,
        "pass_candidate": pass_candidate,
        "block_reasons": block_reasons,
        "inputs": input_records,
        "validation_checks": checks,
        "s1c2_parser_requirements": PRIVATE_PARSER_REQUIREMENTS,
        "h2_layout": h2_layout,
        "s1c1_code_budget": s1c1_code_budget,
        "s1c1_ingress_code_budget": ingress_code,
        "candidates": candidates,
        "positive_reachability": positive_reachability,
        "listing_extracts": listing_extracts,
        "generic_uniform_runs_top20": uniform_runs(official),
        "branch_reach_examples": {
            "completed_call_to_residual_tail": short_call_info(0x0202D202, 0x0201E1EC),
            "completed_call_to_original_handler": short_call_info(0x0202D202, 0x0201E254),
            "completed_call_to_app_tail_candidate": short_call_info(0x0202D202, 0x02096A34),
            "residual_tail_call32_to_handler": call32_info(0x0201E1EC, 0x0201E254),
        },
        "smallest_next_runtime_evidence_if_authorized_later": next_runtime_evidence,
    }
    return evidence


def render_validation(evidence: dict[str, Any]) -> str:
    lines = []
    ok = True
    for check in evidence["validation_checks"]:
        if check["status"] != "PASS":
            ok = False
        lines.append(f"{check['status']}\t{check['check']}\t{check.get('detail')}")
    lines.append(f"RESULT\t{evidence['decision']}\tfirmware_candidate_created={evidence['scope']['firmware_candidate_created']}")
    if not ok:
        lines.append("RESULT\tFAIL\tinput or evidence validation failed")
    return "\n".join(lines) + "\n"


def render_report(evidence: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append("# S1-C2 executable placement unblock audit")
    lines.append("")
    lines.append("Date: 2026-08-02 UTC")
    lines.append(f"Status: **{evidence['decision']}**")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append("Read-only static audit of exact official v15, live-PASS H2, and live-PASS S1-C1 boundary-only images. No firmware candidate, app, FWSC, rollback, device access, flash, OTA, or reset was created or performed.")
    lines.append("")
    lines.append("## Exact inputs")
    lines.append("")
    lines.append("| id | path | sha256 |")
    lines.append("|---|---|---|")
    for rec in evidence["inputs"]:
        if rec.get("sha256"):
            lines.append(f"| `{rec['id']}` | `{rec['path']}` | `{rec['sha256']}` |")
    lines.append("")
    lines.append("## Decision")
    lines.append("")
    if evidence["decision"] == "BLOCK":
        lines.append("**BLOCK.** No concrete executable range is proven for the S1-C2 private atomic parser/selector that can be overwritten without removing exact S1-C1/H2 reachable behavior.")
        lines.append("")
        for reason in evidence["block_reasons"]:
            lines.append(f"- {reason}")
    else:
        lines.append("**PASS.** See `pass_candidate` in evidence.json for the admitted range and constraints.")
    lines.append("")
    lines.append("## Candidate placement matrix")
    lines.append("")
    lines.append("| candidate | range | bytes | decision | critical evidence |")
    lines.append("|---|---:|---:|---|---|")
    for item in evidence["candidates"]:
        facts = item.get("blocking_facts") or item.get("positive_facts") or []
        fact = facts[0] if facts else "see evidence.json"
        lines.append(f"| `{item['name']}` | `{item['range']}` | {item['size']} | **{item.get('decision', 'BLOCK')}** | {fact} |")
    lines.append("")
    lines.append("## Positive reachability and ownership facts")
    lines.append("")
    lines.append("- Official v15 decoders show direct stock calls to `0x0201e13e` at `0x0201e468`, `0x0201e49c`, and in Quarkslab exhaustive output at `0x02026dac`. H2/S1-C1 deliberately replace that packer body and block SAVE.")
    lines.append("- H2/S1-C1 reachable producer bytes occupy `0x0201e1a2..0x0201e1ec`. The product callsites are redirected to that producer, so overwriting it removes live-PASS H2 behavior.")
    lines.append("- The only residual executable tail with a plausible ownership argument is `0x0201e1ec..0x0201e254`, exactly 104 contiguous bytes after the H2 producer return and before official handler entry.")
    lines.append("- The `0x0202d202` completed-message callsite can short-call this tail (`bfeaf387`), but reach alone is not parser placement proof.")
    lines.append("- `0x0201e254` is the official/H2 completed-message handler entry used by callers at `0x0202d1fa` and `0x0202d202`; it must be preserved for non-private traffic.")
    lines.append("- The apparent app-area tail maps to `cfg_tool.bin` and remains BLOCKED. Uniform zero/0xff runs are reported as generic data-cave candidates only and are not promoted.")
    lines.append("")
    lines.append("## Why the residual tail does not unblock S1-C2")
    lines.append("")
    lines.append("S1-C2 needs a private parser that performs prefix discrimination, exact length/F7 gates, byte-range gates, TX/FLAGS/LEN gates, packet CRC, full-set CRC, nonblocking lock/state publication, two 156-byte copies, rejection cleanup, mutation-after-ARMED rejection, and unchanged H2 delegation. The residual tail provides only 104 contiguous bytes and no exact assembled PI32 implementation proves those requirements fit. A PASS would require exact bytes, exact overwritten range, exact branch/call encodings, and positive non-removal proof. That evidence does not exist in the current artifacts.")
    lines.append("")
    lines.append("## Smallest next runtime evidence, if later authorized")
    lines.append("")
    for item in evidence["smallest_next_runtime_evidence_if_authorized_later"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/analyze_executable_placement.py")
    lines.append("shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/SHA256SUMS")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def write_sha256s(files: list[Path]) -> None:
    lines = []
    for path in files:
        digest = sha256_path(path)
        lines.append(f"{digest}  {rel(path)}")
    (HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    evidence = make_evidence()
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "validation.txt").write_text(render_validation(evidence), encoding="utf-8")
    (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
    write_sha256s([HERE / "analyze_executable_placement.py", HERE / "evidence.json", HERE / "report.md", HERE / "validation.txt"])
    print(f"S1-C2 executable placement audit: {evidence['decision']}")
    print("wrote evidence.json report.md validation.txt SHA256SUMS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
