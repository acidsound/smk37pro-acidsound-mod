#!/usr/bin/env python3
"""Summarize paired V15DecoderAnalysis logs without reinterpreting xrefs as proof."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

METRIC_RE = re.compile(r"METRIC phase=(\w+) key=([^ ]+) value=(\d+)")
TARGET_COUNT_RE = re.compile(
    r"TARGET_XREF_COUNT phase=(\w+) target=([^ ]+) exact=(\d+) interior=(\d+)"
)
RAW_COUNT_RE = re.compile(
    r"RAW_POINTER_COUNT target=([^ ]+) exact=(\d+) interior=(\d+)"
)
PROVENANCE_RE = re.compile(r"PROVENANCE ([^=]+)=(.*?)(?: \(GhidraScript\))?$")


def payload(line: str) -> str:
    marker = "V15DecoderAnalysis.java> "
    return line.split(marker, 1)[1] if marker in line else line


def parse_log(path: Path) -> dict[str, object]:
    text = path.read_text(errors="replace")
    metrics: dict[str, dict[str, int]] = {}
    targets: dict[str, dict[str, dict[str, int]]] = {}
    raw_pointers: dict[str, dict[str, int]] = {}
    provenance: dict[str, str] = {}
    xref_records: list[str] = []

    for original in text.splitlines():
        line = payload(original)
        match = METRIC_RE.search(line)
        if match:
            phase, key, value = match.groups()
            metrics.setdefault(phase, {})[key] = int(value)
            continue
        match = TARGET_COUNT_RE.search(line)
        if match:
            phase, target, exact, interior = match.groups()
            targets.setdefault(phase, {})[target] = {
                "exact": int(exact),
                "interior": int(interior),
            }
            continue
        match = RAW_COUNT_RE.search(line)
        if match:
            target, exact, interior = match.groups()
            raw_pointers[target] = {"exact": int(exact), "interior": int(interior)}
            continue
        match = PROVENANCE_RE.search(line)
        if match:
            provenance[match.group(1)] = match.group(2).strip()
            continue
        if "TARGET_XREF phase=" in line:
            xref_records.append(line.strip())

    for phase_metrics in metrics.values():
        code_bytes = phase_metrics.get("code_region_bytes", 0)
        decoded_bytes = phase_metrics.get("instruction_bytes", 0)
        if code_bytes:
            phase_metrics["decoded_byte_percent_x1000"] = round(
                decoded_bytes * 100_000 / code_bytes
            )

    error_patterns = {
        "report_script_error": r"REPORT SCRIPT ERROR",
        "pcode_error": r"(?:Pcode error|pcode error)",
        "unresolved_constructor": r"Unable to resolve constructor",
        "delay_slot_context_error": r"Could not find cached delayslot parser context",
        "cross_build_error": r"cross-build instruction",
        "constant_propagation_exception": r"ConstantPropagationAnalyzer.*(?:Exception|ERROR)",
    }
    errors = {
        name: len(re.findall(pattern, text)) for name, pattern in error_patterns.items()
    }
    return {
        "path": str(path),
        "provenance": provenance,
        "metrics": metrics,
        "target_xref_counts": targets,
        "raw_pointer_counts": raw_pointers,
        "target_xrefs": xref_records,
        "errors": errors,
    }


def percent(metrics: dict[str, int]) -> str:
    value = metrics.get("decoded_byte_percent_x1000")
    if value is None:
        return "n/a"
    return f"{value / 1000:.3f}%"


def markdown(report: dict[str, object]) -> str:
    variants: dict[str, dict[str, object]] = report["variants"]  # type: ignore[assignment]
    keys = [
        "instruction_count",
        "instruction_bytes",
        "undecoded_even_slots",
        "function_count",
        "call_instruction_count",
        "direct_call_reference_count",
        "branch_instruction_count",
        "computed_flow_count",
        "evidence_reference_count",
        "evidence_scalar_count",
        "evidence_pcode_constant_count",
    ]
    lines = [
        "# Decoder comparison summary",
        "",
        "Generated mechanically from the paired Ghidra logs. Exact/interior xrefs are",
        "candidate evidence only. Exhaustive-sweep results may include decoded data.",
        "",
    ]
    for phase in ("recursive", "exhaustive"):
        lines.extend(
            [
                f"## {phase.title()} phase",
                "",
                "| Metric | Quarkslab | kagaimiq + patch |",
                "|---|---:|---:|",
            ]
        )
        q = variants["quarkslab"]["metrics"].get(phase, {})  # type: ignore[index,union-attr]
        k = variants["kagaimiq-patched"]["metrics"].get(phase, {})  # type: ignore[index,union-attr]
        for key in keys:
            lines.append(f"| `{key}` | {q.get(key, 0):,} | {k.get(key, 0):,} |")
        lines.append(f"| decoded byte coverage | {percent(q)} | {percent(k)} |")
        lines.append("")

    lines.extend(
        [
            "## Exact and interior target xrefs",
            "",
            "| Phase | Target | Quarkslab exact/interior | kagaimiq + patch exact/interior |",
            "|---|---|---:|---:|",
        ]
    )
    target_names: set[str] = set()
    for variant in variants.values():
        for phase_targets in variant["target_xref_counts"].values():  # type: ignore[union-attr]
            target_names.update(phase_targets)
    for phase in ("recursive", "exhaustive"):
        for target in sorted(target_names):
            q = variants["quarkslab"]["target_xref_counts"].get(phase, {}).get(  # type: ignore[index,union-attr]
                target, {"exact": 0, "interior": 0}
            )
            k = variants["kagaimiq-patched"]["target_xref_counts"].get(phase, {}).get(  # type: ignore[index,union-attr]
                target, {"exact": 0, "interior": 0}
            )
            lines.append(
                f"| {phase} | `{target}` | {q['exact']}/{q['interior']} | {k['exact']}/{k['interior']} |"
            )
    lines.extend(
        [
            "",
            "## Decoder/tool error markers",
            "",
            "| Marker | Quarkslab | kagaimiq + patch |",
            "|---|---:|---:|",
        ]
    )
    error_names = sorted(
        set(variants["quarkslab"]["errors"])  # type: ignore[arg-type,index]
        | set(variants["kagaimiq-patched"]["errors"])  # type: ignore[arg-type,index]
    )
    for name in error_names:
        lines.append(
            f"| `{name}` | {variants['quarkslab']['errors'][name]} | "  # type: ignore[index]
            f"{variants['kagaimiq-patched']['errors'][name]} |"  # type: ignore[index]
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--quarkslab-log", type=Path, required=True)
    parser.add_argument("--kagaimiq-log", type=Path, required=True)
    parser.add_argument("--json", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()

    report = {
        "classification_policy": {
            "recursive": "flow-followed and internal-pointer-seeded; still heuristic",
            "exhaustive": "aligned sweep; may decode data and cannot establish a function by itself",
            "zero_xref": "not absence when decoder/p-code errors or incomplete coverage remain",
        },
        "variants": {
            "quarkslab": parse_log(args.quarkslab_log),
            "kagaimiq-patched": parse_log(args.kagaimiq_log),
        },
    }
    args.json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    args.markdown.write_text(markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
