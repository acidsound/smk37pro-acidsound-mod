#!/usr/bin/env python3
"""Official-v15-only R03 RAM ownership candidate audit.

Read-only extractor. It consumes the official v15 app/package, Quarkslab and
Kagaimiq listing artifacts, and existing v15-only runtime-source/sysex/UI-state
evidence. It writes a reproducible evidence pack under this directory only.
It does not patch, flash, contact a device, or use v12-derived assumptions.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
BASE = 0x02000000

APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
QUARK = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
KAGA = LISTING_DIR / "kagaimiq-patched-exhaustive-listing.tsv.gz"
RUNTIME_JSON = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/runtime_source_trace.json"
RUNTIME_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/report.md"
RUNTIME_INVENTORY = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/writer_inventory.tsv"
SYSEX_JSON = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/sysex_staging_trace.json"
SYSEX_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md"
UI_EVENTS_JSON = ROOT / "baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json"
UI_EVENTS_REPORT = ROOT / "baselines/v15/analysis/ui-preflash/final-pass/events/report.md"
REQUIREMENTS = ROOT / "baselines/v15/analysis/r03-owned-ram/requirements.md"
ROADMAP = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/post-r02-roadmap.md"

EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quarkslab_exhaustive_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kagaimiq_patched_exhaustive_sha256": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

KNOWN_ADDRS = {
    "ui_ram_base": 0x01C33260,
    "stock_current_source": 0x01C34C74,
    "stock_current_source_end_9c": 0x01C34D10,
    "sysex_stage_base": 0x01C37030,
    "sysex_stage": 0x01C37FD0,
    "ui_alt_base": 0x01C34894,
    "product_ram_base": 0x01C0DE20,
    "bss_zero_start": 0x01C099D4,
    "bss_zero_end_exclusive": 0x01C4651C,
    "main_sp": 0x01C3A2D4,
    "main_ssp": 0x01C3B2D4,
    "irq_usp": 0x01C3B5D4,
    "irq_sp": 0x01C3C5D4,
}

SNIPPET_RANGES = {
    "boot_zero_and_stack_init": (0x02000004, 0x0200002C),
    "stock_loader_current_copy": (0x02005682, 0x02005712),
    "stock_note_dispatcher_copies": (0x0201C5EC, 0x0201C684),
    "sysex_complete_stage_copy": (0x0201E3EE, 0x0201E46C),
    "sysex_other_stage_overwrites": (0x0201E4C0, 0x0201E52C),
    "sysex_segmented_stage_copy": (0x0201E57A, 0x0201E592),
    "single_parameter_current_write": (0x0201E606, 0x0201E644),
    "ui_pending_consumer": (0x02029152, 0x020291CC),
    "ui_alt_base_handlers": (0x02029A1E, 0x02029A8A),
    "product_ram_handlers": (0x02025DD6, 0x02025E60),
}


def hx(value: int | None, width: int = 8) -> str | None:
    return None if value is None else f"0x{value:0{width}x}"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_line(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"])


def row_out(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def rows_between(rows: list[dict[str, str]], lo: int, hi: int) -> list[dict[str, str]]:
    return [row_out(r) for r in rows if lo <= row_addr(r) <= hi]


def raw_xrefs(app: bytes, addrs: dict[str, int]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, addr in addrs.items():
        pat = struct.pack("<I", addr)
        refs: list[str] = []
        pos = 0
        while True:
            found = app.find(pat, pos)
            if found < 0:
                break
            refs.append(hx(BASE + found) or "")
            pos = found + 1
        out[name] = {"value": hx(addr), "count": len(refs), "refs": refs}
    return out


def search_rows(rows: list[dict[str, str]], terms: Iterable[str], limit: int = 80) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = {}
    for term in terms:
        low = term.lower()
        out[term] = [row_out(r) for r in rows if low in row_line(r).lower()][:limit]
    return out


def write_access_windows(snippets: dict[str, list[dict[str, str]]]) -> None:
    with (OUT / "access_windows.tsv").open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["label", "address", "bytes", "mnemonic", "text", "flow_type", "function"])
        for label, rows in snippets.items():
            for r in rows:
                w.writerow([label, r["address"], r["bytes"], r["mnemonic"], r["text"], r["flow_type"], r["function"]])


def candidate_matrix(runtime: dict[str, Any], sysex: dict[str, Any], ui: dict[str, Any]) -> list[dict[str, Any]]:
    """Hard-coded candidate classes whose facts are derived from v15-only artifacts."""
    current_writers = runtime["current_source_trace"]["writers_and_producers"]
    sysex_paths = sysex["paths"]
    ui_counts = ui["ram_base_reconstruction"][0]["counts"]
    ui_targets = ui["ram_base_reconstruction"][0]["target_area_mov_immediates"]

    return [
        {
            "id": "stock_current_snapshot_0x01c34c74",
            "decision": "BLOCK",
            "range": {"start": "0x01c34c74", "voice_end_exclusive": "0x01c34d10", "with_0x04_metadata_end_exclusive": "0x01c34d14"},
            "capacity": "0x9c voice bytes exist, but proposed metadata would sit in the stock current-record tail and the loader copies 0xa3 bytes into the same object.",
            "alignment": "4-byte aligned start.",
            "initialization_lifetime": "Initialized by stock selected-record loader 0x02005660 and later UI/SysEx/selection paths. It is the mutable current UI patch snapshot, not an immutable Ch10 session buffer.",
            "owner": "official current Patch/runtime object at 0x01c33260+0x1a14",
            "writer_overlap_evidence": [
                {"role": x["role"], "kind": x.get("kind"), "destination": x.get("destination"), "length": x.get("length"), "summary": x.get("summary")} for x in current_writers
            ],
            "valid_generation_semantics": "Cannot safely host R03 valid/generation. Stock loader, single-parameter writer, bounded setters, UI reset, and reload paths may mutate the voice and tail after validity is published.",
            "blockers": [
                "Fails immutability: UI patch selection and supported SysEx intentionally rewrite this range.",
                "Fails metadata ownership: +0x9c..+0xa2 belongs to the stock 0xa3 current record/tail.",
                "Using it would repeat shared-current behavior instead of surviving Ch1 UI changes.",
            ],
        },
        {
            "id": "sysex_staging_0x01c37fd0",
            "decision": "BLOCK",
            "range": {"start": "0x01c37fd0", "voice_end_exclusive": "0x01c3806c", "with_0x04_metadata_end_exclusive": "0x01c38070"},
            "capacity": "0x9c staged voice bytes are materialized on accepted single-voice bulk paths; no owned metadata bytes are proven.",
            "alignment": "16-byte aligned start as 0x01c37030+0xfa0.",
            "initialization_lifetime": "Written only as a transient SysEx assembly workspace after handler gates. Later single-voice, segmented, and other bulk paths overwrite it.",
            "owner": "official SysEx handler staging workspace, not Ch10 runtime storage",
            "writer_overlap_evidence": {k: v for k, v in sysex_paths.items() if k in ["complete_single_voice_bulk", "segmented_single_voice_final", "other_stage_overwrites"]},
            "valid_generation_semantics": "No stock valid bit or generation is tied to this range. R03 could only add one in separately owned storage, which is not proven here.",
            "blockers": [
                "Later supported SysEx traffic can overwrite the Note Off source.",
                "Existing sysex-staging analysis explicitly classifies it as transient and unsafe as permanent voice storage.",
                "Metadata placed adjacent to stage has no owner/allocation proof and may collide with larger staging paths.",
            ],
        },
        {
            "id": "dispatcher_per_voice_slot_engine_plus_index_times_0xa0_plus_0xa2",
            "decision": "BLOCK",
            "range": {"start": "dynamic", "voice_end_exclusive": "dynamic+0x9c", "metadata": "dynamic+0x9c..+0xa0"},
            "capacity": "Each event destination has exactly the observed 0x9c copy plus four stock metadata bytes in a 0xa0 stride.",
            "alignment": "Dynamic engine/voice index calculation, not a fixed global address.",
            "initialization_lifetime": "Allocated/selected by the dispatcher/audio engine per event. Lifetime is the stock voice record lifetime, not a durable Ch10 source lifetime.",
            "owner": "official voice allocator/engine",
            "writer_overlap_evidence": [
                {"role": x["role"], "kind": x.get("kind"), "destination": x.get("destination"), "length": x.get("length"), "summary": x.get("summary")} for x in current_writers if x["role"].startswith("note_")
            ],
            "valid_generation_semantics": "The four bytes after the 0x9c copy are stock note/velocity/event metadata, not R03 valid/generation. Reusing them would change allocator/audio semantics.",
            "blockers": [
                "Not a fixed source address that future Note On/Off can reread.",
                "Owned by active voice records and voice stealing, not by an immutable Ch10 buffer.",
                "Cannot publish/reject reloads independently from the stock allocator.",
            ],
        },
        {
            "id": "ui_alt_block_or_gap_near_0x01c34894",
            "decision": "BLOCK",
            "range": {"observed_base": "0x01c34894", "tempting_gap_start": "0x01c34896", "tempting_gap_end_exclusive": "0x01c34936"},
            "capacity": "A 0xa0-byte gap can be imagined after the two observed bytes, but no official allocation boundary reserves it.",
            "alignment": "Observed base is 4-byte aligned; tempting +2 start is not 4-byte aligned.",
            "initialization_lifetime": "Within the same zeroed/static RAM region and UI object family. Only two direct base loads are recovered; lifetime/owner size is not closed.",
            "owner": "UI/event state alias from final-pass UI evidence",
            "writer_overlap_evidence": {
                "ui_base_counts": ui_counts,
                "target_area_mov_immediates": [x for x in ui_targets if x["base"] == "0x01c34894"],
                "known_handlers": "0x02029a20 writes [base+1], 0x02029a56 writes [base+0], and neighboring code reads [base-0x38] and table-derived offsets.",
            },
            "valid_generation_semantics": "No stock valid/generation state is associated with this alias. Adding one would rely on an unallocated gap and absence of decoded xrefs.",
            "blockers": [
                "Gate A hard-blocks absence-only free-RAM claims.",
                "The alias is proven UI-owned, not free or Ch10-owned.",
                "Computed/table UI paths and pointer fields prevent a bounded no-alias proof from static listing alone.",
            ],
        },
        {
            "id": "product_ram_stride_workspace_0x01c0de20",
            "decision": "BLOCK",
            "range": {"base": "0x01c0de20", "stride": "0x49e3", "observed_offsets": ["0x1", "0x116", "0xa7e", "0xa7f"]},
            "capacity": "The stride is large enough in principle, but no exact owned subrange is reserved for R03.",
            "alignment": "Base is aligned; selected object is index-dependent.",
            "initialization_lifetime": "Product/UI workspace selected by UI state. It participates in renderer/event logic and product data handling.",
            "owner": "official product/UI state workspace",
            "writer_overlap_evidence": {
                "ui_base_counts": ui_counts,
                "target_area_mov_immediates": [x for x in ui_targets if x["base"] == "0x01c0de20"],
                "known_handlers": "0x02025dea/0x02025e06 pass +0xa7e/+0xa7f to encoder routines; 0x02025e4a reads selected stride+0x116; 0x02029ab2 iterates product_ram + index*0x49e3 + rows.",
            },
            "valid_generation_semantics": "No Ch10 voice validity/generation fields are proven in any product_ram stride.",
            "blockers": [
                "Dynamic index and UI ownership mean it cannot be treated as a session-stable Ch10 buffer.",
                "No bounded allocation map identifies a free 0xa0 subrange inside the stride.",
                "Stack/heap/DMA/storage aliases are not excluded by the static evidence.",
            ],
        },
        {
            "id": "generic_zeroed_bss_gap",
            "decision": "BLOCK",
            "range": {"zero_start": "0x01c099d4", "zero_end_exclusive": "0x01c4651c", "stack_pointers_inside_or_near": ["0x01c3a2d4", "0x01c3b2d4", "0x01c3b5d4", "0x01c3c5d4"]},
            "capacity": "The zeroed static-RAM span is large, but a concrete owned 0xa0 allocation inside it is not identified.",
            "alignment": "Many aligned addresses exist; none is selected here.",
            "initialization_lifetime": "Boot code zeros the range, then official globals, stacks, heaps, tasks, DMA, USB, UI, audio, and storage workspaces use parts of it.",
            "owner": "global runtime memory, not an R03 allocation",
            "writer_overlap_evidence": {
                "boot_rows": "0x02000016..0x0200002a zero 0x01c099d4 for 0x3cb48 bytes; 0x02000004/0x0a and 0x02000098/0x9e initialize multiple stacks inside/near the span.",
                "raw_xref_policy": "Any apparent gap produced only by lack of decoded xrefs is explicitly non-evidence under Gate A.",
            },
            "valid_generation_semantics": "Could be designed only after a real allocation/reservation proof. Current evidence provides reset-to-zero but not ownership or no-alias lifetime.",
            "blockers": [
                "Fails Gate A.4/A.5/A.6 ownership and alias exclusions.",
                "Would be an absence-of-xrefs claim, which is a mandatory BLOCK.",
                "Stack pointers are visible in the same broad memory span, so blind placement is unsafe.",
            ],
        },
        {
            "id": "hypothetical_r03_owned_copy_buffer",
            "decision": "BLOCK",
            "range": {"start": None, "end_exclusive": None, "minimum_size": "0xa0 (0x9c voice + valid/generation metadata)"},
            "capacity": "The R03 design requires this shape, and R02 proved the staged 0x9c payload is sufficient for the controlled Mooger #1 path, but no exact RAM address is proven.",
            "alignment": "To be defined with the eventual allocation.",
            "initialization_lifetime": "Desired policy: reset invalid at boot, copy stage after exact packet acceptance, publish valid+generation after copy, keep immutable until explicit safe reload. This is a requirement, not an observed official allocation.",
            "owner": "not found in official v15 static evidence",
            "writer_overlap_evidence": "No candidate address means no writer-overlap proof can be completed. Producer/consumer ABI and executable cave are also not closed in this analysis.",
            "valid_generation_semantics": "Recommended semantics if a real range is later proven: valid byte initially 0, generation byte increments after completed copy, reload rejected while Ch10 active unless per-active-note generation is added.",
            "blockers": [
                "No exact start/end address.",
                "No bounded allocation or owner/lifetime proof.",
                "No static proof excluding DMA/heap/stack/task/USB/UI/audio/storage aliases.",
            ],
        },
    ]


def validate(evidence: dict[str, Any]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"name": name, "status": "PASS" if ok else "FAIL", "detail": detail})

    sha = evidence["sha256"]
    check("official-v15-app-sha256", sha["app"] == EXPECTED["app_sha256"], sha["app"])
    check("official-v15-package-sha256", sha["package"] == EXPECTED["package_sha256"], sha["package"])
    check("quarkslab-exhaustive-sha256", sha["quarkslab_exhaustive"] == EXPECTED["quarkslab_exhaustive_sha256"], sha["quarkslab_exhaustive"])
    check("kagaimiq-patched-exhaustive-sha256", sha["kagaimiq_patched_exhaustive"] == EXPECTED["kagaimiq_patched_exhaustive_sha256"], sha["kagaimiq_patched_exhaustive"])
    manifest = load_json(MANIFEST)
    check("manifest-app-binding", manifest.get("app_sha256") == EXPECTED["app_sha256"], str(manifest.get("app_sha256")))
    check("manifest-package-binding", manifest.get("package_sha256") == EXPECTED["package_sha256"], str(manifest.get("package_sha256")))
    check("current-alias-arithmetic", 0x01C33260 + 0x1A14 == 0x01C34C74, "0x01c33260+0x1a14=0x01c34c74")
    check("sysex-stage-arithmetic", 0x01C37030 + 0x0FA0 == 0x01C37FD0, "0x01c37030+0x0fa0=0x01c37fd0")
    check("r03-requires-metadata", evidence["requirements_summary"]["minimum_bytes"] == "0xa0", evidence["requirements_summary"]["minimum_bytes"])
    decisions = {c["id"]: c["decision"] for c in evidence["candidates"]}
    check("all-candidates-explicitly-decided", len(decisions) == 7 and all(v in {"PASS", "BLOCK"} for v in decisions.values()), json.dumps(decisions, sort_keys=True))
    check("no-pass-without-owned-allocation", not evidence["pass_candidates"], json.dumps(evidence["pass_candidates"]))
    current = evidence["raw_xrefs"]["stock_current_source"]
    check("stock-current-direct-xref-known", current["count"] == 1 and current["refs"] == ["0x0201c604"], json.dumps(current, sort_keys=True))
    stage = evidence["raw_xrefs"]["sysex_stage"]
    check("sysex-stage-not-direct-immediate", stage["count"] == 0, json.dumps(stage, sort_keys=True))
    ui_alt = evidence["raw_xrefs"]["ui_alt_base"]
    check("ui-alt-base-direct-immediates", ui_alt["count"] == 2 and set(ui_alt["refs"]) == {"0x02029a22", "0x02029a58"}, json.dumps(ui_alt, sort_keys=True))
    failed = [c for c in checks if c["status"] != "PASS"]
    if failed:
        raise SystemExit("validation failed: " + json.dumps(failed, indent=2))
    return checks


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out)


def write_report(evidence: dict[str, Any]) -> None:
    rows = []
    for c in evidence["candidates"]:
        blockers = "<br>".join(c["blockers"][:3])
        rows.append([f"`{c['id']}`", f"**{c['decision']}**", c["range"].get("start") or c["range"].get("observed_base") or c["range"].get("base") or c["range"].get("zero_start") or "dynamic/none", blockers])

    validation_rows = [[x["name"], x["status"], x["detail"].replace("|", "\\|")] for x in evidence["validation"]]
    input_rows = [[k, f"`{v}`"] for k, v in evidence["sha256"].items()]

    report = f"""# R03 owned RAM candidate audit for official v15

Scope: exact official v15 only. This analysis reads the official app/package,
Quarkslab/Kagaimiq listings, and existing v15-only runtime-source, SysEx-staging,
and UI-state evidence. It performs no patching, flashing, device access, or v12-derived reasoning.

## Verdict

**R03 RAM Gate A remains BLOCKED.** No evaluated RAM candidate PASSes. The only
shape that satisfies the desired R03 policy is a hypothetical owned copy buffer,
but this pass did not find a defensible official-v15 address, allocation owner,
lifetime, and writer-overlap proof for it.

This is intentional: the requirements explicitly hard-BLOCK claims based only on
absence of decoded xrefs. Apparent gaps in zeroed BSS, UI RAM, or product RAM are
therefore not promoted to free RAM.

## Input hashes

{md_table(["input", "sha256"], input_rows)}

## Candidate decisions

{md_table(["candidate", "decision", "range/base", "primary blockers"], rows)}

## Candidate notes

### `stock_current_snapshot_0x01c34c74`: BLOCK

The stock dispatcher copies `0x9c` bytes from `0x01c34c74` on both Note On and
Note Off, but runtime-source evidence shows the same bytes are the mutable
current Patch snapshot at `0x01c33260+0x1a14`. Known overlapping stock writers
include the selected-record loader, the bulk SysEx path followed by reload,
single-parameter writes, bounded field setters for `+0x86/+0x87`, and a UI-mode
reset of `+0x9a`. Metadata at `+0x9c` would also overlap the stock `0xa3` current
record tail.

### `sysex_staging_0x01c37fd0`: BLOCK

The official handler can materialize the R02-proven `0x9c` single-voice payload
at `0x01c37030+0xfa0`, but sysex-staging evidence classifies it as a transient
assembly workspace. Complete, segmented, and other bulk paths overwrite it. It
has no valid/generation state and cannot be the Note Off source after later
supported product SysEx traffic.

### `dispatcher_per_voice_slot_engine_plus_index_times_0xa0_plus_0xa2`: BLOCK

The per-voice destination already has the right local shape, `0x9c` copied tone
bytes plus four stock metadata bytes in a `0xa0` stride. It is not a stable source
buffer. It is owned by the official voice allocator/audio engine, may be reused
or stolen, and the four metadata bytes are not available for R03 validity.

### `ui_alt_block_or_gap_near_0x01c34894`: BLOCK

The final-pass UI evidence recovers two direct base loads of `0x01c34894` and
handlers that write `[base+0]` and `[base+1]`. A gap after those bytes is not an
allocation. Because this address is UI-owned and static evidence cannot bound all
computed/table UI aliases, claiming `0x01c34896..+0xa0` would be absence-only.

### `product_ram_stride_workspace_0x01c0de20`: BLOCK

The `0x49e3` product RAM stride is large, but it is a UI/product workspace with
dynamic selection and observed handlers at `+0xa7e`, `+0xa7f`, `+0x116`, and row
iteration paths. No Ch10-owned suballocation or no-alias proof exists.

### `generic_zeroed_bss_gap`: BLOCK

Boot rows zero `0x01c099d4` for `0x3cb48` bytes, and stack pointers are also
initialized inside or near this broad span. Zero-on-boot is initialization, not
ownership. Without a linker/allocation map or runtime watch proving heap, stack,
DMA, task, USB, UI, audio, and storage cannot alias a chosen subrange, every
specific gap in this span remains BLOCKED.

### `hypothetical_r03_owned_copy_buffer`: BLOCK pending proof

The desired R03 policy is still valid: start invalid at boot, copy exactly `0x9c`
from staging only after an accepted exact packet, publish valid/generation after
copy, keep immutable, and reject reload while Ch10 is active unless per-active
note generation is proven. This audit did not find the required exact RAM range.

## Validation

{md_table(["check", "status", "detail"], validation_rows)}

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/ram-ownership/analyze_ram_ownership.py
cd baselines/v15/analysis/r03-owned-ram/ram-ownership
shasum -a 256 -c SHA256SUMS
```

Generated files:

- `analyze_ram_ownership.py`
- `evidence.json`
- `access_windows.tsv`
- `validation.txt`
- `report.md`
- `SHA256SUMS`
"""
    (OUT / "report.md").write_text(report)


def write_validation(checks: list[dict[str, str]]) -> None:
    lines = ["R03 RAM ownership validation", ""]
    for c in checks:
        lines.append(f"{c['status']}\t{c['name']}\t{c['detail']}")
    (OUT / "validation.txt").write_text("\n".join(lines) + "\n")


def write_sha256s() -> None:
    files = [
        OUT / "analyze_ram_ownership.py",
        OUT / "evidence.json",
        OUT / "access_windows.tsv",
        OUT / "validation.txt",
        OUT / "report.md",
    ]
    lines = []
    for p in files:
        lines.append(f"{sha256(p)}  {p.name}")
    (OUT / "SHA256SUMS").write_text("\n".join(lines) + "\n")


def main() -> None:
    app = APP.read_bytes()
    quark_rows = read_listing(QUARK)
    runtime = load_json(RUNTIME_JSON)
    sysex = load_json(SYSEX_JSON)
    ui = load_json(UI_EVENTS_JSON)

    snippets = {label: rows_between(quark_rows, lo, hi) for label, (lo, hi) in SNIPPET_RANGES.items()}
    write_access_windows(snippets)

    evidence: dict[str, Any] = {
        "scope": {
            "official_v15_only": True,
            "no_patch_flash_or_device_access": True,
            "no_v12_assumptions": True,
            "inputs": [
                str(APP.relative_to(ROOT)),
                str(PACKAGE.relative_to(ROOT)),
                str(QUARK.relative_to(ROOT)),
                str(KAGA.relative_to(ROOT)),
                str(RUNTIME_JSON.relative_to(ROOT)),
                str(SYSEX_JSON.relative_to(ROOT)),
                str(UI_EVENTS_JSON.relative_to(ROOT)),
                str(REQUIREMENTS.relative_to(ROOT)),
                str(ROADMAP.relative_to(ROOT)),
            ],
        },
        "requirements_summary": {
            "voice_bytes": "0x9c",
            "metadata_bytes_minimum": "0x04",
            "minimum_bytes": "0xa0",
            "required_metadata": ["valid", "generation"],
            "absence_only_policy": "mandatory BLOCK",
        },
        "sha256": {
            "app": sha256(APP),
            "package": sha256(PACKAGE),
            "manifest": sha256(MANIFEST),
            "quarkslab_exhaustive": sha256(QUARK),
            "kagaimiq_patched_exhaustive": sha256(KAGA),
            "runtime_source_trace": sha256(RUNTIME_JSON),
            "runtime_source_report": sha256(RUNTIME_REPORT),
            "runtime_writer_inventory": sha256(RUNTIME_INVENTORY),
            "sysex_staging_trace": sha256(SYSEX_JSON),
            "sysex_staging_report": sha256(SYSEX_REPORT),
            "ui_final_pass_events": sha256(UI_EVENTS_JSON),
            "ui_final_pass_report": sha256(UI_EVENTS_REPORT),
            "r03_requirements": sha256(REQUIREMENTS),
            "post_r02_roadmap": sha256(ROADMAP),
        },
        "known_addresses": {k: hx(v) for k, v in KNOWN_ADDRS.items()},
        "raw_xrefs": raw_xrefs(app, KNOWN_ADDRS),
        "listing_search_hits": search_rows(quark_rows, ["0x1c34c74", "0x1c37fd0", "0x1c34894", "0x1c0de20", "0x1c099d4", "0x1c3a2d4", "0x49e3", "0xfa0", "0x1a14"]),
        "snippet_ranges": {label: {"start": hx(lo), "end": hx(hi), "rows": rows} for label, ((lo, hi), rows) in zip(SNIPPET_RANGES.keys(), zip(SNIPPET_RANGES.values(), snippets.values()))},
        "source_evidence_summary": {
            "runtime_current_source": runtime["constants"],
            "runtime_writer_roles": [x["role"] for x in runtime["current_source_trace"]["writers_and_producers"]],
            "sysex_constants": sysex["constants"],
            "ui_ram_base_reconstruction": ui["ram_base_reconstruction"],
            "ui_pending_to_live": ui["field_offset_aliases"]["pending_to_live"],
        },
    }
    evidence["candidates"] = candidate_matrix(runtime, sysex, ui)
    evidence["pass_candidates"] = [c["id"] for c in evidence["candidates"] if c["decision"] == "PASS"]
    evidence["block_candidates"] = [c["id"] for c in evidence["candidates"] if c["decision"] == "BLOCK"]
    evidence["validation"] = validate(evidence)

    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    write_validation(evidence["validation"])
    write_report(evidence)
    write_sha256s()


if __name__ == "__main__":
    main()
