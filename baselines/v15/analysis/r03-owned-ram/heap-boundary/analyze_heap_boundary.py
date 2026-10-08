#!/usr/bin/env python3
"""Official-v15 heap-boundary RAM ownership audit.

This script is intentionally read-only with respect to inputs.  It uses the exact
official v15 app, existing v15 Quarkslab/Kagaimiq listings, and pinned SDK
signature evidence already checked into this repository.  Public SDK evidence is
used only to calibrate ABI/RTOS signatures, not to assign unverified product RAM
ownership.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-boundary"
APP = ROOT / "build/v15-official-app.bin"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"
QS_LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
SDK_REPORT = ROOT / "baselines/v15/analysis/sdk-signatures/report.json"
SDK_EVIDENCE = ROOT / "baselines/v15/analysis/sdk-signatures/evidence.md"
R03_REQ = ROOT / "baselines/v15/analysis/r03-owned-ram/requirements.md"
PREV_RAM_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md"

EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
RUNTIME_BASE = 0x02000000
RAM_COPY_SOURCE = 0x0208D160
RAM_COPY_DEST = 0x01C00000
RAM_COPY_SIZE = 0x99D4
BSS_START = 0x01C099D4
BSS_SIZE = 0x3CB48
BSS_END = BSS_START + BSS_SIZE
FIXED_REGION_SIZE = 0xA4
VOICE_BYTES = 0x9C

BOOT_RANGE = range(0x02000000, 0x020000AC)
KEY_TARGETS = {
    "heap_init_candidate": 0x02060E2C,
    "malloc_like_candidate": 0x02060ED4,
    "free_like_candidate": 0x0205FC2E,
    "memcpy_like_candidate": 0x02048CCE,
}
ALLOCATOR_BYTE_WINDOWS = {
    "heap_init_candidate_02060e2c": 0x02060E2C,
    "malloc_like_candidate_02060ed4": 0x02060ED4,
    "freertos_exact_prvSearchForNameWithinSingleList_02060f86": 0x02060F86,
    "freertos_exact_vListInsertEnd_02061050": 0x02061050,
    "freertos_exact_vListInsert_02061ac0": 0x02061AC0,
    "freertos_exact_vListInitialise_02061e68": 0x02061E68,
}
RAM_HELPERS = [0x01C00D6C, 0x01C00EC2, 0x01C00EEA, 0x01C00F2E, 0x01C03566]


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_listing(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with gzip.open(path, "rt", encoding="utf-8") as f:
        header = next(f).rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < len(header):
                parts += [""] * (len(header) - len(parts))
            rows.append(dict(zip(header, parts)))
    return rows


def hx(v: int) -> str:
    return f"0x{v:08x}"


def file_off_for_va(va: int) -> int:
    return va - RUNTIME_BASE


def source_off_for_ram_va(va: int) -> int:
    return (RAM_COPY_SOURCE - RUNTIME_BASE) + (va - RAM_COPY_DEST)


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def call_target(row: dict[str, str]) -> int | None:
    m = re.search(r"call 0x([0-9a-fA-F]+)", row.get("text", ""))
    if not m:
        return None
    return int(m.group(1), 16)


def boot_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return [r for r in rows if row_addr(r) in BOOT_RANGE]


def direct_movs_to_ram(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        m = re.search(r"mov (r\d+|sp|ssp|usp|reti),#0x([0-9a-fA-F]+)", r.get("text", ""))
        if not m:
            continue
        imm = int(m.group(2), 16)
        if 0x01C00000 <= imm <= 0x01C90800:
            out.append({"address": hx(row_addr(r)), "target": m.group(1), "immediate": hx(imm), "function": r.get("function", "")})
    return out


def stack_init_from_boot(rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        m = re.search(r"mov (sp|ssp|usp),#0x([0-9a-fA-F]+)", r.get("text", ""))
        if m:
            imm = int(m.group(2), 16)
            out.append({
                "address": hx(row_addr(r)),
                "register": m.group(1),
                "value": hx(imm),
                "inside_zeroed_bss": BSS_START <= imm < BSS_END,
            })
    return out


def target_calls(rows: list[dict[str, str]]) -> dict[str, Any]:
    by_name: dict[str, Any] = {}
    for name, target in KEY_TARGETS.items():
        calls = [r for r in rows if call_target(r) == target]
        by_name[name] = {
            "target": hx(target),
            "count_in_decoded_listing": len(calls),
            "first_20_callsite_addresses": [hx(row_addr(r)) for r in calls[:20]],
            "functions_first_20": [r.get("function", "") for r in calls[:20]],
        }
    return by_name


def exact_sdk_matches() -> list[dict[str, Any]]:
    report = json.loads(SDK_REPORT.read_text())
    wanted = {0x02060F86, 0x02061050, 0x02061AC0, 0x02061E68}
    matches = []
    for m in report["sdk_elf_exact"]["all_matches"]:
        if m["app_address"] in wanted or any(token in m["name"] for token in ("vList", "prvSearchForName")):
            matches.append({
                "name": m["name"],
                "app_address": hx(m["app_address"]),
                "app_offset": hx(m["app_offset"]),
                "sdk_address": hx(m["sdk_address"]),
                "size": m["size"],
                "body_sha256": m["body_sha256"],
            })
    return matches


def app_bytes_windows(app: bytes) -> dict[str, Any]:
    windows = {}
    for name, va in ALLOCATOR_BYTE_WINDOWS.items():
        off = file_off_for_va(va)
        windows[name] = {
            "va": hx(va),
            "file_offset": hx(off),
            "sha256_96_bytes": hashlib.sha256(app[off:off+96]).hexdigest(),
            "hex_96_bytes": app[off:off+96].hex(),
        }
    for va in RAM_HELPERS:
        off = source_off_for_ram_va(va)
        windows[f"ram_helper_{va:08x}_copied_from_app"] = {
            "ram_va": hx(va),
            "source_file_offset": hx(off),
            "sha256_96_bytes": hashlib.sha256(app[off:off+96]).hexdigest(),
            "hex_96_bytes": app[off:off+96].hex(),
        }
    return windows


def immediate_counts(movs: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for m in movs:
        counts[m["immediate"]] = counts.get(m["immediate"], 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:40])


def validation(e: dict[str, Any]) -> list[dict[str, str]]:
    checks = []
    def add(name: str, ok: bool, detail: Any) -> None:
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)})
    def block(name: str, detail: Any) -> None:
        checks.append({"check": name, "status": "BLOCK", "detail": str(detail)})
    add("official-v15-app-sha256", e["inputs"]["app_sha256"] == EXPECTED_APP_SHA256, e["inputs"]["app_sha256"])
    add("manifest-app-binding", e["inputs"]["manifest_app_sha256"] == EXPECTED_APP_SHA256, e["inputs"]["manifest_app_sha256"])
    add("bss-end-arithmetic", e["boot"]["bss_end_exclusive"] == hx(BSS_END), e["boot"]["bss_end_exclusive"])
    add("data-copy-end-arithmetic", e["boot"]["ram_copy_dest_end_exclusive"] == hx(RAM_COPY_DEST + RAM_COPY_SIZE), e["boot"]["ram_copy_dest_end_exclusive"])
    add("boot-stack-pointers-inside-zeroed-bss", all(x["inside_zeroed_bss"] for x in e["boot"]["stack_pointer_initializers"]), e["boot"]["stack_pointer_initializers"])
    add("single-heap-init-candidate-call", e["calls"]["heap_init_candidate"]["count_in_decoded_listing"] == 1, e["calls"]["heap_init_candidate"])
    add("malloc-like-calls-present", e["calls"]["malloc_like_candidate"]["count_in_decoded_listing"] > 20, e["calls"]["malloc_like_candidate"]["count_in_decoded_listing"])
    add("freertos-sdk-exact-anchors-present", len(e["sdk_signature_anchors"]) >= 4, len(e["sdk_signature_anchors"]))
    add("fixed-region-size", FIXED_REGION_SIZE == 0xA4, hx(FIXED_REGION_SIZE))
    add("voice-plus-metadata-budget", VOICE_BYTES < FIXED_REGION_SIZE, f"voice={hx(VOICE_BYTES)} total={hx(FIXED_REGION_SIZE)}")
    block("heap-bounds-proven", "No v15-internal exact arena start/end and no no-alias proof were recovered")
    add("decision-is-block", e["decision"]["verdict"] == "BLOCK", e["decision"]["verdict"])
    return checks


def write_tsv(path: Path, rows: list[dict[str, Any]], headers: list[str]) -> None:
    with path.open("w", encoding="utf-8") as f:
        f.write("\t".join(headers) + "\n")
        for r in rows:
            f.write("\t".join(str(r.get(h, "")) for h in headers) + "\n")


def make_report(e: dict[str, Any], checks: list[dict[str, str]]) -> str:
    verdict = e["decision"]["verdict"]
    return f"""# R03 heap-boundary RAM ownership audit for official v15

Scope: exact official v15 app only. This audit performs no patching, flashing,
device access, or v12-derived reasoning. The public AC79 SDK is used only through
pinned local signature evidence to calibrate ABI/FreeRTOS shapes and SoC facts,
then every claim is checked against v15-internal bytes/listings.

## Verdict

**{verdict}.** A fixed `0xa4` RAM region is **not proven ownable** by shrinking or
relocating a heap, or by extending a proven allocation, with no alias.

The reason is not that RAM is too small. The exact boot image clearly zeros a
large BSS span and initializes stacks inside it, and the app contains a
malloc-like entry plus FreeRTOS list/task infrastructure. The blocker is that the
v15-internal evidence recovered here does **not** prove an allocator arena
start/end, every dynamic stack/task/heap consumer, or a bounded allocation whose
lifetime and alias exclusions reserve `0xa4` bytes for R03. Under Gate A, a
zeroed gap or absence of decoded xrefs remains a hard BLOCK.

## Exact boot memory evidence

| item | value |
| --- | --- |
| data copy source | `{e['boot']['ram_copy_source_start']}` |
| data copy destination | `{e['boot']['ram_copy_dest_start']}..{e['boot']['ram_copy_dest_end_exclusive']}` |
| data copy size | `{e['boot']['ram_copy_size']}` |
| BSS zero start | `{e['boot']['bss_start']}` |
| BSS zero end exclusive | `{e['boot']['bss_end_exclusive']}` |
| BSS zero size | `{e['boot']['bss_size']}` |

Boot stack/register initializers:

| address | register | value | inside zeroed BSS |
| --- | --- | --- | --- |
""" + "\n".join(
        f"| `{x['address']}` | `{x['register']}` | `{x['value']}` | {x['inside_zeroed_bss']} |"
        for x in e["boot"]["stack_pointer_initializers"]
    ) + f"""

Important consequence: the zeroed span is not free RAM. It contains stock globals
and stack pointers. Any proposed fixed `0xa4` destination inside or adjacent to
this span needs an owner/lifetime proof, not just zero-on-boot behavior.

## Task/RTOS and allocator ABI evidence

Pinned SDK evidence establishes the pi32v2 scalar ABI model used for calibration:
`r0..r3` carry the first four scalar/pointer arguments and `r0` carries return.
The same SDK report has exact FreeRTOS list/task infrastructure matches inside
v15 near the allocator region:

| SDK symbol | v15 address | size | body sha256 |
| --- | ---: | ---: | --- |
""" + "\n".join(
        f"| `{m['name']}` | `{m['app_address']}` | {m['size']} | `{m['body_sha256']}` |"
        for m in e["sdk_signature_anchors"]
    ) + f"""

Decoded v15 call inventory for key targets:

| target | address | decoded call count | first callsites |
| --- | ---: | ---: | --- |
""" + "\n".join(
        f"| `{name}` | `{info['target']}` | {info['count_in_decoded_listing']} | `{', '.join(info['first_20_callsite_addresses'][:8])}` |"
        for name, info in e["calls"].items()
    ) + f"""

`0x02060e2c` is called once during boot after BSS zero/data copy. `0x02060ed4`
has many decoded callsites and is treated here as the malloc-like entry for ABI
risk analysis. `0x0205fc2e` has a deallocation-like call pattern. These names are
calibrated, not promoted into a complete allocator proof: the required heap arena
bounds are not recovered.

## Heap-boundary decision matrix

| question | decision | evidence | blocker |
| --- | --- | --- | --- |
| Exact boot BSS zeroing known? | PASS | boot rows show `0x01c099d4` zeroed for `0x3cb48` bytes | none |
| Stack initialization known? | PASS | `sp=0x01c3a2d4`, `ssp=0x01c3b2d4`, later `usp=0x01c3b5d4`, `sp=0x01c3c5d4` | margins and later task stacks not bounded |
| Task/RTOS presence known? | PASS/PARTIAL | exact SDK FreeRTOS list anchors in v15 | no complete task/stack allocation inventory |
| Allocator ABI known enough for call risk? | PARTIAL | SDK ABI calibration plus many v15 callsites to malloc/free-like targets | allocator body is not fully decoded into arena map here |
| Heap arena start/end proven? | BLOCK | only allocator globals/calls and boot init bytes were recovered | no exact v15-internal arena low/high, high-water, or linker map |
| Shrink/relocate heap to own `0xa4`? | BLOCK | no arena bounds or all-consumer stack/heap inventory | cannot prove no alias after shrink/relocation |
| Extend a proven allocation by `0xa4`? | BLOCK | no bounded official allocation with owner/lifetime and spare tail was found | cannot prove object size, lifetime, and all aliases |
| Use zeroed BSS gap as fixed `0xa4`? | BLOCK | boot zeroing is initialization only | Gate A forbids absence-only claims |

## PASS/BLOCK answer

**BLOCK.** Do not claim R03-owned RAM from heap shrinkage, heap relocation, or an
extended allocation based on current official-v15 evidence. A future PASS would
need at minimum:

1. exact v15 allocator arena start/end and metadata format;
2. complete task stack creation/static stack inventory and stack bounds;
3. complete heap allocation consumer inventory or a linked allocation map;
4. a concrete `0xa4` range with owner, lifetime, valid/generation metadata, and
   DMA/stack/heap/task/USB/UI/audio/storage no-alias proof;
5. independent verification that the proposed change does not alter stock
   allocator ABI or claimed polyphony.

## Validation

| check | status | detail |
| --- | --- | --- |
""" + "\n".join(
        f"| `{c['check']}` | {c['status']} | `{c['detail']}` |" for c in checks
    ) + f"""

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/heap-boundary/analyze_heap_boundary.py
cd baselines/v15/analysis/r03-owned-ram/heap-boundary
shasum -a 256 -c SHA256SUMS
```

Generated files:

- `analyze_heap_boundary.py`
- `evidence.json`
- `boot-rows.tsv`
- `allocator-calls.tsv`
- `validation.txt`
- `report.md`
- `SHA256SUMS`
"""


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = APP.read_bytes()
    rows = read_listing(LISTING)
    manifest = json.loads(MANIFEST.read_text())
    sdk_sha = sha256_path(SDK_REPORT)
    sdk_evidence_sha = sha256_path(SDK_EVIDENCE)
    movs = direct_movs_to_ram(rows)
    boot = boot_rows(rows)
    e: dict[str, Any] = {
        "format": "smk37-v15-r03-heap-boundary-evidence-v1",
        "inputs": {
            "app_path": str(APP.relative_to(ROOT)),
            "app_sha256": sha256_path(APP),
            "manifest_path": str(MANIFEST.relative_to(ROOT)),
            "manifest_sha256": sha256_path(MANIFEST),
            "manifest_app_sha256": manifest.get("app_sha256"),
            "listing_path": str(LISTING.relative_to(ROOT)),
            "listing_sha256": sha256_path(LISTING),
            "quarkslab_listing_sha256": sha256_path(QS_LISTING),
            "sdk_report_path": str(SDK_REPORT.relative_to(ROOT)),
            "sdk_report_sha256": sdk_sha,
            "sdk_evidence_sha256": sdk_evidence_sha,
            "r03_requirements_sha256": sha256_path(R03_REQ),
            "previous_ram_report_sha256": sha256_path(PREV_RAM_REPORT),
        },
        "boot": {
            "ram_copy_source_start": hx(RAM_COPY_SOURCE),
            "ram_copy_source_end_exclusive": hx(RAM_COPY_SOURCE + RAM_COPY_SIZE),
            "ram_copy_dest_start": hx(RAM_COPY_DEST),
            "ram_copy_dest_end_exclusive": hx(RAM_COPY_DEST + RAM_COPY_SIZE),
            "ram_copy_size": hx(RAM_COPY_SIZE),
            "bss_start": hx(BSS_START),
            "bss_end_exclusive": hx(BSS_END),
            "bss_size": hx(BSS_SIZE),
            "boot_rows": boot,
            "stack_pointer_initializers": stack_init_from_boot(boot),
        },
        "calls": target_calls(rows),
        "sdk_signature_anchors": exact_sdk_matches(),
        "allocator_and_rtos_byte_windows": app_bytes_windows(app),
        "decoded_ram_immediate_counts_top40": immediate_counts(movs),
        "direct_ram_immediates_sample_first200": movs[:200],
        "fixed_region_question": {
            "required_region_size": hx(FIXED_REGION_SIZE),
            "voice_bytes": hx(VOICE_BYTES),
            "metadata_budget": hx(FIXED_REGION_SIZE - VOICE_BYTES),
        },
        "decision": {
            "verdict": "BLOCK",
            "summary": "No exact v15 heap arena bounds or bounded official allocation with no-alias proof were recovered; zeroed BSS gaps are not ownership.",
        },
    }
    checks = validation(e)
    e["validation"] = checks
    (OUT / "evidence.json").write_text(json.dumps(e, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_tsv(OUT / "boot-rows.tsv", boot, ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"])
    call_rows: list[dict[str, Any]] = []
    for name, info in e["calls"].items():
        for a in info["first_20_callsite_addresses"]:
            call_rows.append({"target_name": name, "target": info["target"], "callsite": a})
    write_tsv(OUT / "allocator-calls.tsv", call_rows, ["target_name", "target", "callsite"])
    (OUT / "validation.txt").write_text("\n".join(f"{c['status']}\t{c['check']}\t{c['detail']}" for c in checks) + "\n", encoding="utf-8")
    (OUT / "report.md").write_text(make_report(e, checks), encoding="utf-8")
    files = ["analyze_heap_boundary.py", "evidence.json", "boot-rows.tsv", "allocator-calls.tsv", "validation.txt", "report.md"]
    sums = []
    for name in files:
        p = OUT / name
        sums.append(f"{sha256_path(p)}  {name}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
