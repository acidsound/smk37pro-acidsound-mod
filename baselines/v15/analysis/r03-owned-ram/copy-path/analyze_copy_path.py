#!/usr/bin/env python3
"""R03 owned-RAM copy-path design evidence for official v15.

Read-only analysis. It consumes only exact official v15 artifacts and existing v15
Quarkslab/Kagaimiq listings. It does not patch, flash, access a device, choose a
RAM cave, or choose an executable cave.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent

APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
QUARK = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
KAGA = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"
REQ = ROOT / "baselines/v15/analysis/r03-owned-ram/requirements.md"
SYSEX_JSON = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/sysex_staging_trace.json"
RUNTIME_JSON = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/runtime_source_trace.json"
R02_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R02/app-manifest.json"

EXPECTED = {
    "app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quark": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kaga": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

ADDR = {
    "dispatcher": 0x0201C5EC,
    "note_off_memcpy_call": 0x0201C63E,
    "note_on_memcpy_call": 0x0201C67C,
    "sysex_handler": 0x0201E254,
    "one_shot_packer_call": 0x0201E468,
    "one_shot_reload_call": 0x0201E46C,
    "segmented_packer_call": 0x0201E49C,
    "segmented_reload_call": 0x0201E4A0,
    "save_packer_call": 0x02026DAC,
    "stock_packer_start": 0x0201E13E,
    "stock_packer_end_exclusive": 0x0201E252,
    "loader": 0x02005660,
    "memcpy": 0x02048CCE,
    "stage": 0x01C37FD0,
    "stage_base": 0x01C37030,
    "current_source": 0x01C34C74,
}

REQUIRED_ROWS = {
    0x0201E3EE: "lb.z r0,[r7 + 0x206]",
    0x0201E3F8: "lb.z r0,[r7 + 0x104]",
    0x0201E448: "add r8,r6,#0xfa0",
    0x0201E456: "call 0x02048cce",
    0x0201E462: "jne r0,#0xf7",
    0x0201E466: "mov r0,r8",
    0x0201E468: "call 0x0201e13e",
    0x0201E46C: "call 0x02005660",
    0x0201E484: "jne r5,#0x9e",
    0x0201E494: "call 0x02048cce",
    0x0201E49C: "call 0x0201e13e",
    0x0201E4A0: "call 0x02005660",
    0x0201E580: "add r0,r6,#0xfa0",
    0x0201E58C: "call 0x02048cce",
    0x0201E634: "sb r1,[r0 + r2]",
    0x0201E644: "call 0x0201c5ec",
    0x0201C63A: "mov r2,#0x9c",
    0x0201C63E: "call 0x02048cce",
    0x0201C678: "mov r2,#0x9c",
    0x0201C67C: "call 0x02048cce",
    0x0201E236: "call 0x02004b02",
    0x02026DAC: "call 0x0201e13e",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hx(v: int) -> str:
    return f"0x{v:08x}"


def load_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_slim(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ("address", "bytes", "mnemonic", "text", "flow_type", "function")}


def call_xrefs(rows: list[dict[str, str]], target: int) -> list[dict[str, str]]:
    needle = hx(target)
    return [row_slim(r) for r in rows if r["mnemonic"] == "call" and needle in r["text"].lower()]


def checks(evidence: dict[str, Any]) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []

    def check(name: str, ok: bool, detail: str) -> None:
        out.append({"status": "PASS" if ok else "FAIL", "name": name, "detail": detail})

    shas = evidence["sha256"]
    for key, expected in EXPECTED.items():
        check(f"sha256-{key}", shas[key] == expected, shas[key])

    req_text = REQ.read_text()
    check("requirements-read", "R03 owned-RAM checkpoint requirements" in req_text, str(REQ))
    check("official-v15-only", "v12" not in " ".join(evidence["inputs"]).lower(), json.dumps(evidence["inputs"]))

    rows = evidence["required_rows"]
    for addr, expected_text in REQUIRED_ROWS.items():
        row = rows.get(hx(addr))
        check(f"row-{hx(addr)}", row is not None and expected_text in row["text"], row["text"] if row else "missing")

    packer = {int(r["address"], 16) for r in evidence["callers"]["stock_packer_0x0201e13e"]}
    check("stock-packer-callers-exact", packer == {0x0201E468, 0x0201E49C, 0x02026DAC}, ",".join(hx(x) for x in sorted(packer)))

    loader = {int(r["address"], 16) for r in evidence["callers"]["loader_0x02005660"]}
    check("loader-callers-include-stock-sysex-reloads", {0x0201E46C, 0x0201E4A0} <= loader, ",".join(hx(x) for x in sorted(loader)))

    dispatcher = {int(r["address"], 16) for r in evidence["callers"]["dispatcher_0x0201c5ec"]}
    check("dispatcher-callers-exact", dispatcher == {0x0201C736, 0x0201E644}, ",".join(hx(x) for x in sorted(dispatcher)))

    r02 = evidence["r02_live_primitive"]
    check("r02-wrapper-length-known", r02["wrapper_bytes"] == 36 and r02["entry"] == "0x0201e13e" and r02["end"] == "0x0201e162", json.dumps(r02))
    check("stage-arithmetic", ADDR["stage_base"] + 0x0FA0 == ADDR["stage"], f"{hx(ADDR['stage_base'])}+0x0fa0={hx(ADDR['stage'])}")

    decision = evidence["decision"]
    check("gate-a-block-recorded", decision["gate_a_owned_ram"] == "BLOCK", decision["gate_a_owned_ram_reason"])
    check("placement-block-recorded", decision["code_placement"] == "BLOCK", decision["code_placement_reason"])
    check("no-patch-output", not any(p.suffix == ".bin" or p.suffix == ".fwsc" for p in OUT.iterdir()), "copy-path directory contains no firmware binary/package outputs")
    return out


def make_report(e: dict[str, Any], check_rows: list[dict[str, str]]) -> str:
    lines: list[str] = []
    lines += [
        "# R03 owned-RAM copy-path design, official v15",
        "",
        "Decision: **BLOCK**.",
        "",
        "This report designs the smallest producer/consumer shape that would satisfy the R03 copy-path requirements, then blocks it because two mandatory proofs are missing: no owned RAM destination is proven, and no executable placement is proven that preserves stock `0x0201e13e` SAVE/SysEx behavior. No cave, patch, flash package, or device operation is chosen.",
        "",
        "## Scope and gates",
        "",
        f"- Requirements read: `{REQ.relative_to(ROOT)}`.",
        "- Inputs are exact official v15 only.",
        f"- app SHA-256: `{e['sha256']['app']}`.",
        f"- FWSC SHA-256: `{e['sha256']['package']}`.",
        f"- Quarkslab listing SHA-256: `{e['sha256']['quark']}`.",
        f"- Kagaimiq listing SHA-256: `{e['sha256']['kaga']}`.",
        "- No v12, M08, R01d boot-hook, arbitrary SysEx fuzzing, PCM, UI, persistence, flashing, or device access was used.",
        "",
        "## Smallest viable design contract, not patch-ready",
        "",
        "### Producer",
        "",
        "Patch concept if and only if a later review proves owned RAM and executable placement:",
        "",
        "1. Replace only the one-shot complete-product call at `0x0201e468` with a call to a producer wrapper. Do not use a boot hook.",
        "2. At entry, the stock handler has already copied `message+6` to `0x01c37030+0x0fa0 == 0x01c37fd0`, verified final `F7`, and put `r0 = 0x01c37fd0`.",
        "3. The wrapper additionally requires `r9 == 0xa3` so only `F0 43 00 00 01 1B` + exactly `0x9c` payload bytes + `F7` publishes Ch10-owned data.",
        "4. If `active_count != 0`, do not copy and do not publish. Still tail-call or call/return through stock `0x0201e13e` so stock product SysEx behavior is preserved.",
        "5. If `active_count == 0`, copy exactly `0x9c` bytes from staging to owned destination, then increment `generation`, then set `valid = 1`. Publication occurs only after the copy completes.",
        "6. Call stock `0x0201e13e` after the R03 copy decision, then return to the existing `0x0201e46c` stock reload path. This preserves stock product storage/reload semantics.",
        "7. Leave the segmented-final product caller `0x0201e49c` and SAVE caller `0x02026dac` stock for the minimal R03 contract. Segmented/partial/unsupported packets therefore do not publish Ch10-owned data and continue stock behavior.",
        "",
        "### Owned destination metadata required by Gate A",
        "",
        "Minimum layout that must be proven before a Flash candidate exists:",
        "",
        "| Offset | Size | Meaning | Publication rule |",
        "|---:|---:|---|---|",
        "| `+0x00` | `0x9c` | immutable Ch10 voice source | written before metadata publish |",
        "| `+0x9c` | `1` | `valid` | `0` at reset, `1` only after full copy |",
        "| `+0x9d` | `1` | `active_count` | increment/decrement only on accepted Ch10 Note On/Off wrapper path |",
        "| `+0x9e` | `2` | reserved/alignment | zero or reserved |",
        "| `+0xa0` | `4` | `generation` | increment after copy, before valid publish |",
        "",
        "Required alignment: at least 4-byte aligned so generation can be read/written atomically under the firmware's normal aligned word conventions. Required span: `0xa4` bytes minimum. This report does not assign a start/end address because doing so from absence of xrefs would violate Gate A.",
        "",
        "### Consumer",
        "",
        "1. Redirect both dispatcher copy callsites, not Note On alone: Note Off `0x0201c63e`, Note On `0x0201c67c`.",
        "2. Preserve stock ABI: wrapper receives `r0 = per-voice destination`, `r1 = stock current source`, `r2 = 0x9c`, and `r9 = MIDI channel nibble`; non-Ch10 calls `memcpy(r0, r1, 0x9c)` unchanged.",
        "3. For Ch10 with `valid == 1`, call `memcpy(r0, owned_voice, 0x9c)`. For invalid state, fall back to stock Ch10 source or suppress deterministically. This report chooses stock fallback for smallest allocator-neutral behavior, but this remains a design choice to review before patching.",
        "4. Use separate Note On and Note Off entrypoints or callsite identity so `active_count` can be incremented on accepted Ch10 Note On and decremented after accepted Ch10 Note Off. This prohibits producer generation changes while a Ch10 note is active.",
        "5. Do not alter the voice allocator, claimed polyphony, or Ch1 path.",
        "",
        "## Proven callsites and callers",
        "",
        "| Function / callsite | Evidence | R03 implication |",
        "|---|---|---|",
        "| `0x0201e468` | one-shot product path calls stock packer after staging and `F7` gate | only plausible minimal producer hook |",
        "| `0x0201e49c` | segmented-final path calls stock packer after accumulated length/F7 checks | leave stock in minimal R03 so partial/segmented does not publish |",
        "| `0x02026dac` | UI SAVE path calls stock packer | must remain stock or SAVE is regressed |",
        "| `0x0201e46c`, `0x0201e4a0` | post-packer stock reload calls | preserved when producer wrapper calls stock packer |",
        "| `0x0201c63e` | Note Off `memcpy` call with `r2 = 0x9c` | redirect with same source rule as Note On |",
        "| `0x0201c67c` | Note On `memcpy` call with `r2 = 0x9c` | redirect with same source rule as Note Off |",
        "| `0x0201c736`, `0x0201e644` | only static callers of dispatcher in listing | caller inventory for hot consumer path |",
        "",
        "Stock `0x0201e13e` callers from the listing:",
        "",
    ]
    for row in e["callers"]["stock_packer_0x0201e13e"]:
        lines.append(f"- `{row['address']}` `{row['bytes']}` {row['text']} ({row['function']})")
    lines += [
        "",
        "Loader `0x02005660` callers from the listing:",
        "",
    ]
    for row in e["callers"]["loader_0x02005660"]:
        lines.append(f"- `{row['address']}` `{row['bytes']}` {row['text']} ({row['function']})")
    lines += [
        "",
        "Dispatcher `0x0201c5ec` callers from the listing:",
        "",
    ]
    for row in e["callers"]["dispatcher_0x0201c5ec"]:
        lines.append(f"- `{row['address']}` `{row['bytes']}` {row['text']} ({row['function']})")

    lines += [
        "",
        "## ABI proof",
        "",
        "- SysEx producer wrapper entry at `0x0201e468`: official rows show `r0 = r8 = 0x01c37fd0` immediately before the stock packer call. The handler length register `r9` is still live in this basic block because it is used to compute the copied length at `0x0201e44e` and the last-byte check at `0x0201e45c..0x0201e460`. The wrapper must preserve callee-saved registers and call stock `0x0201e13e(r0=stage)` after the R03 copy decision.",
        "- Stock packer ABI: `0x0201e13e` takes `r0 = expanded source`, packs into a stack `0x80` buffer, then calls `0x02004b02` with `r0=packed80`, `r1=selected persistent slot`, `r2=0x80`. This is why replacing it, as R02 did, regresses SAVE unless every caller is handled.",
        "- Consumer wrapper ABI: prior live-booted R01/R02 primitive proves a compact wrapper can preserve `r0`, branch on `r9 == 9`, set `r1` to an alternate source only for Ch10, set `r2 = 0x9c`, call `0x02048cce`, and return through the original dispatcher control flow. R03 must add valid/active metadata around the same source-selection primitive.",
        "",
        "## Instruction budget and placement",
        "",
        f"- Proven compact consumer wrapper budget from R02 manifest: `{e['r02_live_primitive']['wrapper_bytes']}` bytes for source selection plus `memcpy`, occupying `0x0201e13e..0x0201e162` in R02. That budget excludes R03 valid/generation/active-count checks.",
        "- R03 producer wrapper cannot use `0x0201e13e` if stock SAVE/SysEx is to be preserved, because `0x0201e13e..0x0201e252` is the stock packer body and has three direct callers including SAVE.",
        f"- Stock packer occupied span used for placement accounting: `0x0201e13e..0x0201e252` (`0x{ADDR['stock_packer_end_exclusive'] - ADDR['stock_packer_start']:x}` bytes, end-exclusive).",
        "- No alternate executable cave is proven by these inputs. A later candidate must provide exact start/end, original bytes, all static callers/fallthroughs, execute permissions, sector impact, and a relocation story if any stock code is displaced.",
        "- Therefore exact R03 instruction budget cannot be closed to a placed binary. Treat the producer plus R03-augmented consumer as design-only until placement is proven independently.",
        "",
        "## Gate decisions",
        "",
        "| Gate | Decision | Reason |",
        "|---|---|---|",
        "| A owned RAM | **BLOCK** | No exact owned start/end/lifetime/reader/writer inventory is proven. Using `0x01c37fd0` is disallowed because it is transient SysEx staging. Any other address would be an unsupported cave guess. |",
        "| B producer | **BLOCK** | The callsite and ABI are proven, but destination and placement are not. The safe repeated-packet policy is defined as no-publish while `active_count != 0`. |",
        "| C consumer/generation | **BLOCK** | Matched Note On/Off callsites are proven and the active-count policy is defined, but metadata storage is not. |",
        "| D offline artifact safety | **BLOCK** | No changed-address manifest, sector inventory, rollback package, deterministic build, or uploader tests were produced because no patch candidate is approved. |",
        "| E live pass | **BLOCK** | No device access was performed or requested. |",
        "",
        "## Malformed, partial, repeated, and unsupported behavior",
        "",
        "- Malformed or unsupported messages: no R03 publish because the wrapper is reached only from the accepted one-shot callsite and additionally checks `r9 == 0xa3`. Stock behavior continues through stock packer/handler paths where applicable.",
        "- Partial/segmented product packets: no R03 publish in the minimal design because `0x0201e49c` is left stock. This is intentionally conservative.",
        "- Repeated exact one-shot product packet with no active Ch10 note: copy, increment generation, set valid, then preserve stock pack/reload.",
        "- Repeated exact one-shot product packet while Ch10 active: do not copy, do not increment generation, do not clear valid, and still preserve stock pack/reload. Ch10 remains on the old generation until all Ch10 notes are off.",
        "",
        "## Validation output",
        "",
        "```text",
    ]
    for row in check_rows:
        lines.append(f"{row['status']} {row['name']}: {row['detail']}")
    lines += ["```", ""]
    return "\n".join(lines)


def main() -> int:
    rows = load_listing(QUARK)
    by_addr = {row_addr(r): r for r in rows}
    r02_manifest = json.loads(R02_MANIFEST.read_text())
    sysex_trace = json.loads(SYSEX_JSON.read_text())
    runtime_trace = json.loads(RUNTIME_JSON.read_text())

    required_rows = {hx(a): row_slim(by_addr[a]) for a in REQUIRED_ROWS if a in by_addr}
    evidence: dict[str, Any] = {
        "format": "smk37-v15-r03-owned-ram-copy-path-evidence-v1",
        "decision": {
            "overall": "BLOCK",
            "gate_a_owned_ram": "BLOCK",
            "gate_a_owned_ram_reason": "No exact owned RAM start/end, owner, lifetime, initialization, and complete alias exclusion are proven. 0x01c37fd0 is transient staging, not owned R03 storage.",
            "code_placement": "BLOCK",
            "code_placement_reason": "The only live-booted compact wrapper placement reused 0x0201e13e, but preserving stock SAVE/SysEx requires retaining the stock packer body and all three callers. No alternate executable cave is proven.",
            "patch_candidate": False,
        },
        "inputs": [str(p.relative_to(ROOT)) for p in (APP, PACKAGE, QUARK, KAGA, REQ, SYSEX_JSON, RUNTIME_JSON, R02_MANIFEST)],
        "sha256": {
            "app": sha256(APP),
            "package": sha256(PACKAGE),
            "quark": sha256(QUARK),
            "kaga": sha256(KAGA),
        },
        "constants": {k: hx(v) for k, v in ADDR.items()},
        "required_rows": required_rows,
        "callers": {
            "stock_packer_0x0201e13e": call_xrefs(rows, ADDR["stock_packer_start"]),
            "loader_0x02005660": call_xrefs(rows, ADDR["loader"]),
            "dispatcher_0x0201c5ec": call_xrefs(rows, ADDR["dispatcher"]),
            "memcpy_0x02048cce_count": len(call_xrefs(rows, ADDR["memcpy"])),
        },
        "stock_traces_reused": {
            "sysex_staging_decision": sysex_trace.get("verdict", "see sysex_staging_trace/report"),
            "runtime_current_source_alias": runtime_trace.get("summary", {}).get("current_source_alias", "0x01c33260+0x1a14 == 0x01c34c74"),
        },
        "minimal_design": {
            "producer_hook": hx(ADDR["one_shot_packer_call"]),
            "producer_input": "r0 == 0x01c37fd0 after official complete-message acceptance; additionally require r9 == 0xa3",
            "producer_copy": "memcpy(owned_voice, 0x01c37fd0, 0x9c); publish generation and valid only after copy",
            "stock_preservation": "call stock 0x0201e13e after copy/reject decision, then return to existing 0x0201e46c reload",
            "consumer_hooks": [hx(ADDR["note_off_memcpy_call"]), hx(ADDR["note_on_memcpy_call"])],
            "consumer_rule": "r9 != 9 stock memcpy; r9 == 9 and valid use owned source for both Note On and Note Off",
            "generation_policy": "producer rejects publication while active_count != 0",
            "ram_minimum_bytes": 0xA4,
            "ram_candidate": None,
        },
        "r02_live_primitive": {
            "entry": r02_manifest["layout"]["entry"],
            "end": r02_manifest["layout"]["end"],
            "wrapper_bytes": int(r02_manifest["layout"]["end"], 16) - int(r02_manifest["layout"]["entry"], 16),
            "note_on_memcpy": r02_manifest["design"]["note_on_memcpy"],
            "note_off_memcpy": r02_manifest["design"]["note_off_memcpy"],
            "source_length": r02_manifest["design"]["source_length"],
        },
    }

    check_rows = checks(evidence)
    evidence["checks"] = check_rows
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (OUT / "validation.txt").write_text("\n".join(f"{c['status']} {c['name']}: {c['detail']}" for c in check_rows) + "\n")
    (OUT / "report.md").write_text(make_report(evidence, check_rows))
    print("R03 owned-RAM copy-path: BLOCK")
    print(f"wrote {(OUT / 'report.md').relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
