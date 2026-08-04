#!/usr/bin/env python3
"""Exact S1C5/S2 persistent-restore placement audit.

Read-only offline evidence generator. It does not emit firmware, FWSC, OTA,
rollback, host sender, or any device-access path.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FLASH = ROOT / "baselines/v15/analysis/flash-candidates"
ANALYSIS = ROOT / "baselines/v15/analysis"
S1C5 = FLASH / "S1C5-playback-register-return"
BASE = 0x02000000

INPUTS = {
    "s1c5_app": (S1C5 / "app.bin", "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189"),
    "s1c5_fwsc": (S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc", "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91"),
    "s1c5_live_validation": (S1C5 / "live-validation-20260804.md", "94fc5083ff1ce1061c474eba18a30ad3f10a277f85c84f6cee5a117c2593f152"),
    "s1c7_failure_report": (FLASH / "S1C7-live-failure-root-cause-20260804/report.md", "48ab1fd30abea5b81772a36cc13313241ec55c257f2c032545fedc3588811963"),
    "s1c8_manifest_report": (FLASH / "S1C8-manifest-gated-persistence-block/report.md", "77bfec1101546429560bf3c925392bf84acf15edb0e699b1bbc7628656cce94e"),
    "s2_default_report": (FLASH / "S2-persistent-default/report.md", "451150aadbde8ce9967ec53b165b145023b1d04870db1d92925a86f2948e4dba"),
    "s2_restore_report": (ANALYSIS / "persistence-s2/restore/report.md", "c9ce9d4da638790c7e2803a1e85133cedfb8a069204d81ddbdb1bc5eba32b7c1"),
    "save_cave_report": (ANALYSIS / "persistence-s2/save-cave-helper/report.md", "88f60a4abde79e3be6747a560cc22f6a037015ef62c081c110c8186788d649e5"),
    "ui_save_seed_report": (ANALYSIS / "persistence-s2/official-ui-save-prefix-seed/report.md", "004cd11a3d4f9e0f2d798427e77942253943cc9825df7d49e1fd7fe3fae04d8a"),
    "app_tail_report": (ANALYSIS / "r03-owned-ram/app-tail-placement/report.md", "036eca79c6258a9ffff9f493874058a1876cbbe92f2cd76c27d06efe2f2c105c"),
    "official_listing": (ANALYSIS / "quarkslab/results/quarkslab-exhaustive-listing.tsv.gz", "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"),
}

SEL_START = 0x0201E13E
SEL_END = 0x0201E196
PRODUCER_START = 0x0201E196
PRODUCER_END = 0x0201E252
OWNED_END = 0x0201E254
SAVE_PATCH = 0x02026D7A
SAVE_CAVE = 0x02026D80
SAVE_GOTO = 0x02026DA6
SAVE_DEAD_START = 0x02026DA8
SAVE_EXIT = 0x02026DD4
SAVE_EXIT_END = 0x02026DDE
READ_WRAPPER = 0x02004870
WRITE_WRAPPER = 0x02004B02
MEMCPY = 0x02048CCE
POST_STORAGE_CALL = 0x02005FA4
REVOKED_BOOT_CALL = 0x02005F9C
UI_RELOAD_CALL = 0x0202422E
DEFAULT_LOAD_CALL = 0x020255A6
APP_TAIL_START = 0x02096A34
APP_TAIL_END = 0x02096BB3

EXPECTED_S1C5 = {
    "selector_sha256": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "producer_sha256": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "producer_plus_tail_sha256": "53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4",
    "combined_sha256": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "save_branch_patch_old": "60ffff602a00",
    "save_branch_patch_new": "80f82b020016",
    "save_goto_bytes": "0496",
    "save_neutralized_call_bytes": "00000000",
    "read_wrapper_bytes": "7404241612164116518f90e80004442040165404",
    "write_wrapper_bytes": "7404241612164116519790e80004442040165404",
}


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def hx(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}x}"


def off(addr: int) -> int:
    return addr - BASE


def load_listing() -> list[dict[str, str]]:
    path = INPUTS["official_listing"][0]
    rows: list[dict[str, str]] = []
    with gzip.open(path, "rt", errors="replace") as f:
        header = next(f).rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == len(header):
                rows.append(dict(zip(header, parts)))
    return rows


def listing_gap_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    spans: list[tuple[int, int]] = []
    for r in rows:
        try:
            start = int(r["address"], 16)
            length = int(r["length"])
        except ValueError:
            continue
        spans.append((start, start + length))
    spans.sort()
    gaps: list[tuple[int, int, int]] = []
    cur = BASE
    for start, end in spans:
        if start > cur:
            gaps.append((cur, start, start - cur))
        if end > cur:
            cur = end
    top = sorted(gaps, key=lambda x: x[2], reverse=True)[:10]
    return {
        "coverage_end": hx(cur),
        "gap_count": len(gaps),
        "total_gap_bytes": sum(x[2] for x in gaps),
        "largest_gaps": [{"start": hx(s), "end_exclusive": hx(e), "bytes": n} for s, e, n in top],
        "decision": "NOT PROMOTED; exhaustive-listing holes/gaps are not exact dead-code ownership proof and may be data, alignment, indirect targets, or resources",
    }


def listing_row(rows: list[dict[str, str]], addr: int) -> dict[str, str]:
    h = f"{addr:08x}"
    for row in rows:
        if row["address"].lower() == h:
            return row
    raise SystemExit(f"FAIL: listing row {hx(addr)}")


def listing_text_hits(rows: list[dict[str, str]], term: str) -> list[dict[str, str]]:
    term_l = term.lower()
    return [r for r in rows if term_l in (r["text"] + " " + r["function"] + " " + r["mnemonic"]).lower()]


def listing_call_xrefs(rows: list[dict[str, str]], target: int) -> list[dict[str, Any]]:
    needle = hx(target)
    out = []
    for r in rows:
        if r["mnemonic"] == "call" and needle in r["text"]:
            out.append({"address": "0x" + r["address"], "bytes": r["bytes"], "length": int(r["length"]), "function": r["function"]})
    return out


def region(app: bytes, start: int, end: int) -> bytes:
    return app[off(start):off(end)]


def branch_reach(source: int, target: int) -> dict[str, Any]:
    disp = target - source
    call32_fits = -(1 << 31) <= disp < (1 << 31)
    local_jcc_fits = -512 <= (target - (source + 4)) <= 510
    same_0x20000_window = (source & ~0x1FFFF) == (target & ~0x1FFFF)
    return {
        "source": hx(source),
        "target": hx(target),
        "displacement_bytes": disp,
        "pi32_call32_6_byte_fits": call32_fits,
        "local_jcc_2_or_4_byte_range_fits": local_jcc_fits,
        "short_call_4_byte_same_0x20000_window": same_0x20000_window,
    }


def gate_inputs() -> dict[str, Any]:
    gates = {}
    for name, (path, expected) in INPUTS.items():
        actual = shaf(path)
        req(actual == expected, f"input hash {name}")
        gates[name] = {"path": rel(path), "sha256": actual, "status": "PASS"}
    return gates


def s1c5_identity(app: bytes) -> dict[str, Any]:
    selector = region(app, SEL_START, SEL_END)
    producer = region(app, PRODUCER_START, PRODUCER_END)
    combined = region(app, SEL_START, OWNED_END)
    req(sha(selector) == EXPECTED_S1C5["selector_sha256"], "exact S1C5 selector hash")
    req(sha(producer) == EXPECTED_S1C5["producer_sha256"], "exact S1C5 producer hash")
    req(sha(combined) == EXPECTED_S1C5["combined_sha256"], "exact S1C5 selector/producer/tail hash")
    return {
        "selector": {"start": hx(SEL_START), "end_exclusive": hx(SEL_END), "bytes": SEL_END - SEL_START, "sha256": sha(selector), "must_preserve_exact": True},
        "producer": {"start": hx(PRODUCER_START), "end_exclusive": hx(PRODUCER_END), "bytes": PRODUCER_END - PRODUCER_START, "sha256": sha(producer), "must_preserve_exact": True},
        "tail": {"start": hx(PRODUCER_END), "end_exclusive": hx(OWNED_END), "bytes": OWNED_END - PRODUCER_END, "useful_for_restore": False},
        "owned_window": {"start": hx(SEL_START), "end_exclusive": hx(OWNED_END), "bytes": OWNED_END - SEL_START, "free_bytes_preserving_exact_selector_and_producer": OWNED_END - PRODUCER_END},
        "decision": "BLOCK as an executable restore placement; only two tail bytes remain when the exact live S1C5 selector and producer are preserved",
    }


def dead_region_audit(app: bytes, rows: list[dict[str, str]]) -> dict[str, Any]:
    req(region(app, SAVE_PATCH, SAVE_CAVE).hex() == EXPECTED_S1C5["save_branch_patch_old"], "S1C5 SAVE branch original bytes")
    req(region(app, SAVE_GOTO, SAVE_GOTO + 2).hex() == EXPECTED_S1C5["save_goto_bytes"], "S1C5 goto at save write callsite")
    req(region(app, 0x02026DAC, 0x02026DB0).hex() == EXPECTED_S1C5["save_neutralized_call_bytes"], "S1C5 neutralized packer call")
    current_dead = SAVE_EXIT - SAVE_DEAD_START
    quarantined = SAVE_EXIT - SAVE_CAVE
    return {
        "audited_regions": [
            {
                "name": "current S1C5 SAVE tail dead after 0x02026da6 goto",
                "range": [hx(SAVE_DEAD_START), hx(SAVE_EXIT)],
                "bytes": current_dead,
                "evidence": "exact S1C5 has 0x02026da6 bytes 0496, a goto to 0x02026dd4; 0x02026dac packer call is neutralized to 00000000",
                "decision": "BLOCK for manifest/magic/CRC restore; 44 bytes cannot hold checked manifest read, CRC, 16-payload validation, RAM publication, and ABI repair",
            },
            {
                "name": "SAVE handler quarantined leaf after UI branch patch",
                "range": [hx(SAVE_CAVE), hx(SAVE_EXIT)],
                "bytes": quarantined,
                "required_patch": {"address": hx(SAVE_PATCH), "old_hex": EXPECTED_S1C5["save_branch_patch_old"], "new_hex": EXPECTED_S1C5["save_branch_patch_new"]},
                "decision": "PARTIAL only; 84 bytes can host a tiny leaf, but prior lower bounds still exclude positive CRC-gated restore/write semantics",
            },
            {
                "name": "stock local SAVE exit retained",
                "range": [hx(SAVE_EXIT), hx(SAVE_EXIT_END)],
                "bytes": SAVE_EXIT_END - SAVE_EXIT,
                "decision": "NOT A CAVE; must remain stock exit if SAVE handler is quarantined",
            },
            {
                "name": "app-area tail / cfg_tool.bin",
                "range": [hx(APP_TAIL_START), hx(APP_TAIL_END)],
                "bytes": APP_TAIL_END - APP_TAIL_START,
                "decision": "BLOCK; named JLFS cfg_tool.bin occupies the whole 383-byte apparent tail, preserving JLFS leaves 0 bytes",
            },
        ],
        "listing_gap_scan": listing_gap_summary(rows),
        "summary": "No exact audited dead region provides a sufficient executable body for manifest/magic/CRC-gated restore while keeping S1C5 selector/producer exact.",
    }


def helper_audit(app: bytes, rows: list[dict[str, str]]) -> dict[str, Any]:
    req(region(app, READ_WRAPPER, READ_WRAPPER + 0x14).hex() == EXPECTED_S1C5["read_wrapper_bytes"], "read wrapper bytes")
    req(region(app, WRITE_WRAPPER, WRITE_WRAPPER + 0x14).hex() == EXPECTED_S1C5["write_wrapper_bytes"], "write wrapper bytes")
    no_crc_hits = {term: len(listing_text_hits(rows, term)) for term in ["crc", "memcmp", "strcmp", "strncmp", "compare"]}
    req(all(v == 0 for v in no_crc_hits.values()), "no named CRC/compare helpers in exact listing text")
    read_xrefs = listing_call_xrefs(rows, READ_WRAPPER)
    write_xrefs = listing_call_xrefs(rows, WRITE_WRAPPER)
    memcpy_xrefs = listing_call_xrefs(rows, MEMCPY)
    return {
        "callable_helpers": [
            {"name": "read wrapper", "entry": hx(READ_WRAPPER), "bytes": 20, "exact_hex": EXPECTED_S1C5["read_wrapper_bytes"], "abi": "r0=dest, r1=storage_rel, r2=len; returns len only on complete success else 0", "xref_count_official_listing": len(read_xrefs), "decision": "CALLABLE but not a validity gate"},
            {"name": "write wrapper", "entry": hx(WRITE_WRAPPER), "bytes": 20, "exact_hex": EXPECTED_S1C5["write_wrapper_bytes"], "abi": "r0=src, r1=storage_rel, r2=len; returns len only on complete success else 0", "xref_count_official_listing": len(write_xrefs), "decision": "CALLABLE only with readback/compare/commit-last wrapper"},
            {"name": "memcpy", "entry": hx(MEMCPY), "abi": "stock memcpy; preserves only r6/r5/r4 in prior reviews", "xref_count_official_listing": len(memcpy_xrefs), "decision": "CALLABLE for copies, not a compare or CRC helper"},
        ],
        "missing_helpers": {
            "listing_text_search_counts": no_crc_hits,
            "crc32_or_crc16_runtime_abi": "BLOCK; no exact callable firmware CRC ABI was identified by the exhaustive-listing labels/text, and no compact in-place PI32 CRC implementation is proven",
            "memcmp_runtime_abi": "BLOCK; no exact callable memcmp/compare ABI was identified; magic compare would need hand-coded byte loads/branches and CRC still remains",
        },
        "xrefs": {"read_wrapper": read_xrefs, "write_wrapper": write_xrefs, "memcpy_count": len(memcpy_xrefs)},
    }


def cross_cave_and_cold_paths(rows: list[dict[str, str]]) -> dict[str, Any]:
    key_rows = {name: listing_row(rows, addr) for name, addr in {
        "revoked_boot_loader": REVOKED_BOOT_CALL,
        "post_storage_tail_call": POST_STORAGE_CALL,
        "ui_bank_preset_reload": UI_RELOAD_CALL,
        "default_load_reload": DEFAULT_LOAD_CALL,
    }.items()}
    return {
        "branch_reach": [
            {**branch_reach(0x0201E190, SAVE_CAVE), "known_encoding_from_prior_save_cave_audit": "80ffea8b0000"},
            {**branch_reach(0x0201E228, SAVE_CAVE), "known_encoding_from_prior_save_cave_audit": "80ff528b0000"},
            branch_reach(POST_STORAGE_CALL, SAVE_CAVE),
            branch_reach(UI_RELOAD_CALL, SAVE_CAVE),
            branch_reach(DEFAULT_LOAD_CALL, SAVE_CAVE),
            branch_reach(POST_STORAGE_CALL, APP_TAIL_START),
        ],
        "cold_ui_paths": [
            {"site": hx(REVOKED_BOOT_CALL), "listing": key_rows["revoked_boot_loader"], "decision": "REJECT; disproven/revoked S1C7/R01d-style early boot behavior must not be reused"},
            {"site": hx(POST_STORAGE_CALL), "listing": key_rows["post_storage_tail_call"], "decision": "BLOCK; syntactically after stock reads/loader, but pre-USB/live safety and wrapper placement are unproven and it must preserve 0x020057e0"},
            {"site": hx(UI_RELOAD_CALL), "listing": key_rows["ui_bank_preset_reload"], "decision": "BLOCK; user-action UI bank/preset reload, not autonomous restore, and repurposing would break stock UI behavior"},
            {"site": hx(DEFAULT_LOAD_CALL), "listing": key_rows["default_load_reload"], "decision": "BLOCK; conditional default-load/bank-block path with storage side effects, not an every-boot or side-effect-free restore hook"},
            {"site": hx(SAVE_CAVE), "decision": "PARTIAL; can be quarantined as an 84-byte leaf only after disabling the current UI SAVE body, but no caller/space for full manifest CRC restore exists"},
        ],
        "summary": "Branch reach is not the blocker for 6-byte call32. The blockers are exact S1C5 call insertion, insufficient quarantined bytes, missing CRC/compare ABI, and no approved lifecycle hook.",
    }


def architecture_decision() -> dict[str, Any]:
    return {
        "decision": "BLOCK",
        "candidate_built": False,
        "defensible_architecture": None,
        "rejected_split_call_architectures": [
            {"name": "exact selector/producer plus SAVE-cave restore leaf", "blocker": "no exact call insertion point remains without altering selector/producer or note hook ABI; 84-byte leaf cannot validate manifest CRCs and publish 16 slots"},
            {"name": "post-storage boot wrapper plus SAVE-cave body", "blocker": "0x02005fa4 has no live post-USB safety proof and still needs a wrapper preserving stock 0x020057e0 plus body placement beyond 84 bytes"},
            {"name": "relocated cold UI reload/default-load path", "blocker": "not autonomous or not side-effect-free; repurposing changes UI/default behavior and still lacks CRC/materializer placement"},
            {"name": "S1C7 not-ARMED helper reuse", "blocker": "explicitly rejected; S1C7 trusted full-length unseeded reads and gave invalid persistent fallback priority over exact S1C5 behavior"},
        ],
        "next_discriminator": "A minimal standalone PI32 manifest validator/materializer must be assembled and byte-counted against two explicit budgets: 84-byte quarantined SAVE leaf and a separately proved >=300-byte executable region. It must use 0x02004870 length checks, implement or call a proven CRC/compare routine, validate manifest first, publish RAM valid-last/ARMED-last, and leave exact S1C5 selector/producer bytes unchanged. Without that byte-level body and a safe lifecycle hook, no FWSC should be emitted.",
    }


def build_evidence() -> dict[str, Any]:
    gates = gate_inputs()
    app = INPUTS["s1c5_app"][0].read_bytes()
    rows = load_listing()
    return {
        "format": "smk37-v15-s2-restore-placement-audit-v1",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "fwsc_emitted": False},
        "basis": gates,
        "s1c5_identity": s1c5_identity(app),
        "dead_region_audit": dead_region_audit(app, rows),
        "helper_audit": helper_audit(app, rows),
        "cross_cave_and_cold_paths": cross_cave_and_cold_paths(rows),
        "architecture_decision": architecture_decision(),
    }


def render_report(ev: dict[str, Any]) -> str:
    ident = ev["s1c5_identity"]
    dead = ev["dead_region_audit"]
    helper = ev["helper_audit"]
    arch = ev["architecture_decision"]
    reach = ev["cross_cave_and_cold_paths"]
    rows = []
    for r in dead["audited_regions"]:
        rows.append(f"| {r['name']} | `{r['range'][0]}..{r['range'][1]}` | {r['bytes']} | {r['decision']} |")
    helper_rows = []
    for h in helper["callable_helpers"]:
        helper_rows.append(f"| {h['name']} | `{h['entry']}` | {h.get('bytes', '-')} | {h['xref_count_official_listing']} | {h['decision']} |")
    cold_rows = []
    for c in reach["cold_ui_paths"]:
        cold_rows.append(f"| `{c['site']}` | {c['decision']} |")
    return f"""# S2 restore placement audit: BLOCK

## Decision

**BLOCK.** No firmware candidate, FWSC, rollback bundle, exact OTA executable, or host/device writer is emitted.

The exact live S1C5 selector (`{ident['selector']['bytes']}` bytes, `{ident['selector']['sha256']}`) and producer (`{ident['producer']['bytes']}` bytes, `{ident['producer']['sha256']}`) are preserved as the controlling baseline. Preserving them leaves only `{ident['owned_window']['free_bytes_preserving_exact_selector_and_producer']}` tail bytes in the owned hot window. The audited split-call alternatives do not provide both a safe lifecycle hook and enough proven executable space for manifest/magic/CRC-gated persistent restore.

## Exact dead/cave region audit

| Region | Range | Bytes | Decision |
|---|---:|---:|---|
{chr(10).join(rows)}

Summary: {dead['summary']}

Exact official exhaustive-listing gap scan: `{dead['listing_gap_scan']['gap_count']}` gaps totaling `{dead['listing_gap_scan']['total_gap_bytes']}` bytes through coverage end `{dead['listing_gap_scan']['coverage_end']}`. Largest gap is `{dead['listing_gap_scan']['largest_gaps'][0]['start']}..{dead['listing_gap_scan']['largest_gaps'][0]['end_exclusive']}` ({dead['listing_gap_scan']['largest_gaps'][0]['bytes']} bytes). Decision: {dead['listing_gap_scan']['decision']}.

## Callable stock helper audit

| Helper | Entry | Bytes | Official listing call xrefs | Decision |
|---|---:|---:|---:|---|
{chr(10).join(helper_rows)}

Search counts in the exact official exhaustive listing for callable CRC/compare labels/text: `{helper['missing_helpers']['listing_text_search_counts']}`. Result: {helper['missing_helpers']['crc32_or_crc16_runtime_abi']}. {helper['missing_helpers']['memcmp_runtime_abi']}.

## Cross-cave reach and cold UI paths

6-byte `call32` reach to the SAVE cave is numerically possible, for example prior encodings `0x0201e190 -> 0x02026d80 = 80ffea8b0000` and `0x0201e228 -> 0x02026d80 = 80ff528b0000`. Reach is not sufficient because exact S1C5 has no hot-window call insertion budget.

| Site | Decision |
|---:|---|
{chr(10).join(cold_rows)}

Summary: {reach['summary']}

## Split-call architecture outcome

All audited split-call architectures remain blocked:

""" + "\n".join(f"- **{x['name']}**: {x['blocker']}" for x in arch["rejected_split_call_architectures"]) + f"""

Next discriminator: {arch['next_discriminator']}

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/restore-placement-audit/analyze_restore_placement.py --check
python3 baselines/v15/analysis/persistence-s2/restore-placement-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/restore-placement-audit && shasum -a 256 -c SHA256SUMS)
```
"""


def write_outputs(ev: dict[str, Any]) -> None:
    (HERE / "evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(render_report(ev), encoding="utf-8")
    (HERE / "README.md").write_text("# S2 restore placement audit\n\nOffline BLOCK evidence. Run `python3 analyze_restore_placement.py --check` and `python3 validate.py`.\n", encoding="utf-8")
    (HERE / "validation.txt").write_text("PASS exact S1C5 selector/producer identity\nPASS dead/cave/helper/cold-path audits\nBLOCK no safe manifest/magic/CRC-gated restore placement\n", encoding="utf-8")
    names = ["README.md", "analyze_restore_placement.py", "evidence.json", "report.md", "validate.py", "validation.txt"]
    sums = []
    for name in names:
        sums.append(f"{shaf(HERE / name)}  {name}")
    (HERE / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    ev = build_evidence()
    if args.check:
        req(ev["architecture_decision"]["decision"] == "BLOCK", "BLOCK decision")
        req(ev["s1c5_identity"]["owned_window"]["free_bytes_preserving_exact_selector_and_producer"] == 2, "2-byte tail")
        req(ev["dead_region_audit"]["audited_regions"][0]["bytes"] == 44, "current dead SAVE tail bytes")
        req(ev["dead_region_audit"]["audited_regions"][1]["bytes"] == 84, "quarantined SAVE cave bytes")
        req(ev["helper_audit"]["missing_helpers"]["listing_text_search_counts"] == {"crc": 0, "memcmp": 0, "strcmp": 0, "strncmp": 0, "compare": 0}, "no CRC/compare labels")
        print("PASS S2 restore placement audit checks")
        print("BLOCK no defensible manifest/magic/CRC-gated executable placement")
        return
    write_outputs(ev)
    print("S2 restore placement audit BLOCK; deterministic outputs rebuilt")


if __name__ == "__main__":
    main()
