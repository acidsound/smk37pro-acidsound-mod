#!/usr/bin/env python3
"""Official-v15-only SysEx RAM reservation audit around 0x01c37030.

Read-only extractor. It consumes official v15 app/package, v15 Quarkslab and
Kagaimiq listings, and existing v15 analysis artifacts. It writes evidence under
this directory only. It does not patch, flash, contact a device, or use v12 data.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
BASE = 0x02000000
APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
QUARK = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
KAGA = LISTING_DIR / "kagaimiq-patched-exhaustive-listing.tsv.gz"
REQ = ROOT / "baselines/v15/analysis/r03-owned-ram/requirements.md"
SYSEX_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md"
SYSEX_JSON = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/sysex_staging_trace.json"
RAM_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md"
PERSIST_REPORT = ROOT / "baselines/v15/analysis/ui-preflash/followup/persistence-direction.md"

EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quarkslab_exhaustive_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kagaimiq_patched_exhaustive_sha256": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

OBJ = 0x01C33260
STAGE_BASE = 0x01C37030
STAGE_OFF = 0x0FA0
STAGE = STAGE_BASE + STAGE_OFF
STAGE_LEN = 0x1000
STAGE_END = STAGE + STAGE_LEN
VOICE_LEN = 0x9C
PROPOSED_RESERVE_LEN = 0xA4
PROPOSED_START = STAGE
PROPOSED_END = PROPOSED_START + PROPOSED_RESERVE_LEN

# Rows that form the complete decoded-code direct reference set for 0x01c37030
# in both Quarkslab and Kagaimiq exhaustive listings.
DIRECT_BASE_ROWS = [0x02008B7E, 0x0201BED2, 0x0201C2DE, 0x0201E3FC, 0x02025528]

RANGES = {
    "init_audio_structure_02008ae0": (0x02008AE0, 0x02008C9A),
    "queue_writer_a_0201be96": (0x0201BE96, 0x0201BF18),
    "queue_writer_b_0201c2a2": (0x0201C2A2, 0x0201C324),
    "queue_consumer_in_ui_task_020274a6": (0x020274A6, 0x020274EA),
    "sysex_handler_complete_and_segmented_0201e3ee": (0x0201E3EE, 0x0201E596),
    "sysex_handler_large_bulk_0201e4a6": (0x0201E4A6, 0x0201E538),
    "default_load_storage_path_0202553c": (0x0202553C, 0x020255AA),
    "save_current_path_02026d9e": (0x02026D9E, 0x02026DD0),
}

KEY_ROWS = [
    0x02008B7E, 0x02008B86, 0x02008B8E, 0x02008B90, 0x02008BA8,
    0x0201BED2, 0x0201BED8, 0x0201BEE2, 0x0201BEEC,
    0x0201C2DE, 0x0201C2E4, 0x0201C2EE, 0x0201C2F8,
    0x0201E3FC, 0x0201E448, 0x0201E456, 0x0201E468,
    0x0201E488, 0x0201E494, 0x0201E49C,
    0x0201E4B8, 0x0201E4BC, 0x0201E4C2, 0x0201E4CE, 0x0201E4D6, 0x0201E4EC,
    0x0201E51C, 0x0201E524, 0x0201E52C,
    0x0201E580, 0x0201E58C,
    0x02025528, 0x02025564, 0x02025568, 0x0202556E, 0x020255A6,
    0x02026DA6, 0x02026DAC,
    0x020274C2,
]

PATCH_SITES = [
    {"address": 0x0201E448, "row": "add r8,r6,#0xfa0", "reason": "complete one-shot single-voice staging destination"},
    {"address": 0x0201E488, "row": "add r6,r6,#0xfa0", "reason": "segmented-final single-voice staging base"},
    {"address": 0x0201E4C2, "row": "add r0,r0,#0xfa0", "reason": "large/final bulk staging destination plus accumulated offset"},
    {"address": 0x0201E4D6, "row": "movz r1,#0xfa0", "reason": "large bulk checksum/read loop base offset"},
    {"address": 0x0201E524, "row": "add r0,r0,#0xfa0", "reason": "large/intermediate chunk staging destination"},
    {"address": 0x0201E580, "row": "add r0,r6,#0xfa0", "reason": "initial segmented single-voice staging destination"},
    {"address": 0x02025564, "row": "add r0,r10,#0xfa0", "reason": "default-load selected-bank 0x1000 source buffer"},
    {"address": 0x02025568, "row": "movz r2,#0x1000", "reason": "default-load selected-bank source length if attempting to shrink/split"},
    {"address": 0x0201E4B8, "row": "movz r1,#0x1002", "reason": "large bulk final accumulated length if attempting to shrink/split"},
    {"address": 0x0201E4EC, "row": "jne r0,#0x1000", "reason": "large bulk checksum loop count if attempting to shrink/split"},
    {"address": 0x0201E51C, "row": "ja r5,#0xfff", "reason": "large bulk maximum accumulated byte bound if attempting to shrink/split"},
]


def hx(v: int, width: int = 8) -> str:
    return f"0x{v:0{width}x}"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_out(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def line(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"])


def rows_between(rows: list[dict[str, str]], lo: int, hi: int) -> list[dict[str, str]]:
    return [row_out(r) for r in rows if lo <= addr(r) <= hi]


def raw_xrefs(blob: bytes, values: dict[str, int]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in values.items():
        pat = struct.pack("<I", value)
        refs: list[str] = []
        pos = 0
        while True:
            found = blob.find(pat, pos)
            if found < 0:
                break
            refs.append(hx(BASE + found))
            pos = found + 1
        out[name] = {"value": hx(value), "count": len(refs), "refs": refs}
    return out


def overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def make_writer_set(rows_by_addr: dict[int, dict[str, str]]) -> list[dict[str, Any]]:
    return [
        {
            "id": "audio_init_dynamic_blocks",
            "mode": "writer",
            "range_or_formula": "0x01c37030 + r4*0x3c8 + 0xb10 + *(0x01c33260+0x390+r4*4) for 0x1a words, plus byte fields at +0xb8f and pointer fields at +0xb78/+0x2df*4",
            "rows": [row_out(rows_by_addr[a]) for a in [0x02008B7E, 0x02008B86, 0x02008B8E, 0x02008B90, 0x02008BA8] if a in rows_by_addr],
            "overlaps_proposed_0xa4": "not statically closed; dynamic r4/offset owner prevents free-slice proof",
            "notes": "This is a containing-object writer, not a SysEx-only allocator. It proves 0x01c37030 belongs to shared official runtime state.",
        },
        {
            "id": "usb_task_queue_writer_a",
            "mode": "writer",
            "range_or_formula": "0x01c37030 + 4*(uint16_t)(0x01c33260+0x9e), capped/incremented as a 0x100-word queue in decoded rows; bounded object 0x01c37030..0x01c37430 exclusive if the stock index invariant holds",
            "rows": [row_out(rows_by_addr[a]) for a in [0x0201BED2, 0x0201BED8, 0x0201BEE2, 0x0201BEEC] if a in rows_by_addr],
            "overlaps_proposed_0xa4": False,
            "notes": "Uses lockset/csync around queue update. It shares the same base constant but writes below the SysEx 0xfa0 staging offset.",
        },
        {
            "id": "usb_task_queue_writer_b",
            "mode": "writer",
            "range_or_formula": "same 0x100-word queue as writer_a: 0x01c37030..0x01c37430 exclusive under stock index invariant",
            "rows": [row_out(rows_by_addr[a]) for a in [0x0201C2DE, 0x0201C2E4, 0x0201C2EE, 0x0201C2F8] if a in rows_by_addr],
            "overlaps_proposed_0xa4": False,
            "notes": "Second producer for the same queue. The consumer reads with 0x020274c2 `lw r6,[r10+r1<<2]`.",
        },
        {
            "id": "complete_single_voice_sysex",
            "mode": "writer_then_packer_consumer",
            "range_or_formula": f"{hx(STAGE)}..{hx(STAGE + 0x9D)} for accepted 0xa3-byte host message, first 0x9c bytes consumed by packer; terminal F7 lands at +0x9c",
            "rows": [row_out(rows_by_addr[a]) for a in [0x0201E3FC, 0x0201E448, 0x0201E456, 0x0201E468] if a in rows_by_addr],
            "overlaps_proposed_0xa4": overlaps(STAGE, STAGE + 0x9D, PROPOSED_START, PROPOSED_END),
            "notes": "One-shot accepted single-voice bulk path.",
        },
        {
            "id": "segmented_single_voice_sysex",
            "mode": "writer_then_packer_consumer",
            "range_or_formula": f"{hx(STAGE)} + accumulated offset, final accepts offset+len == 0x9e and calls packer on {hx(STAGE)}",
            "rows": [row_out(rows_by_addr[a]) for a in [0x0201E488, 0x0201E494, 0x0201E49C, 0x0201E580, 0x0201E58C] if a in rows_by_addr],
            "overlaps_proposed_0xa4": True,
            "notes": "Initial and final segmented paths write the same staging base.",
        },
        {
            "id": "large_bulk_sysex_stage",
            "mode": "writer_and_checksum_reader",
            "range_or_formula": f"contiguous {hex(STAGE_LEN)} bytes: {hx(STAGE)}..{hx(STAGE_END)}; final accumulated length compare is 0x1002 and checksum loop count is 0x1000",
            "rows": [row_out(rows_by_addr[a]) for a in [0x0201E4B8, 0x0201E4BC, 0x0201E4C2, 0x0201E4CE, 0x0201E4D6, 0x0201E4EC, 0x0201E51C, 0x0201E524, 0x0201E52C] if a in rows_by_addr],
            "overlaps_proposed_0xa4": overlaps(STAGE, STAGE_END, PROPOSED_START, PROPOSED_END),
            "notes": "This is the explicit bound that makes the proposed 0xa4 slice non-reservable without relocating/splitting a 4 KiB stock object.",
        },
        {
            "id": "default_load_selected_bank_block",
            "mode": "stock_storage_consumer_of_stage",
            "range_or_formula": f"0x02004b02 source {hx(STAGE)}..{hx(STAGE_END)}, len 0x1000, destination *(0x01c33260+0x160)+bank*0x1000",
            "rows": [row_out(rows_by_addr[a]) for a in [0x02025528, 0x02025564, 0x02025568, 0x0202556E, 0x020255A6] if a in rows_by_addr],
            "overlaps_proposed_0xa4": overlaps(STAGE, STAGE_END, PROPOSED_START, PROPOSED_END),
            "notes": "Persistence-direction evidence identifies 0x02004b02 as RAM -> storage. This path is not a writer to RAM, but stock behavior requires the slice to contain valid bank-image bytes.",
        },
        {
            "id": "stock_save_current_path",
            "mode": "stock_save_packer_caller_not_stage_writer",
            "range_or_formula": "SAVE writes 0x01c33260+0x1a14 for 0xa3 to storage and calls 0x0201e13e(current); it does not use 0x01c37fd0 but constrains hook strategy",
            "rows": [row_out(rows_by_addr[a]) for a in [0x02026DA6, 0x02026DAC] if a in rows_by_addr],
            "overlaps_proposed_0xa4": False,
            "notes": "Hooking 0x0201e13e globally would affect SAVE. Stock SAVE calls ignore 0x02004b02 return in the decoded path.",
        },
    ]


def write_tsv(writer_set: list[dict[str, Any]]) -> None:
    with (OUT / "writer_set.tsv").open("w", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["id", "mode", "range_or_formula", "overlaps_proposed_0xa4", "notes"])
        for item in writer_set:
            w.writerow([item["id"], item["mode"], item["range_or_formula"], item["overlaps_proposed_0xa4"], item["notes"]])


def validate(e: dict[str, Any]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def check(name: str, cond: bool, detail: str) -> None:
        checks.append({"status": "PASS" if cond else "FAIL", "name": name, "detail": detail})

    check("official-v15-app-sha256", e["sha256"]["app"] == EXPECTED["app_sha256"], e["sha256"]["app"])
    check("official-v15-package-sha256", e["sha256"]["package"] == EXPECTED["package_sha256"], e["sha256"]["package"])
    check("quarkslab-listing-sha256", e["sha256"]["quarkslab_exhaustive"] == EXPECTED["quarkslab_exhaustive_sha256"], e["sha256"]["quarkslab_exhaustive"])
    check("kagaimiq-listing-sha256", e["sha256"]["kagaimiq_patched_exhaustive"] == EXPECTED["kagaimiq_patched_exhaustive_sha256"], e["sha256"]["kagaimiq_patched_exhaustive"])
    check("stage-arithmetic", STAGE_BASE + STAGE_OFF == STAGE, f"{hx(STAGE_BASE)}+0x{STAGE_OFF:x}={hx(STAGE)}")
    check("stage-bound", STAGE + STAGE_LEN == STAGE_END, f"{hx(STAGE)}+0x1000={hx(STAGE_END)}")
    check("proposed-slice-bound", PROPOSED_START + PROPOSED_RESERVE_LEN == PROPOSED_END, f"{hx(PROPOSED_START)}+0xa4={hx(PROPOSED_END)}")
    check("proposed-inside-stage", STAGE <= PROPOSED_START and PROPOSED_END <= STAGE_END, f"{hx(PROPOSED_START)}..{hx(PROPOSED_END)} inside {hx(STAGE)}..{hx(STAGE_END)}")
    check("raw-base-xrefs", e["raw_xrefs"]["stage_base_0x01c37030"]["count"] == 6, json.dumps(e["raw_xrefs"]["stage_base_0x01c37030"]))
    check("no-direct-stage-immediate", e["raw_xrefs"]["stage_0x01c37fd0"]["count"] == 0, json.dumps(e["raw_xrefs"]["stage_0x01c37fd0"]))
    check("quark-decoded-base-refs", e["decoded_direct_base_refs"]["quarkslab"] == [hx(a) for a in DIRECT_BASE_ROWS], json.dumps(e["decoded_direct_base_refs"]["quarkslab"]))
    check("kagaimiq-decoded-base-refs", e["decoded_direct_base_refs"]["kagaimiq"] == [hx(a) for a in DIRECT_BASE_ROWS], json.dumps(e["decoded_direct_base_refs"]["kagaimiq"]))
    overlapping = {x["id"] for x in e["writer_set"] if x["overlaps_proposed_0xa4"] is True}
    check("overlap-set-complete-for-hard-blockers", {"complete_single_voice_sysex", "segmented_single_voice_sysex", "large_bulk_sysex_stage", "default_load_selected_bank_block"} <= overlapping, json.dumps(sorted(overlapping)))
    check("decision-block", e["decision"]["status"] == "BLOCK", e["decision"]["status"])
    check("v12-excluded", all("v12" not in p.lower() for p in e["scope"]["inputs"]), json.dumps(e["scope"]["inputs"]))
    failed = [c for c in checks if c["status"] != "PASS"]
    if failed:
        raise SystemExit("validation failed: " + json.dumps(failed, ensure_ascii=False))
    return checks


def make_report(e: dict[str, Any]) -> str:
    shas = e["sha256"]
    lines: list[str] = []
    lines.append("# R03 SysEx RAM reservation audit for official v15")
    lines.append("")
    lines.append("Scope: exact official v15 only. This pass reads the official v15 app/package, v15 Quarkslab/Kagaimiq listings, R03 requirements, prior SysEx-staging evidence, RAM-ownership evidence, and persistence-direction evidence. It performs no patching, flashing, device access, or v12-derived reasoning.")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("**BLOCK.** The `0x01c37030` containing object cannot provide an explicitly reserved `0xa4` slice at `0x01c37fd0..0x01c38074` by merely patching known bounds/destinations. The exact SysEx/default-load staging subobject is the contiguous 4 KiB range `0x01c37fd0..0x01c38fd0`, and the proposed slice is inside that live stock range.")
    lines.append("")
    lines.append("A reservation would need a new proven 4 KiB replacement staging/bank-image buffer, or split-copy/checksum/storage logic that preserves all stock paths. No such destination allocation, executable body, or concurrency proof is present in the official-v15 static evidence. Therefore this is not a PASSable R03 owned-RAM candidate.")
    lines.append("")
    lines.append("## SHA gates")
    lines.append("")
    lines.append(f"- app: `{shas['app']}`")
    lines.append(f"- official package: `{shas['package']}`")
    lines.append(f"- Quarkslab exhaustive listing: `{shas['quarkslab_exhaustive']}`")
    lines.append(f"- Kagaimiq exhaustive listing: `{shas['kagaimiq_patched_exhaustive']}`")
    lines.append("")
    lines.append("## Exact bounds")
    lines.append("")
    lines.append("| object/range | exact bound | basis | decision |")
    lines.append("| --- | --- | --- | --- |")
    lines.append("| Containing direct base | `0x01c37030` | Five decoded code references in both listings plus one raw data occurrence. It is shared by queue, init/audio, SysEx staging, and UI/default-load storage paths. | No closed allocation end proven for the containing object. Not ownable by absence-of-xrefs. |")
    lines.append("| Queue subobject | `0x01c37030..0x01c37430` under stock 0x100-word index invariant | `0x0201bed8` and `0x0201c2e4` store words at `base+idx*4`; `0x020274c2` consumes from the same lower queue. | Does not overlap the proposed slice, but proves the base is shared with USB/task queue state. |")
    lines.append("| SysEx/default-load staging subobject | `0x01c37fd0..0x01c38fd0` | `0x01c37030+0xfa0`; large bulk final length is `0x1002`, checksum loop is `0x1000`, default-load writes the same `0x1000` source to storage. | Overlaps and owns the whole proposed slice. |")
    lines.append("| Proposed R03 slice | `0x01c37fd0..0x01c38074` (`0xa4` bytes) | First `0xa4` bytes of the staging subobject. | BLOCK. It is not free and cannot host durable valid/generation metadata. |")
    lines.append("")
    lines.append("Boot zeroing of `0x01c099d4..0x01c4651c` initializes the broad RAM span, but zero-on-boot is not an allocation owner. It does not reserve a subrange for R03.")
    lines.append("")
    lines.append("## Complete decoded writer/consumer set for `0x01c37030` direct-code users")
    lines.append("")
    lines.append("Both exhaustive listings decode the same direct-code references: `0x02008b7e`, `0x0201bed2`, `0x0201c2de`, `0x0201e3fc`, `0x02025528`. The app also contains one raw data occurrence at `0x0208fe66`, not a decoded writer row.")
    lines.append("")
    lines.append("| id | mode | bound/formula | proposed-slice overlap |")
    lines.append("| --- | --- | --- | --- |")
    for item in e["writer_set"]:
        lines.append(f"| `{item['id']}` | {item['mode']} | {item['range_or_formula']} | `{item['overlaps_proposed_0xa4']}` |")
    lines.append("")
    lines.append("`writer_set.tsv` contains the same inventory in machine-readable form. `evidence.json` contains the supporting rows for each item.")
    lines.append("")
    lines.append("## Required patches if attempting reservation")
    lines.append("")
    lines.append("A valid reservation cannot be claimed by only proving that a future patch would avoid the first `0xa4` bytes. At minimum, every stock producer/consumer below would need a destination or bound rewrite, plus a proven replacement allocation and code budget:")
    lines.append("")
    lines.append("| address | current row | why relevant |")
    lines.append("| --- | --- | --- |")
    for p in e["required_patch_sites_for_any_attempt"]:
        lines.append(f"| `{p['address']}` | `{p['row']}` | {p['reason']} |")
    lines.append("")
    lines.append("This list is not a safe patch plan. It is the minimum static set proving why the reservation is currently BLOCKED. The lower queue refs at `0x0201bed2/0x0201c2de/0x020274c2` also show that a blind global change of `0x01c37030` would corrupt unrelated USB/task queue state.")
    lines.append("")
    lines.append("## Scenario review")
    lines.append("")
    lines.append("- One-shot single voice: accepted `F0 43 00 00 01 1B + 0x9c + F7` writes `len-6 = 0x9d` bytes at `0x01c37fd0`; the packer consumes the first `0x9c`. This directly overlaps `0x01c37fd0..0x01c3806d`.")
    lines.append("- Segmented single voice: initial and final paths use the same `+0xfa0` base, accumulated length state at `obj+0x9c`, and final packer call. It overlaps the same proposed slice.")
    lines.append("- Larger bulk: official path accepts/checksums a contiguous `0x1000` bytes at `0x01c37fd0..0x01c38fd0`. The proposed `0xa4` slice is at the start of that object, so shrink/split would change stock large-bulk semantics unless all length, checksum, and copy logic is redesigned.")
    lines.append("- USB/task concurrency: decoded queue producers use lock/csync around the lower `0x01c37030` queue, but no lock, valid bit, or generation field protects the staging area. Later supported SysEx can rewrite the proposed slice between Note On and Note Off.")
    lines.append("- Stock SAVE/default-load: SAVE itself uses current snapshot and calls `0x0201e13e`, so global packer hooks would affect SAVE. The default-load path consumes `0x01c37fd0..0x01c38fd0` as a `0x1000` RAM source for storage at `0x0202556e`; reservation would corrupt or require relocating that bank-image source. Decoded SAVE/storage paths ignore the `0/len` return before marking saved in the reviewed evidence, so error-prone split writes are unacceptable without deeper proof.")
    lines.append("")
    lines.append("## PASS/BLOCK matrix")
    lines.append("")
    lines.append("| Requirement | Result | Evidence |")
    lines.append("| --- | --- | --- |")
    lines.append("| Exact start/end/alignment for proposed slice | PASS | `0x01c37fd0..0x01c38074`, 16-byte aligned start. |")
    lines.append("| Exact owning allocation for slice | BLOCK | The exact stock staging allocation is larger: `0x01c37fd0..0x01c38fd0`. The proposed slice is owned by stock SysEx/default-load staging. |")
    lines.append("| Complete known static writer/consumer set | PASS for decoded direct-code refs | Five decoded base refs plus raw xref inventory are recorded. Dynamic init formulas are not closed enough to prove free space. |")
    lines.append("| One-shot and segmented safety | BLOCK | Both write/use the proposed slice. |")
    lines.append("| Larger bulk safety | BLOCK | Contiguous 4 KiB stage requires the slice. |")
    lines.append("| USB/task concurrency | BLOCK | No valid/generation/lock for the proposed stage slice; lower queue shows unrelated shared ownership of same base. |")
    lines.append("| Stock SAVE/default-load behavior | BLOCK | Default-load consumes the same 4 KiB source; packer hooks affect SAVE. |")
    lines.append("| Explicit reservation by patching all bounds/destinations | BLOCK | Requires relocation/splitting of stock 4 KiB staging, checksum, default-load storage source, and a new proven allocation. Not present. |")
    lines.append("")
    lines.append("## Validation")
    lines.append("")
    lines.append("| check | status | detail |")
    lines.append("| --- | --- | --- |")
    for c in e["validation"]:
        detail = c["detail"].replace("|", "\\|")
        lines.append(f"| {c['name']} | {c['status']} | `{detail}` |")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/r03-owned-ram/sysex-reservation/analyze_sysex_reservation.py")
    lines.append("cd baselines/v15/analysis/r03-owned-ram/sysex-reservation")
    lines.append("shasum -a 256 -c SHA256SUMS")
    lines.append("```")
    lines.append("")
    lines.append("Generated files: `analyze_sysex_reservation.py`, `evidence.json`, `writer_set.tsv`, `validation.txt`, `report.md`, `SHA256SUMS`.")
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    app = APP.read_bytes()
    quark_rows = read_listing(QUARK)
    kaga_rows = read_listing(KAGA)
    rows_by_addr = {addr(r): r for r in quark_rows}
    kaga_by_addr = {addr(r): r for r in kaga_rows}

    decoded_quark = [addr(r) for r in quark_rows if "1c37030" in r["text"].lower()]
    decoded_kaga = [addr(r) for r in kaga_rows if "1c37030" in r["text"].lower()]
    writer_set = make_writer_set(rows_by_addr)

    e: dict[str, Any] = {
        "scope": {
            "constraints": ["official v15 only", "read-only", "no patch", "no flash", "no device access", "no v12-derived reasoning"],
            "inputs": [str(p.relative_to(ROOT)) for p in [APP, PACKAGE, QUARK, KAGA, REQ, SYSEX_REPORT, SYSEX_JSON, RAM_REPORT, PERSIST_REPORT]],
        },
        "sha256": {
            "app": sha256(APP),
            "package": sha256(PACKAGE),
            "quarkslab_exhaustive": sha256(QUARK),
            "kagaimiq_patched_exhaustive": sha256(KAGA),
            "r03_requirements": sha256(REQ),
            "sysex_staging_report": sha256(SYSEX_REPORT),
            "sysex_staging_trace": sha256(SYSEX_JSON),
            "ram_ownership_report": sha256(RAM_REPORT),
            "persistence_direction_report": sha256(PERSIST_REPORT),
        },
        "constants": {
            "containing_base": hx(STAGE_BASE),
            "stage_offset": hex(STAGE_OFF),
            "stage_start": hx(STAGE),
            "stage_end_exclusive": hx(STAGE_END),
            "stage_length": hex(STAGE_LEN),
            "voice_length": hex(VOICE_LEN),
            "proposed_reservation_start": hx(PROPOSED_START),
            "proposed_reservation_end_exclusive": hx(PROPOSED_END),
            "proposed_reservation_length": hex(PROPOSED_RESERVE_LEN),
        },
        "raw_xrefs": raw_xrefs(app, {
            "stage_base_0x01c37030": STAGE_BASE,
            "stage_0x01c37fd0": STAGE,
            "queue_end_0x01c37430": STAGE_BASE + 0x400,
            "proposed_end_0x01c38074": PROPOSED_END,
            "stage_end_0x01c38fd0": STAGE_END,
        }),
        "decoded_direct_base_refs": {
            "quarkslab": [hx(a) for a in decoded_quark],
            "kagaimiq": [hx(a) for a in decoded_kaga],
        },
        "key_rows": {hx(a): row_out(rows_by_addr[a]) for a in KEY_ROWS if a in rows_by_addr},
        "ranges": {name: rows_between(quark_rows, lo, hi) for name, (lo, hi) in RANGES.items()},
        "writer_set": writer_set,
        "required_patch_sites_for_any_attempt": [
            {"address": hx(p["address"]), "row": p["row"], "reason": p["reason"], "listing_row": row_out(rows_by_addr[p["address"]]) if p["address"] in rows_by_addr else None}
            for p in PATCH_SITES
        ],
        "decision": {
            "status": "BLOCK",
            "summary": "The proposed 0xa4 slice at 0x01c37fd0..0x01c38074 is inside the explicit 0x1000-byte stock SysEx/default-load staging object 0x01c37fd0..0x01c38fd0. Reserving it requires relocation/splitting plus a new proven 4 KiB allocation and concurrency proof, not just inferred free RAM.",
        },
    }
    e["validation"] = validate(e)

    write_tsv(writer_set)
    (OUT / "evidence.json").write_text(json.dumps(e, indent=2, sort_keys=True) + "\n")
    (OUT / "validation.txt").write_text("\n".join(f"{c['status']}\t{c['name']}\t{c['detail']}" for c in e["validation"]) + "\n")
    (OUT / "report.md").write_text(make_report(e))

    files = ["analyze_sysex_reservation.py", "evidence.json", "writer_set.tsv", "validation.txt", "report.md"]
    with (OUT / "SHA256SUMS").open("w") as f:
        for name in files:
            f.write(f"{sha256(OUT / name)}  {name}\n")


if __name__ == "__main__":
    main()
