#!/usr/bin/env python3
"""Official-v15 product SysEx + stock UI/SAVE raw-prefix seed investigation.

Offline-only. This script reads already-committed v15 images/reports/listings, emits
machine-readable evidence, and validates the conclusion. It never opens USB, MIDI,
/dev, PhysicalDrive, or any live transport.
"""
from __future__ import annotations

import hashlib
import json
import stat
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
STORAGE_REPORT = ROOT / "baselines/v15/analysis/persistence-s2/storage/report.md"
STORAGE_ROWS = ROOT / "baselines/v15/analysis/persistence-s2/storage/exact-rows.tsv"
SYSEX_REPORT = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/report.md"
S1C7_EVIDENCE = ROOT / "baselines/v15/analysis/flash-candidates/S1C7-current-set-helper-checkpoint/evidence.json"

FORMAT = "smk37-v15-official-ui-save-prefix-seed-investigation-v1"
APP_SHA = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
FWSC_SHA = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
APP_BASE = 0x02000000
RAW_TABLE_REL = 0x4000
PACKED_BANK_STRIDE = 0x1000
PACKED_RECORD_STRIDE = 0x80
RAW_RECORD_STRIDE = 0xA3
PREFIX_LEN = 0x9C
RAW_TABLE_PHYS_BASE = 0x0F8000
BANK_D = 3
PRESET_COUNT = 16
RECORD_BASE = BANK_D * 32

# Exact bytes are from existing official-v15 reports and are rechecked against
# build/v15-official-app.bin by file offset = runtime_va - 0x02000000.
EXACT_BYTES = {
    0x0201E468: ("bfea69fe", "complete product SysEx calls 0x0201e13e packer"),
    0x0201E46C: ("bfeaf838", "complete product SysEx reloads selected record through 0x02005660"),
    0x0201E49C: ("bfea4ffe", "segmented-final product SysEx calls 0x0201e13e packer"),
    0x0201E4A0: ("bfeade38", "segmented-final product SysEx reloads selected record through 0x02005660"),
    0x0201E606: ("89f8180e", "single-parameter path requires exact 7-byte message"),
    0x0201E622: ("42f0141a", "single-parameter writer targets current snapshot base +0x1a14"),
    0x0201E630: ("0017", "single-parameter index is truncated to 8 bits"),
    0x0201E634: ("d8ee0112", "single-parameter writer stores msg[5] to current snapshot index"),
    0x0201E236: ("bfea6434", "stock packer writes selected packed 0x80 record through 0x02004b02"),
    0x02026DA6: ("beeaacee", "stock SAVE writes selected raw 0xa3 record through 0x02004b02"),
    0x02026DAC: ("bfeac7b9", "stock SAVE calls stock packer after raw write"),
    0x02026DD0: ("beea97ee", "stock SAVE flushes flag table through 0x02004b02"),
}

REQUIRED_REPORT_SNIPPETS = {
    STORAGE_REPORT: [
        "0x02026da6`: write `g+0x1a14`, length `0xa3`, to `*(g+0x160)+0x4000+index*0xa3`",
        "Both `0x02004b02` returns are ignored.",
        "bank   = g[0x3a4]",
        "preset = g[0x3a0 + bank]",
        "It returns early for `bank > 3` or `preset > 31`.",
        "Raw record `index` is:",
    ],
    SYSEX_REPORT: [
        "F0 43 00 00 01 1B` + `0x9c` bytes + `F7`",
        "`0x0201e468` and `0x0201e49c` are the two official v15 calls from the SysEx handler to `0x0201e13e`.",
        "`0x0201e13e` consumes the expanded single-voice source pointer in `r0`, packs it into a stack `0x80` buffer",
        "Single-parameter writer",
        "`0201e634\td8ee0112\tsb\tsb r1,[r0 + r2]",
    ],
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(ok: bool, msg: str, checks: list[str]) -> None:
    if not ok:
        checks.append("FAIL\t" + msg)
        raise SystemExit("FAIL: " + msg)
    checks.append("PASS\t" + msg)


def reject_nonregular(path: Path, label: str) -> None:
    raw = str(path)
    lower = raw.lower()
    forbidden = ("/dev/", "\\\\.\\", "\\\\.\\physicaldrive")
    if lower.startswith(forbidden):
        raise SystemExit(f"FAIL: {label} is a device path, refusing offline analysis: {raw}")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit(f"FAIL: {label} is not a regular file: {raw}")


def app_slice(app: bytes, va: int, size: int) -> bytes:
    off = va - APP_BASE
    if off < 0 or off + size > len(app):
        raise SystemExit(f"FAIL: VA 0x{va:08x} outside app")
    return app[off:off + size]


def record(slot: int) -> dict[str, Any]:
    index = RECORD_BASE + slot
    raw_rel = RAW_TABLE_REL + index * RAW_RECORD_STRIDE
    raw_phys = RAW_TABLE_PHYS_BASE + index * RAW_RECORD_STRIDE
    packed_rel = BANK_D * PACKED_BANK_STRIDE + slot * PACKED_RECORD_STRIDE
    return {
        "slot": slot,
        "bank": "D",
        "bank_zero_based": BANK_D,
        "preset_display": slot + 1,
        "preset_zero_based": slot,
        "record_index": index,
        "raw_storage_rel": f"0x{raw_rel:04x}",
        "raw_physical_offset": f"0x{raw_phys:06x}",
        "raw_prefix_range": f"0x{raw_phys:06x}..0x{raw_phys + PREFIX_LEN - 1:06x}",
        "raw_tail_range": f"0x{raw_phys + PREFIX_LEN:06x}..0x{raw_phys + RAW_RECORD_STRIDE - 1:06x}",
        "packed_storage_rel": f"0x{packed_rel:04x}",
    }


def build_evidence() -> dict[str, Any]:
    checks: list[str] = []
    for path, label in [(APP, "official app"), (OFFICIAL_FWSC, "official fwsc"), (STORAGE_REPORT, "storage report"), (SYSEX_REPORT, "sysex report")]:
        reject_nonregular(path, label)
        req(path.exists(), f"{label} exists", checks)

    app = APP.read_bytes()
    req(sha(app) == APP_SHA, "official v15 app SHA-256", checks)
    req(shaf(OFFICIAL_FWSC) == FWSC_SHA, "official v15 FWSC SHA-256", checks)

    byte_rows = []
    for va, (hex_bytes, meaning) in EXACT_BYTES.items():
        expected = bytes.fromhex(hex_bytes)
        actual = app_slice(app, va, len(expected))
        req(actual == expected, f"exact official bytes 0x{va:08x} {hex_bytes} {meaning}", checks)
        byte_rows.append({"va": f"0x{va:08x}", "bytes": hex_bytes, "meaning": meaning})

    report_refs: dict[str, Any] = {}
    for path, snippets in REQUIRED_REPORT_SNIPPETS.items():
        text = path.read_text(encoding="utf-8")
        rel = str(path.relative_to(ROOT))
        report_refs[rel] = {"sha256": sha(text.encode()), "snippets": snippets}
        for snippet in snippets:
            req(snippet in text, f"report snippet present in {rel}: {snippet[:72]}", checks)

    rows_text = STORAGE_ROWS.read_text(encoding="utf-8")
    for va in ["02005662", "02026da6", "02026dac", "02026dd0"]:
        req(va in rows_text, f"storage exact-rows.tsv contains {va}", checks)

    records = [record(slot) for slot in range(PRESET_COUNT)]
    req(records[0]["record_index"] == 96 and records[-1]["record_index"] == 111, "Bank D slots 1..16 map to records 96..111", checks)
    req(records[0]["raw_storage_rel"] == "0x7d20", "record 96 raw storage offset 0x7d20", checks)
    req(records[-1]["raw_physical_offset"] == "0x0fc6ad", "record 111 physical start 0x0fc6ad", checks)

    s1c7_summary: dict[str, Any] | None = None
    if S1C7_EVIDENCE.exists():
        ev = json.loads(S1C7_EVIDENCE.read_text(encoding="utf-8"))
        seed = ev.get("persistent_seed_prefixes") or ev.get("seed_prefixes") or []
        # The exact key has changed across candidates, so keep this as advisory.
        s1c7_summary = {
            "path": str(S1C7_EVIDENCE.relative_to(ROOT)),
            "sha256": shaf(S1C7_EVIDENCE),
            "prefix_count_hint": len(seed) if isinstance(seed, list) else None,
        }

    evidence = {
        "format": FORMAT,
        "date": "2026-08-04",
        "scope": "official v15 product SysEx and stock UI/SAVE only; no v12 assumptions; no live device access",
        "decision": "BLOCK_DETERMINISTIC_SAFE_HOST_SENDER",
        "normal_firmware_capability": {
            "product_sysex_alone": "does not write raw 0xa3 records; it stages 0x9c bytes, calls 0x0201e13e, writes selected packed 0x80 record, then reloads selected current snapshot",
            "single_parameter_sysex": "can write one byte in current snapshot, including index 0x9b via F0 43 10 01 1B dd F7, but it is volatile until SAVE",
            "stock_ui_save": "can write the selected raw 0xa3 record and therefore can write record indices 96..111 when Bank D presets 1..16 are selected",
            "combined_manual_sequence": "Bank D slot selected on UI -> product SysEx -> optional single-parameter 0x9b playback-note byte -> press stock SAVE before changing selection should seed the raw prefix through normal firmware",
        },
        "blockers": [
            "No exact v15 host command or SysEx path is proven to set or read back g+0x3a4/g+0x3a0 selected Bank D slot; selection is stock UI state.",
            "No exact v15 host command is proven to invoke stock SAVE or confirm its storage writes; SAVE is a UI handler path.",
            "Stock SAVE ignores both 0x02004b02 returns, so the normal UI/SAVED path is not a guarded write/readback protocol.",
            "No normal-firmware readback path is proven for raw prefixes 96..111 after SAVE; existing readback validators require external dump artifacts.",
            "Therefore a deterministic unattended host sender would risk writing the wrong selected slot or reporting success after a failed/partial SAVE.",
        ],
        "safe_sender_emitted": False,
        "non_sender_reason": "The only normal-firmware raw writer is stock UI SAVE, which is not host-addressed or readback-guarded in the exact v15 evidence.",
        "exact_bytes": byte_rows,
        "records_96_111": records,
        "report_references": report_refs,
        "s1c7_reference": s1c7_summary,
        "checks": checks,
    }
    return evidence


def render_report(ev: dict[str, Any]) -> str:
    rec0 = ev["records_96_111"][0]
    rec15 = ev["records_96_111"][-1]
    lines = [
        "# Official v15 UI/SAVE raw-prefix seed investigation",
        "",
        "Date: 2026-08-04  ",
        "Scope: exact official v15 code paths, existing v15 traces, and offline files only. No device, USB, MIDI, flash, recovery, or v12-derived assumptions were used.",
        "",
        "## Decision",
        "",
        "**BLOCK for a deterministic safe host sender.**",
        "",
        "Exact official v15 code shows that stock UI `SAVE` can write the selected raw `0xa3` record. Since Bank D presets 1..16 map to raw records `96..111`, normal firmware can write those record prefixes if the user manually selects each Bank D slot and presses stock `SAVE` after the host has materialized the desired current snapshot.",
        "",
        "However, this is not a safe unattended host protocol. Product SysEx alone writes only the selected packed `0x80` record. The raw writer is the stock UI SAVE handler, its selection and invocation are not proven host-addressable, and its storage-write return values are ignored. No sender was emitted.",
        "",
        "## Capability split",
        "",
        "| Path | Exact v15 result | Raw prefix 96..111 effect |",
        "|---|---|---|",
        "| Product single-voice SysEx | `0x0201e468/0x0201e49c -> 0x0201e13e`, then `0x0201e46c/0x0201e4a0 -> 0x02005660` | No direct raw write. It writes the selected packed `0x80` slot through `0x02004b02`. |",
        "| Single-parameter SysEx | `F0 43 10 aa bb dd F7`; `0x0201e634` stores `dd` to `g+0x1a14+(((aa<<7)+bb)&0xff)` | Volatile current-snapshot byte write only. For byte `0x9b`, use `aa=0x01`, `bb=0x1b`. |",
        "| Stock UI SAVE | `0x02026da6` writes `g+0x1a14`, length `0xa3`, to `*(g+0x160)+0x4000+(bank*32+preset)*0xa3` | Yes, if Bank D slot is selected. It writes the full raw record, including prefix and preserved/current tail. |",
        "",
        "A manual normal-firmware sequence that should seed one prefix is therefore: select Bank D preset N on the stock UI, send official product SysEx to materialize bytes `0x00..0x9a`, send single-parameter byte `0x9b` if the S1C7 Playback Note byte must differ from the stock normalized value, then press stock SAVE before any selection change.",
        "",
        "## Exact xrefs and bytes checked",
        "",
        "| VA | Bytes | Meaning |",
        "|---|---|---|",
    ]
    for row in ev["exact_bytes"]:
        lines.append(f"| `{row['va']}` | `{row['bytes']}` | {row['meaning']} |")
    lines += [
        "",
        "## Record mapping for S1C7 prefixes",
        "",
        f"Bank D preset 1 maps to record `{rec0['record_index']}`, storage `{rec0['raw_storage_rel']}`, physical `{rec0['raw_physical_offset']}`.",
        f"Bank D preset 16 maps to record `{rec15['record_index']}`, storage `{rec15['raw_storage_rel']}`, physical `{rec15['raw_physical_offset']}`.",
        "",
        "| Slot | Bank/Preset | Record | Raw storage rel | Physical prefix range | Packed rel side effect |",
        "|---:|---|---:|---:|---|---:|",
    ]
    for r in ev["records_96_111"]:
        lines.append(f"| {r['slot']} | {r['bank']} {r['preset_display']} | {r['record_index']} | `{r['raw_storage_rel']}` | `{r['raw_prefix_range']}` | `{r['packed_storage_rel']}` |")
    lines += [
        "",
        "## Blockers to a safe host sender",
        "",
    ]
    for b in ev["blockers"]:
        lines.append(f"- {b}")
    lines += [
        "",
        "## Reproduce",
        "",
        "```sh",
        "python3 baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed/analyze_official_ui_save_prefix_seed.py --check",
        "python3 baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed/validate.py",
        "(cd baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed && shasum -a 256 -c SHA256SUMS)",
        "```",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="rebuild and validate evidence/report/validation files")
    args = parser.parse_args()

    ev = build_evidence()
    report = render_report(ev)
    evidence_path = HERE / "evidence.json"
    report_path = HERE / "report.md"
    validation_path = HERE / "validation.txt"
    sums_path = HERE / "SHA256SUMS"

    evidence_text = json.dumps(ev, indent=2, sort_keys=True) + "\n"
    validation_text = "\n".join(ev["checks"] + ["RESULT\tPASS"]) + "\n"

    if args.check:
        req(evidence_path.read_text(encoding="utf-8") == evidence_text, "evidence.json byte-identical rebuild", ev["checks"])
        req(report_path.read_text(encoding="utf-8") == report, "report.md byte-identical rebuild", ev["checks"])
        req(validation_path.read_text(encoding="utf-8") == validation_text, "validation.txt byte-identical rebuild", ev["checks"])
        # Recompute SHA list after checking deterministic file content.
        expected_lines = []
        for name in ["analyze_official_ui_save_prefix_seed.py", "evidence.json", "report.md", "validate.py", "validation.txt"]:
            expected_lines.append(f"{shaf(HERE / name)}  {name}")
        req(sums_path.read_text(encoding="utf-8") == "\n".join(expected_lines) + "\n", "SHA256SUMS current", ev["checks"])
        print(validation_text, end="")
        print("PASS\tevidence.json byte-identical rebuild")
        print("PASS\treport.md byte-identical rebuild")
        print("PASS\tvalidation.txt byte-identical rebuild")
        print("PASS\tSHA256SUMS current")
        return

    evidence_path.write_text(evidence_text, encoding="utf-8")
    report_path.write_text(report, encoding="utf-8")
    validation_path.write_text(validation_text, encoding="utf-8")
    # validate.py may not exist on first generation; SHA256SUMS is finalized after writing validate.py.


if __name__ == "__main__":
    main()
