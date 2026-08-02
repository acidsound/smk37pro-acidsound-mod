#!/usr/bin/env python3
"""Official v15 SysEx staging trace for RAM 0x01c37fd0.

Read-only extractor. It consumes the official v15 app plus the already generated
v15 Quarkslab/Kagaimiq TSV listings, then writes JSON/Markdown evidence under
this directory. It does not patch, flash, access a device, or use v12-derived
assumptions.
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
APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING_DIR = ROOT / "baselines/v15/analysis/quarkslab/results"
QUARK = LISTING_DIR / "quarkslab-exhaustive-listing.tsv.gz"
KAGA = LISTING_DIR / "kagaimiq-patched-exhaustive-listing.tsv.gz"

EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quarkslab_exhaustive_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "kagaimiq_patched_exhaustive_sha256": "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

BASE = 0x02000000
OBJ = 0x01C33260
STAGE_BASE = 0x01C37030
STAGE_OFF = 0x0FA0
STAGE = STAGE_BASE + STAGE_OFF
STAGE_VOICE_LEN = 0x9C
CURRENT = OBJ + 0x1A14
MEMCPY = 0x02048CCE
PACKER = 0x0201E13E
LOADER = 0x02005660
HANDLER = 0x0201E254
DISPATCHER = 0x0201C5EC

RANGES = {
    "ui_sysex_handler_bulk_and_dispatch_0201e3ee_0201e648": (0x0201E3EE, 0x0201E648),
    "single_voice_bulk_direct_path_0201e40e_0201e470": (0x0201E40E, 0x0201E470),
    "single_voice_bulk_segmented_final_path_0201e472_0201e4a4": (0x0201E472, 0x0201E4A4),
    "large_bulk_or_segmented_paths_0201e4a6_0201e602": (0x0201E4A6, 0x0201E602),
    "single_parameter_and_midi_fallback_0201e606_0201e648": (0x0201E606, 0x0201E648),
    "packer_0201e13e_0201e252": (0x0201E13E, 0x0201E252),
    "note_dispatcher_0201c5ec_0201c720": (0x0201C5EC, 0x0201C720),
}

REQUIRED_ROWS = {
    0x0201E3F8: "lb.z r0,[r7 + 0x104]",
    0x0201E3FC: "mov r6,#0x1c37030",
    0x0201E448: "add r8,r6,#0xfa0",
    0x0201E44C: "add r1,r4,#0x6",
    0x0201E44E: "add r6,r9,#-0x6",
    0x0201E456: "call 0x02048cce",
    0x0201E462: "jne r0,#0xf7",
    0x0201E468: "call 0x0201e13e",
    0x0201E46C: "call 0x02005660",
    0x0201E472: "lh.z r0,[r7 + 0x9c]",
    0x0201E484: "jne r5,#0x9e",
    0x0201E488: "add r6,r6,#0xfa0",
    0x0201E494: "call 0x02048cce",
    0x0201E49C: "call 0x0201e13e",
    0x0201E4A0: "call 0x02005660",
    0x0201E516: "jbe r5,0x9c",
    0x0201E522: "add r0,r6",
    0x0201E524: "add r0,r0,#0xfa0",
    0x0201E52C: "call 0x02048cce",
    0x0201E57C: "sb r0,[r7 + 0x14]",
    0x0201E580: "add r0,r6,#0xfa0",
    0x0201E58C: "call 0x02048cce",
    0x0201E592: "sh r4,[r7 + 0x9c]",
    0x0201E606: "jne r9,#0x7",
    0x0201E634: "sb r1,[r0 + r2]",
    0x0201E644: "call 0x0201c5ec",
    0x0201C63E: "call 0x02048cce",
    0x0201C67C: "call 0x02048cce",
    0x0201E236: "call 0x02004b02",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def hx(v: int) -> str:
    return f"0x{v:08x}"


def read_listing(path: Path) -> list[dict[str, str]]:
    with gzip.open(path, "rt", errors="replace", newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def row_addr(row: dict[str, str]) -> int:
    return int(row["address"], 16)


def row_out(row: dict[str, str]) -> dict[str, str]:
    return {k: row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"]}


def row_line(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "mnemonic", "text", "flow_type", "function"])


def rows_between(rows: list[dict[str, str]], lo: int, hi: int) -> list[dict[str, str]]:
    return [row_out(r) for r in rows if lo <= row_addr(r) <= hi]


def raw_pointer_xrefs(app: bytes, values: dict[str, int]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in values.items():
        pat = struct.pack("<I", value)
        refs: list[str] = []
        i = 0
        while True:
            j = app.find(pat, i)
            if j < 0:
                break
            refs.append(hx(BASE + j))
            i = j + 1
        out[name] = {"value": hx(value), "count": len(refs), "refs": refs}
    return out


def call_xrefs(rows: list[dict[str, str]], target: int) -> list[dict[str, str]]:
    needle = hx(target)
    return [row_out(r) for r in rows if r["mnemonic"] == "call" and needle in r["text"].lower()]


def key_rows(rows: list[dict[str, str]], addrs: list[int]) -> list[dict[str, str]]:
    by_addr = {row_addr(r): r for r in rows}
    return [row_out(by_addr[a]) for a in addrs]


def validate(evidence: dict[str, Any], rows: list[dict[str, str]]) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []

    def check(name: str, cond: bool, detail: str) -> None:
        checks.append({"status": "PASS" if cond else "FAIL", "name": name, "detail": detail})

    manifest = json.loads(MANIFEST.read_text())
    check("official-v15-app-sha256", evidence["sha256"]["app"] == EXPECTED["app_sha256"], evidence["sha256"]["app"])
    check("official-v15-package-sha256", evidence["sha256"]["package"] == EXPECTED["package_sha256"], evidence["sha256"]["package"])
    check("manifest-app-gate", manifest.get("app_sha256") == EXPECTED["app_sha256"], str(manifest.get("app_sha256")))
    check("manifest-package-gate", manifest.get("package_sha256") == EXPECTED["package_sha256"], str(manifest.get("package_sha256")))
    check("quarkslab-listing-sha256", evidence["sha256"]["quarkslab_exhaustive"] == EXPECTED["quarkslab_exhaustive_sha256"], evidence["sha256"]["quarkslab_exhaustive"])
    check("kagaimiq-listing-sha256", evidence["sha256"]["kagaimiq_patched_exhaustive"] == EXPECTED["kagaimiq_patched_exhaustive_sha256"], evidence["sha256"]["kagaimiq_patched_exhaustive"])
    check("stage-arithmetic", STAGE_BASE + STAGE_OFF == STAGE, f"{hx(STAGE_BASE)}+0x{STAGE_OFF:x}={hx(STAGE)}")
    check("voice-length", STAGE_VOICE_LEN == 156, hex(STAGE_VOICE_LEN))

    by_addr = {row_addr(r): r for r in rows}
    for addr, text in REQUIRED_ROWS.items():
        row = by_addr.get(addr)
        check(f"listing-row-{hx(addr)}", row is not None and text in row["text"], row["text"] if row else "missing")

    packer_callers = {int(r["address"], 16) for r in evidence["call_xrefs"]["0x0201e13e"]}
    loader_callers = {int(r["address"], 16) for r in evidence["call_xrefs"]["0x02005660"]}
    dispatcher_callers = {int(r["address"], 16) for r in evidence["call_xrefs"]["0x0201c5ec"]}
    check("packer-callers-include-sysex-staging", {0x0201E468, 0x0201E49C} <= packer_callers, ",".join(hx(x) for x in sorted(packer_callers)))
    check("loader-callers-include-post-packer-reloads", {0x0201E46C, 0x0201E4A0} <= loader_callers, ",".join(hx(x) for x in sorted(loader_callers)))
    check("dispatcher-callers", dispatcher_callers == {0x0201C736, 0x0201E644}, ",".join(hx(x) for x in sorted(dispatcher_callers)))
    direct_stage = evidence["raw_xrefs"]["stage_0x01c37fd0"]
    check("no-direct-stage-immediate", direct_stage["count"] == 0, json.dumps(direct_stage))
    check("v12-excluded", all("v12" not in p.lower() for p in evidence["scope"]["inputs"]), json.dumps(evidence["scope"]["inputs"]))

    failed = [c for c in checks if c["status"] != "PASS"]
    if failed:
        raise SystemExit("validation failed: " + json.dumps(failed, ensure_ascii=False))
    return checks


def make_report(e: dict[str, Any]) -> str:
    shas = e["sha256"]
    lines: list[str] = []
    lines.append("# official v15 SysEx staging lifecycle for 0x01c37fd0")
    lines.append("")
    lines.append("Scope: exact official v15 only. This pass reads `build/v15-official-app.bin`, `build/SMK-37_Pro_015.fwsc`, and the v15 Quarkslab/Kagaimiq listings only. It performs no patching, flashing, live device access, or v12-derived reasoning.")
    lines.append("")
    lines.append("## SHA gates")
    lines.append("")
    lines.append(f"- app: `{shas['app']}` ({'PASS' if shas['app'] == EXPECTED['app_sha256'] else 'FAIL'})")
    lines.append(f"- official package: `{shas['package']}` ({'PASS' if shas['package'] == EXPECTED['package_sha256'] else 'FAIL'})")
    lines.append(f"- Quarkslab exhaustive listing: `{shas['quarkslab_exhaustive']}` ({'PASS' if shas['quarkslab_exhaustive'] == EXPECTED['quarkslab_exhaustive_sha256'] else 'FAIL'})")
    lines.append(f"- Kagaimiq exhaustive listing: `{shas['kagaimiq_patched_exhaustive']}` ({'PASS' if shas['kagaimiq_patched_exhaustive'] == EXPECTED['kagaimiq_patched_exhaustive_sha256'] else 'FAIL'})")
    lines.append("")
    lines.append("## Verdict")
    lines.append("")
    lines.append("### Proven facts")
    lines.append("")
    lines.append("- The named staging address is not a direct immediate in the app. The handler constructs it as `0x01c37030 + 0x0fa0 = 0x01c37fd0` at `0x0201e3fc` and `0x0201e448`/`0x0201e580` or equivalent add rows.")
    lines.append("- Official v15 can materialize a 156-byte single-voice runtime payload at `0x01c37fd0` without boot-time hooks when the already-live handler accepts Yamaha single-voice bulk SysEx. The direct complete-message path checks `F0 43 00 00 01 1B`, copies bytes after the 6-byte header to `0x01c37fd0`, verifies the final byte is `F7`, calls `0x0201e13e(stage)`, then calls `0x02005660` to reload the selected current snapshot.")
    lines.append("- The required complete host message for that path is `F0 43 00 00 01 1B` + `0x9c` bytes + `F7`, total `0xa3` bytes. In Yamaha DX7 terminology the `0x9c` staged bytes are the 155 single-voice data bytes plus checksum byte. The handler does not prove a checksum gate on this direct complete-message path before `0x0201e13e`; it proves only the header and terminal `F7` gate.")
    lines.append("- `0x0201e468` and `0x0201e49c` are the two official v15 calls from the SysEx handler to `0x0201e13e`. Both are immediately paired with `0x02005660` reload calls at `0x0201e46c` and `0x0201e4a0`.")
    lines.append("- `0x0201e13e` consumes the expanded single-voice source pointer in `r0`, packs it into a stack `0x80` buffer, then calls `0x02004b02` with `r0=stack_packed80`, `r1=selected_persistent_slot`, `r2=0x80`. It is a producer for selected persistent backing storage, not a Note On/Off consumer.")
    lines.append("- Stock Note On and Note Off consumption still occurs through `0x0201c5ec`, which copies `0x9c` bytes from current snapshot `0x01c34c74` into the allocated voice slot on both Note On and Note Off class paths. The SysEx staging buffer is not the stock dispatcher source.")
    lines.append("")
    lines.append("### Blockers and negative safety result")
    lines.append("")
    lines.append("- A live-booted channel wrapper must not blindly source both Note On and Note Off from `0x01c37fd0`. The staging region is a transient SysEx assembly workspace. Official paths overwrite it for single-voice bulk, segmented single-voice bulk, and larger/other bulk staging paths, and no durable valid/owner/channel generation flag is proven in the traced rows.")
    lines.append("- Note Off safety is the hard blocker. If a wrapper rereads `0x01c37fd0` at Note Off, any intervening SysEx bulk write can make the release copy differ from the Note On copy for the same voice. Stock code already copies parameters into the voice slot at Note On; a safe separation design must preserve per-voice identity or store a validated per-channel/per-voice copy, not rely on the global staging workspace staying unchanged.")
    lines.append("- The handler has runtime gates not resolved by static listing alone: `0x0201e3ee` returns when `obj+0x206 == 0`, and `obj+0x104` selects staging subpaths. This does not require boot-time hooks, but host success requires the device to be in a state where the official handler accepts the message.")
    lines.append("- This pass proves the message shape and copy/pack/reload lifecycle statically. It does not prove all USB-MIDI packetization, UI mode setup, checksum semantics, interrupt races, or DMA absence. Those remain live-device or emulator instrumentation blockers, intentionally out of scope here.")
    lines.append("")
    lines.append("## Host message formats observed")
    lines.append("")
    lines.append("| Path | State/gates | Host bytes | Staged bytes | Outcome |")
    lines.append("| --- | --- | --- | --- | --- |")
    lines.append("| Complete single-voice bulk | `obj+0x206 != 0`, `obj+0x104 == 0`, bytes match `F0 43 00 00 01 1B`, final byte `F7` | `F0 43 00 00 01 1B` + `0x9c` payload/checksum bytes + `F7` | copies `len-6 = 0x9d` bytes to stage, with the first `0x9c` bytes usable by packer and `F7` at `stage+0x9c` | `0x0201e13e(stage)` then `0x02005660()` |")
    lines.append("| Segmented/final single-voice bulk | `obj+0x104 == 2`, current offset from `obj+0x9c`, final byte `F7`, accumulated `offset+len == 0x9e` | continuation frame ending in `F7` | copies `len-2` bytes into `stage+offset` | `0x0201e13e(stage)` then `0x02005660()` |")
    lines.append("| Initial single-voice segmented path | header variant `F0 43 00 09 20 00` reaches `0x0201e57a` | message bytes after offset 6 | copies `len-6` bytes to stage and stores length at `obj+0x9c` | no pack until final path |")
    lines.append("| Single-parameter writer | exactly 7 bytes `F0 43 10 aa bb dd F7` | no stage use | writes one byte to `0x01c33260 + 0x1a14 + (((aa << 7) + bb) & 0xff)` | direct current snapshot mutation, not staging |")
    lines.append("")
    lines.append("## Lifecycle")
    lines.append("")
    lines.append("```mermaid")
    lines.append("flowchart TD")
    lines.append("  HOST[Host Yamaha single-voice SysEx] --> H[0x0201e254 official handler]")
    lines.append("  H -->|constructs 0x01c37030+0xfa0| STAGE[0x01c37fd0 transient staging]")
    lines.append("  STAGE -->|r0| PACK[0x0201e13e pack expanded source]")
    lines.append("  PACK -->|0x02004b02 length 0x80| STORE[selected persistent packed slot]")
    lines.append("  PACK --> FLAGS[selected dirty/save flag update]")
    lines.append("  H -->|after pack| LOAD[0x02005660 selected record reload]")
    lines.append("  STORE --> LOAD")
    lines.append("  LOAD --> CUR[0x01c34c74 current runtime snapshot]")
    lines.append("  CUR -->|0x9c copy| DISP[0x0201c5ec Note On/Off]")
    lines.append("  DISP --> VOICE[per-voice slot]")
    lines.append("  OTHER[Later SysEx bulk/chunk] --> STAGE")
    lines.append("```")
    lines.append("")
    lines.append("## Key rows")
    lines.append("")
    for title, rows in [
        ("complete single-voice bulk path", e["paths"]["complete_single_voice_bulk"]),
        ("segmented final single-voice path", e["paths"]["segmented_single_voice_final"]),
        ("other staging overwrite paths", e["paths"]["other_stage_overwrites"]),
        ("single parameter writer and MIDI fallback", e["paths"]["single_parameter_and_midi_fallback"]),
        ("packer sink", e["paths"]["packer_sink"]),
        ("note dispatcher consumers", e["paths"]["note_dispatcher_consumers"]),
    ]:
        lines.append(f"### {title}")
        lines.append("")
        for r in rows:
            lines.append(f"- `{row_line(r)}`")
        lines.append("")
    lines.append("## Call xrefs")
    lines.append("")
    for target, rows in e["call_xrefs"].items():
        lines.append(f"### `{target}`")
        lines.append("")
        for r in rows:
            lines.append(f"- `{row_line(r)}`")
        lines.append("")
    lines.append("## Raw pointer xrefs")
    lines.append("")
    for name, data in e["raw_xrefs"].items():
        lines.append(f"- `{name}` `{data['value']}`: count `{data['count']}`, refs {', '.join('`'+x+'`' for x in data['refs']) or 'none'}")
    lines.append("")
    lines.append("## Reproduce")
    lines.append("")
    lines.append("```sh")
    lines.append("python3 baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/trace_sysex_staging.py")
    lines.append("cd baselines/v15/analysis/channel-separation-reanalysis/sysex-staging")
    lines.append("shasum -a 256 -c SHA256SUMS")
    lines.append("```")
    lines.append("")
    lines.append("`validation.txt` records SHA gates, manifest binding, staging arithmetic, required listing rows, caller sets, lack of direct stage immediate, and v12 path exclusion. `sysex_staging_trace.json` contains the same evidence machine-readably.")
    return "\n".join(lines) + "\n"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    app = APP.read_bytes()
    rows = read_listing(QUARK)
    evidence: dict[str, Any] = {
        "scope": {
            "inputs": [str(APP.relative_to(ROOT)), str(PACKAGE.relative_to(ROOT)), str(QUARK.relative_to(ROOT)), str(KAGA.relative_to(ROOT))],
            "constraints": ["official v15 only", "read-only", "no patch", "no flash", "no device access", "no v12 assumptions"],
        },
        "sha256": {
            "app": sha256(APP),
            "package": sha256(PACKAGE),
            "quarkslab_exhaustive": sha256(QUARK),
            "kagaimiq_patched_exhaustive": sha256(KAGA),
        },
        "constants": {
            "obj_base": hx(OBJ),
            "stage_base": hx(STAGE_BASE),
            "stage_offset": hex(STAGE_OFF),
            "stage": hx(STAGE),
            "stage_voice_len": hex(STAGE_VOICE_LEN),
            "current_snapshot": hx(CURRENT),
        },
        "raw_xrefs": raw_pointer_xrefs(app, {
            "stage_0x01c37fd0": STAGE,
            "stage_base_0x01c37030": STAGE_BASE,
            "obj_0x01c33260": OBJ,
            "current_0x01c34c74": CURRENT,
        }),
        "ranges": {name: rows_between(rows, lo, hi) for name, (lo, hi) in RANGES.items()},
        "call_xrefs": {
            "0x0201e13e": call_xrefs(rows, PACKER),
            "0x02005660": call_xrefs(rows, LOADER),
            "0x0201c5ec": call_xrefs(rows, DISPATCHER),
            "0x02048cce": call_xrefs(rows, MEMCPY),
        },
        "paths": {
            "complete_single_voice_bulk": key_rows(rows, [0x0201E3EE, 0x0201E3F8, 0x0201E3FC, 0x0201E40E, 0x0201E410, 0x0201E414, 0x0201E416, 0x0201E41A, 0x0201E41C, 0x0201E430, 0x0201E436, 0x0201E43C, 0x0201E442, 0x0201E448, 0x0201E44C, 0x0201E44E, 0x0201E452, 0x0201E454, 0x0201E456, 0x0201E45C, 0x0201E460, 0x0201E462, 0x0201E466, 0x0201E468, 0x0201E46C]),
            "segmented_single_voice_final": key_rows(rows, [0x0201E472, 0x0201E476, 0x0201E47A, 0x0201E47E, 0x0201E480, 0x0201E484, 0x0201E488, 0x0201E48C, 0x0201E48E, 0x0201E492, 0x0201E494, 0x0201E49A, 0x0201E49C, 0x0201E4A0]),
            "other_stage_overwrites": key_rows(rows, [0x0201E4C0, 0x0201E4C2, 0x0201E4C6, 0x0201E4CA, 0x0201E4CC, 0x0201E4CE, 0x0201E516, 0x0201E522, 0x0201E524, 0x0201E528, 0x0201E52A, 0x0201E52C, 0x0201E57A, 0x0201E580, 0x0201E584, 0x0201E586, 0x0201E58A, 0x0201E58C, 0x0201E592]),
            "single_parameter_and_midi_fallback": key_rows(rows, [0x0201E606, 0x0201E60A, 0x0201E610, 0x0201E616, 0x0201E61C, 0x0201E622, 0x0201E626, 0x0201E628, 0x0201E62A, 0x0201E62C, 0x0201E62E, 0x0201E630, 0x0201E632, 0x0201E634, 0x0201E640, 0x0201E642, 0x0201E644]),
            "packer_sink": key_rows(rows, [0x0201E216, 0x0201E21C, 0x0201E220, 0x0201E222, 0x0201E226, 0x0201E22A, 0x0201E22C, 0x0201E22E, 0x0201E230, 0x0201E232, 0x0201E234, 0x0201E236, 0x0201E23A, 0x0201E23C, 0x0201E240, 0x0201E242, 0x0201E244, 0x0201E246, 0x0201E24A]),
            "note_dispatcher_consumers": key_rows(rows, [0x0201C602, 0x0201C630, 0x0201C636, 0x0201C63A, 0x0201C63C, 0x0201C63E, 0x0201C666, 0x0201C66C, 0x0201C674, 0x0201C678, 0x0201C67A, 0x0201C67C]),
        },
    }
    checks = validate(evidence, rows)
    evidence["validation"] = checks
    (OUT / "sysex_staging_trace.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (OUT / "report.md").write_text(make_report(evidence))
    (OUT / "validation.txt").write_text("\n".join(f"{c['status']}\t{c['name']}\t{c['detail']}" for c in checks) + f"\nPASS\tcheck-count\t{len(checks)}\n")
    names = ["trace_sysex_staging.py", "sysex_staging_trace.json", "report.md", "validation.txt"]
    (OUT / "SHA256SUMS").write_text("\n".join(f"{sha256(OUT / n)}  {n}" for n in names) + "\n")


if __name__ == "__main__":
    main()
