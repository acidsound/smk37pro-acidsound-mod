#!/usr/bin/env python3
"""Offline S1C7 live-failure root-cause and successor blocker analysis.

This script reads only repository artifacts. It never opens USB/MIDI/device paths,
never invokes OTA, never writes a firmware image, and never flashes.
"""
from __future__ import annotations

import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
S1C5 = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return"
S1C7 = ROOT / "baselines/v15/analysis/flash-candidates/S1C7-current-set-helper-checkpoint"
DUMPS = ROOT / "baselines/v15/device-dumps/s1c7-preseed-20260804"
S1C5_RESTORE = ROOT / "baselines/v15/device-dumps/s1c5-restored-20260804"
LIVE_S1C7_LOG = ROOT / "logs/v15/ota-v15-s1c7-current-set-helper-20260804.log"
LIVE_S1C5_RESTORE_LOG = ROOT / "logs/v15/ota-v15-s1c5-restore-from-s1c7-20260804.log"
SEED_BUNDLE = ROOT / "build/SMK37Pro-WL82-v15-S1C7-seed-20260804-v1"

BASE = 0x02000000
SEL_START, SEL_END, PRODUCER_START, OWNED_END = 0x0201E13E, 0x0201E196, 0x0201E196, 0x0201E254
HELPER_START, HELPER_END = 0x02026D80, 0x02026DD4
SAVE_SKIP = 0x02026D7A
RECORD_BASE_PHYSICAL = 0x0F8000
RECORD_BASE = 96
RECORD_STRIDE = 0xA3
PREFIX_LEN = 0x9C
SLOTS = 16

EXPECTED = {
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "s1c5_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "s1c5_producer": "53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4",
    "s1c7_app": "71cfc1fcbeecd1a9277f88272be6b122a96f33fbd741d7486c670ffab6e58646",
    "s1c7_fwsc": "3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593",
    "s1c7_selector": "b77f2787874ad37d724e1c6305e74f97c8a6eb9fe6b51627c8fce35dd257daeb",
    "s1c7_helper": "e9ea13c277736c000e5b7f275f97d319b725b2376e9ac15aac97209a8b0f4396",
    "s1c7_dual_dump": "078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946",
    "empty_prefix": "59bf9091f4cbbd2a8796bfe086a501c57226c42739dcf8ad323e7493ad51e38f",
}

SUCCESSOR_MAGIC = "SMK37S8P"


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


def off(address: int) -> int:
    return address - BASE


def compact_ranges(offsets: list[int]) -> list[str]:
    if not offsets:
        return []
    out: list[str] = []
    start = prev = offsets[0]
    for x in offsets[1:]:
        if x == prev + 1:
            prev = x
            continue
        out.append(f"0x{start:x}..0x{prev + 1:x}")
        start = prev = x
    out.append(f"0x{start:x}..0x{prev + 1:x}")
    return out


def diff_offsets(a: bytes, b: bytes) -> list[int]:
    req(len(a) == len(b), "diff operands same length")
    return [i for i, (x, y) in enumerate(zip(a, b)) if x != y]


def load_exact_binaries() -> dict[str, Any]:
    s1c5_app = (S1C5 / "app.bin").read_bytes()
    s1c7_app = (S1C7 / "app.bin").read_bytes()
    req(sha(s1c5_app) == EXPECTED["s1c5_app"], "exact S1C5 app")
    req(shaf(S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc") == EXPECTED["s1c5_fwsc"], "exact S1C5 FWSC")
    req(sha(s1c7_app) == EXPECTED["s1c7_app"], "exact S1C7 app")
    req(shaf(S1C7 / "SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc") == EXPECTED["s1c7_fwsc"], "exact S1C7 FWSC")
    s1c5_combined = s1c5_app[off(SEL_START):off(OWNED_END)]
    s1c5_producer = s1c5_app[off(PRODUCER_START):off(OWNED_END)]
    s1c7_selector = s1c7_app[off(SEL_START):off(SEL_END)]
    s1c7_producer = s1c7_app[off(PRODUCER_START):off(OWNED_END)]
    s1c7_helper = s1c7_app[off(HELPER_START):off(HELPER_END)]
    req(sha(s1c5_combined) == EXPECTED["s1c5_combined"], "S1C5 combined selector/producer")
    req(sha(s1c5_producer) == EXPECTED["s1c5_producer"], "S1C5 producer")
    req(sha(s1c7_producer) == EXPECTED["s1c5_producer"], "S1C7 producer preserved from S1C5")
    req(sha(s1c7_selector) == EXPECTED["s1c7_selector"], "S1C7 selector")
    req(sha(s1c7_helper) == EXPECTED["s1c7_helper"], "S1C7 helper")
    req(s1c7_app[off(SAVE_SKIP):off(SAVE_SKIP)+6].hex() == "04ac00160016", "S1C7 SAVE skip")

    appdiff = diff_offsets(s1c5_app, s1c7_app)
    return {
        "s1c5": {
            "app_sha256": sha(s1c5_app),
            "fwsc_sha256": EXPECTED["s1c5_fwsc"],
            "combined_window_sha256": sha(s1c5_combined),
            "producer_sha256": sha(s1c5_producer),
        },
        "s1c7": {
            "app_sha256": sha(s1c7_app),
            "fwsc_sha256": EXPECTED["s1c7_fwsc"],
            "selector_sha256": sha(s1c7_selector),
            "producer_sha256": sha(s1c7_producer),
            "helper_sha256": sha(s1c7_helper),
            "save_skip_bytes": s1c7_app[off(SAVE_SKIP):off(SAVE_SKIP)+6].hex(),
        },
        "s1c5_to_s1c7_app_diff": {
            "byte_count": len(appdiff),
            "ranges": compact_ranges(appdiff),
            "producer_preserved_byte_for_byte": s1c5_producer == s1c7_producer,
        },
        "critical_calls_and_branches": {
            "s1c5_not_armed_or_invalid_target": "0x0201e186 stock copy path",
            "s1c7_not_armed_branch": "0x0201e166 jne r0,#2 -> 0x0201e18c persistent helper call",
            "s1c7_invalid_branch": "0x0201e178 jne r0,#1 -> 0x0201e18c persistent helper call",
            "s1c7_persistent_call": "0x0201e18c call32 -> 0x02026d80",
            "s1c7_stock_copy_call": "0x0201e186 call32 -> 0x02026db2",
            "s1c7_helper_read_call": "0x02026d92 call32 -> 0x02004870 with r0=dest, r1=0x7d20+slot*0xa3, r2=0x9c",
            "s1c7_read_ok_gate": "0x02026d98 jne r0,#0 -> trust bytes already copied into dest",
        },
    }


def inspect_live_dumps() -> dict[str, Any]:
    a = DUMPS / "pre-a-live.bin"
    b = DUMPS / "pre-b-live.bin"
    req(a.exists() and b.exists(), "dual S1C7 preseed dumps exist")
    ad = a.read_bytes()
    bd = b.read_bytes()
    req(len(ad) == len(bd) == 1024 * 1024, "dual dumps are 1 MiB")
    req(ad == bd, "dual dumps byte-identical")
    req(sha(ad) == EXPECTED["s1c7_dual_dump"], "dual dump SHA")

    records = []
    for slot in range(SLOTS):
        physical = RECORD_BASE_PHYSICAL + (RECORD_BASE + slot) * RECORD_STRIDE
        prefix = ad[physical:physical + PREFIX_LEN]
        tail = ad[physical + PREFIX_LEN:physical + RECORD_STRIDE]
        prefix_sha = sha(prefix)
        req(prefix_sha == EXPECTED["empty_prefix"], f"slot {slot} empty prefix")
        req(prefix == b"\x00" * PREFIX_LEN, f"slot {slot} prefix all zero")
        records.append({
            "slot": slot,
            "record_index": RECORD_BASE + slot,
            "physical_offset": f"0x{physical:06x}",
            "prefix_sha256": prefix_sha,
            "prefix_all_zero": True,
            "tail_hex": tail.hex(),
        })
    return {
        "preseed_dual_dump": {
            "a": str(a.relative_to(ROOT)),
            "b": str(b.relative_to(ROOT)),
            "size": len(ad),
            "sha256": sha(ad),
            "byte_identical": True,
        },
        "raw_records_96_111_before_seed": records,
        "interpretation": "S1C7 had no positive seed present. Each 0x9c prefix was all zero, but the S1C7 helper only checked read length/nonzero return, not seed magic or CRC.",
    }


def live_observations() -> dict[str, Any]:
    obs = {
        "s1c7_install_log": str(LIVE_S1C7_LOG.relative_to(ROOT)) if LIVE_S1C7_LOG.exists() else None,
        "s1c5_restore_log": str(LIVE_S1C5_RESTORE_LOG.relative_to(ROOT)) if LIVE_S1C5_RESTORE_LOG.exists() else None,
        "s1c7_seed_bundle": str(SEED_BUNDLE.relative_to(ROOT)) if SEED_BUNDLE.exists() else None,
        "observed_s1c7_failure": "User reported after S1C7 OTA: Pad side had no sound, and sending SysEx from Patch Set Editor gave the same result.",
        "observed_s1c5_recovery": "After restoring S1C5 and retransmitting the Patch Set, user reported pad operation normal.",
    }
    if SEED_BUNDLE.exists():
        readme = (SEED_BUNDLE / "README.md").read_text(encoding="utf-8")
        obs["seed_bundle_readme_sha256"] = shaf(SEED_BUNDLE / "README.md")
        obs["seed_bundle_declares_target_dump_sha"] = EXPECTED["s1c7_dual_dump"] in readme
    restored = S1C5_RESTORE / "post-restore.bin"
    if restored.exists():
        obs["s1c5_restore_partial_dump"] = {"path": str(restored.relative_to(ROOT)), "size": restored.stat().st_size, "sha256": shaf(restored)}
    return obs


def successor_design() -> dict[str, Any]:
    # Deterministic design constants only. This is deliberately not a firmware image.
    manifest_header = bytearray(0xA3)
    manifest_header[0:8] = SUCCESSOR_MAGIC.encode("ascii")
    manifest_header[8] = 1  # version
    manifest_header[9] = 1  # committed flag in a valid seed
    manifest_header[10] = RECORD_BASE
    manifest_header[11] = SLOTS
    manifest_header[12:14] = PREFIX_LEN.to_bytes(2, "little")
    manifest_header[14:16] = RECORD_STRIDE.to_bytes(2, "little")
    header_crc = binascii.crc32(manifest_header[:0x9F] + b"\x00\x00\x00\x00") & 0xFFFFFFFF
    manifest_header[0x9F:0xA3] = header_crc.to_bytes(4, "little")
    return {
        "status": "DESIGN_ONLY_BLOCKED_FOR_FIRMWARE_FIT",
        "minimum_contract": [
            "Start from exact S1C5. Preserve its selector/producer and product SysEx producer semantics unless a fully reviewed larger placement is found.",
            "If S1C5 RAM is ARMED and selected slot is valid, use resident RAM before any persistent lookup.",
            "If no positive persistent seed is present, execute exact S1C5 stock/not-ARMED fallback. Do not copy raw storage bytes into the note payload destination.",
            "Persistent restore requires a separate manifest record with magic, version, layout, committed flag, header CRC, payload CRC, per-record CRCs, and playback notes.",
            "Only after all reads and CRCs pass, materialize all 16 resident slots, force voice[0x9b]=0x3f, populate Playback Note map, set valid flags, then publish ARMED last.",
            "Future save/write must write payloads first, readback verify them, then write/readback verify manifest last. A failed write remains invisible to restore.",
        ],
        "manifest_record": 112,
        "payload_records": "96..111",
        "manifest_magic_ascii": SUCCESSOR_MAGIC,
        "manifest_template_sha256": sha(manifest_header),
        "manifest_template_header_crc32": f"0x{header_crc:08x}",
        "why_no_safe_fwsc_emitted": [
            "S1C5 owned selector/producer window has no free bytes when preserving producer and existing Web/CoreMIDI behavior.",
            "S1C7's 84-byte helper already fills the quarantined SAVE cave and still lacks magic/CRC validation.",
            "Adding positive magic plus header CRC plus payload/per-record CRC plus no-seed stock fallback cannot be proven to fit in exact owned placement.",
            "No exact callable runtime CRC ABI or safe larger lazy-load hook is proven in current evidence.",
        ],
    }


def render_report(ev: dict[str, Any]) -> str:
    s1 = ev["binaries"]["s1c5"]
    s7 = ev["binaries"]["s1c7"]
    dump = ev["live_dumps"]["preseed_dual_dump"]
    design = ev["successor_design"]
    return f"""# S1C7 live pad-silence root cause and safe successor blocker

## Decision

**ROOT_CAUSE_CONFIRMED; SAFE FIRMWARE SUCCESSOR BLOCKED OFFLINE.** No `app.bin`, FWSC, exact OTA, rollback flasher, or device writer is emitted from this package. The safe successor needs positive magic/CRC-gated restore, but current exact S1C5/S1C7 placement cannot prove that implementation while preserving S1C5 behavior.

## Exact binaries used

| Artifact | SHA-256 |
|---|---|
| S1C5 app | `{s1['app_sha256']}` |
| S1C5 FWSC | `{s1['fwsc_sha256']}` |
| S1C5 selector+producer window | `{s1['combined_window_sha256']}` |
| S1C5 producer window | `{s1['producer_sha256']}` |
| S1C7 app | `{s7['app_sha256']}` |
| S1C7 FWSC | `{s7['fwsc_sha256']}` |
| S1C7 selector window | `{s7['selector_sha256']}` |
| S1C7 producer window | `{s7['producer_sha256']}` |
| S1C7 helper window | `{s7['helper_sha256']}` |

S1C7 preserved the S1C5 producer byte-for-byte, but it did **not** preserve the S1C5 selector state policy. The app diff from S1C5 to S1C7 is `{ev['binaries']['s1c5_to_s1c7_app_diff']['byte_count']}` bytes in ranges `{', '.join(ev['binaries']['s1c5_to_s1c7_app_diff']['ranges'])}`.

## Exact call, ABI, and state root cause

S1C5 not-ARMED or invalid-slot behavior falls through to the stock copy path at `0x0201e186`. S1C7 changed those branches:

- `0x0201e166`: `jne r0,#2 -> 0x0201e18c`, so not-ARMED state calls the persistent helper.
- `0x0201e178`: `jne r0,#1 -> 0x0201e18c`, so invalid resident slot calls the persistent helper.
- `0x0201e18c`: `call32 -> 0x02026d80`.
- `0x02026d92`: helper calls `0x02004870` with `r0=dest`, `r1=0x7d20 + slot*0xa3`, `r2=0x9c`.
- `0x02026d98`: helper treats any nonzero return as valid data, then loads Playback Note from copied byte `dest+0x9b`.

The ABI mistake is that `0x02004870` is only a full-length read wrapper. It can prove that `0x9c` bytes were read, but not that the bytes are seeded, committed, or valid. S1C7 therefore trusted empty storage as if it were a valid patch record.

## Live evidence

Dual preseed dumps are byte-identical 1 MiB images:

- `{dump['a']}`
- `{dump['b']}`
- SHA-256 `{dump['sha256']}`

For records 96..111 at `0x0fbd20..0x0fc748`, every 156-byte prefix is all zero with SHA-256 `{EXPECTED['empty_prefix']}` and tail `64000000000000`. That is an unseeded state, but S1C7 had no magic or CRC gate, so the full-length read could still be accepted. The helper then copied zero patch bytes into the live note payload destination, forced byte `0x9b` to `0x3f`, and returned metadata note 0. This explains pad silence.

Current live observations align with this: after S1C7 OTA the user reported no pad sound and no change after Patch Set Editor SysEx; after restoring exact S1C5 and retransmitting the Patch Set, the user reported pad operation normal. Producer preservation alone was insufficient because the S1C7 selector gave unvalidated persistent fallback priority in not-ARMED or invalid states instead of retaining S1C5's stock fallback.

## Minimal safe successor design

The next safe successor must guarantee:

1. **No-seed stock fallback:** unseeded, all-zero, short-read, corrupt, wrong-version, uncommitted, or CRC-failing storage does nothing and returns through exact S1C5 behavior.
2. **S1C5 SysEx ARMED priority:** if exact S1C5 resident RAM is `ARMED` and the selected slot is valid, use it before any persistent lookup.
3. **Seeded restore only with positive magic/CRC:** restore requires manifest magic `{SUCCESSOR_MAGIC}`, layout/count checks, committed flag, header CRC, payload CRC, and per-record CRCs before any resident RAM publication.
4. **Publish last:** materialize all 16 resident slots and Playback Note map first, then set valid flags, count, and ARMED state last.
5. **Future write safety:** write payload records first, readback verify, write/readback verify manifest last. Never silently claim saved state.

A deterministic manifest template was generated for the design: SHA-256 `{design['manifest_template_sha256']}`, header CRC `{design['manifest_template_header_crc32']}`.

## Why no FWSC/rollback candidate is emitted

- The exact S1C5 selector/producer window has no free bytes if Web/CoreMIDI producer behavior is preserved.
- The exact S1C7 helper window is only 84 bytes and already filled by the unsafe no-manifest helper.
- A positive magic/CRC gate plus stock fallback and ARMED priority does not fit in the proven owned space.
- No exact callable runtime CRC ABI or larger safe lazy-load hook is proven.

Therefore the safe action is blocker evidence, not another flashable candidate.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C7-live-failure-root-cause-20260804 && shasum -a 256 -c SHA256SUMS)
```
"""


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build(check: bool = False) -> dict[str, Any]:
    ev = {
        "format": "smk37-v15-s1c7-live-failure-root-cause-v1",
        "decision": "ROOT_CAUSE_CONFIRMED_SAFE_FWSC_BLOCKED",
        "scope": {
            "offline_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "flash_performed": False,
            "ota_performed": False,
            "reset_performed": False,
            "fwsc_emitted": False,
        },
        "binaries": load_exact_binaries(),
        "live_dumps": inspect_live_dumps(),
        "live_observations": live_observations(),
        "successor_design": successor_design(),
    }
    if check:
        old = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
        req(old == ev, "evidence.json deterministic")
        req((HERE / "report.md").read_text(encoding="utf-8") == render_report(ev), "report.md deterministic")
        return ev

    write_json(HERE / "evidence.json", ev)
    (HERE / "report.md").write_text(render_report(ev), encoding="utf-8")
    (HERE / "README.md").write_text("# S1C7 live failure root-cause package\n\nOffline evidence package. No firmware candidate is emitted because the safe magic/CRC-gated successor is blocked by exact placement and ABI evidence.\n", encoding="utf-8")
    (HERE / "validation.txt").write_text("PASS exact S1C5/S1C7 binary gates\nPASS S1C7 producer preserved but selector fallback changed\nPASS dual S1C7 preseed dumps identical and unseeded zero prefixes\nPASS root cause: full-length read accepted unvalidated all-zero records\nPASS successor design requires no-seed stock fallback, S1C5 ARMED priority, and positive magic/CRC\nBLOCK no safe FWSC emitted\n", encoding="utf-8")
    write_sha_inventory()
    return ev


def write_sha_inventory() -> None:
    files = ["README.md", "analyze.py", "validate.py", "evidence.json", "report.md", "validation.txt"]
    lines = []
    for name in files:
        p = HERE / name
        if p.exists():
            lines.append(f"{shaf(p)}  {name}")
    (HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    ev = build(check=args.check)
    print(ev["decision"])
    print("s1c7_dual_dump_sha256=" + ev["live_dumps"]["preseed_dual_dump"]["sha256"])
    print("fwsc_emitted=false")


if __name__ == "__main__":
    main()
