#!/usr/bin/env python3
"""Exact-v15-only S1C5 power-cycle restore analysis.

Read-only analysis. This script does not build or modify firmware, open a device,
write flash, send MIDI, or reset hardware. It writes findings only in this
analysis directory.
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BASE = 0x02000000

PATHS = {
    "official_app": ROOT / "build/v15-official-app.bin",
    "official_fwsc": ROOT / "build/SMK-37_Pro_015.fwsc",
    "listing": ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz",
    "s1c5_app": ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app.bin",
    "s1c5_evidence": ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/evidence.json",
    "s1c5_combined": ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/combined.bin",
    "s1c5_decode": ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv",
    "clean_dump": ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin",
    "bank_d_manifest": ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16/manifest.json",
    "bank_d_dir": ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16",
    "dx7_vmem": ROOT / "tools/dx7_vmem.py",
    "r01d": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/r01d-incident/evidence.json",
    "factory_loader": ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader/factory_loader_evidence.json",
    "persistence": ROOT / "baselines/v15/analysis/patch-set-ui/persistence/evidence.json",
    "app_extension": ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/evidence.json",
    "placement": ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/executable-placement/evidence.json",
}

EXPECTED_SHA256 = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_evidence": "02213aff815fe951d6b74f349c82cb0af65110be3e65d96f90343fa775d134e5",
    "s1c5_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "clean_dump": "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b",
    "bank_d_manifest": "b2a5bce72249d64c05bd00a9afa935f1e540c9cf10f2928230fe01a16f24ecc7",
    "dx7_vmem": "c833bbd39dc4cd5df2c90c0e444beef2e36edd78ab88aaf1129656c3253392bf",
    "r01d": "e264cceb8837f290bfdd48a73e53b8270638b56193c2a87e155794d5c522d179",
    "factory_loader": "efdda52181e3736221354acfe36633a1fd55cc3f7b83918a03e073bab3ebcd09",
    "persistence": "d6ebfbc356afa97dc4e389754394a9792cc0601b528cad90a5f86c8535e93eea",
    "app_extension": "79632aa79b54e6065e122c9aa312872766c0e5a351f7e680355bd7e676647856",
    "placement": "195bc15381e95e276912a7f0ac7b3cc197959b98bdb688eceb85c56dcc34f20f",
}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def req(condition: bool, message: str, checks: list[str]) -> None:
    if not condition:
        raise AssertionError(message)
    checks.append("PASS\t" + message)


def hx(value: int, width: int = 8) -> str:
    return f"0x{value:0{width}x}"


def app_slice(app: bytes, address: int, size: int) -> bytes:
    offset = address - BASE
    if offset < 0 or offset + size > len(app):
        raise AssertionError(f"app range outside image: {hx(address)}+{size}")
    return app[offset:offset + size]


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_listing() -> tuple[dict[int, dict[str, Any]], list[dict[str, Any]]]:
    rows: dict[int, dict[str, Any]] = {}
    loader_calls: list[dict[str, Any]] = []
    with gzip.open(PATHS["listing"], "rt", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            fields = line.rstrip("\n").split("\t")
            if len(fields) < 5:
                continue
            try:
                address = int(fields[0], 16)
            except ValueError:
                continue
            row = {
                "address": hx(address),
                "bytes": fields[1],
                "size": int(fields[2]),
                "mnemonic": fields[3],
                "asm": fields[4],
                "flow": fields[5] if len(fields) > 5 else "",
                "function": fields[6] if len(fields) > 6 else "",
            }
            rows[address] = row
            if row["asm"] == "call 0x02005660":
                loader_calls.append(row)
    return rows, loader_calls


def read_decode() -> list[dict[str, str]]:
    with PATHS["s1c5_decode"].open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def bank_d_records(checks: list[str]) -> list[dict[str, Any]]:
    sys.path.insert(0, str(ROOT / "tools"))
    from dx7_vmem import unpack_voice  # type: ignore

    dump = PATHS["clean_dump"].read_bytes()
    manifest = read_json(PATHS["bank_d_manifest"])
    out: list[dict[str, Any]] = []
    for slot, item in enumerate(manifest["slots"]):
        index = 96 + slot
        packed_offset = 0xF4000 + index * 0x80
        raw_offset = 0xF8000 + index * 0xA3
        flag_offset = 0xFD180 + index
        packed = dump[packed_offset:packed_offset + 0x80]
        raw = dump[raw_offset:raw_offset + 0xA3]
        packet = (PATHS["bank_d_dir"] / item["packet_file"]).read_bytes()
        runtime = packet[6:-1]
        modeled = unpack_voice(packed)
        req(len(packed) == 0x80 and len(raw) == 0xA3 and len(runtime) == 0x9C,
            f"Bank D slot {slot} exact record lengths", checks)
        req(modeled == runtime, f"Bank D slot {slot} packed128 expands to pinned runtime156", checks)
        req(dump[flag_offset] == 0, f"Bank D slot {slot} clean saved flag is zero", checks)
        raw_diff_count = sum(a != b for a, b in zip(raw[:0x9C], runtime))
        req(raw_diff_count > 0, f"Bank D slot {slot} raw163 prefix cannot substitute for runtime156", checks)
        out.append({
            "slot": slot,
            "trigger_note": 36 + slot,
            "bank_zero_based": 3,
            "preset_zero_based": slot,
            "name": item["name"],
            "record_index": index,
            "packed_dump_offset": hx(packed_offset, 6),
            "packed_sha256": sha(packed),
            "runtime_sha256": sha(runtime),
            "raw_dump_offset": hx(raw_offset, 6),
            "raw_prefix_sha256": sha(raw[:0x9C]),
            "raw_prefix_diff_bytes": raw_diff_count,
            "flag_dump_offset": hx(flag_offset, 6),
            "flag": dump[flag_offset],
        })
    req([r["packed_dump_offset"] for r in out][0] == "0x0f7000" and
        [r["packed_dump_offset"] for r in out][-1] == "0x0f7780",
        "Bank D 1..16 packed records are contiguous at dump 0x0f7000..0x0f7800", checks)
    return out


def render_report(ev: dict[str, Any]) -> str:
    records = ev["bank_d_materialization"]["records"]
    record_rows = "\n".join(
        f"| {r['slot']} | {r['trigger_note']} | D{r['preset_zero_based'] + 1} | {r['name']} | "
        f"`{r['packed_dump_offset']}` | `{r['raw_dump_offset']}` | {r['raw_prefix_diff_bytes']} |"
        for r in records
    )
    call_rows = "\n".join(
        f"| `{r['address']}` | `{r['bytes']}` | {r['classification']} | {r['return_consumer']} |"
        for r in ev["loader_census"]
    )
    return f"""# S1C5 power-cycle restore, exact-v15-only decision

Scope: read-only findings only. No firmware, FWSC, device, MIDI, flash, OTA, or reset action was produced or performed.

## Decision

**BLOCK.** There is no exact-v15-proven, additive S1C5 power-cycle restore mechanism with an assignable executable address today.

The fixed Bank D 1..16 set does **not** need a 2,496-byte embedded runtime payload. Its packed factory sources already exist contiguously. That solves the data-source problem, but not the safe on-device materialization problem:

1. S1C5's only audited replacement window is fully occupied: `0x0201e13e..0x0201e254` is 278 bytes, with 88-byte selector, 188-byte producer, and 2 bytes inert tail. Preserving the live-good S1C5 producer leaves exactly **2 bytes**.
2. The only exact v15 unpack implementation is inlined inside `0x02005660`. Its packed-source through final runtime-byte body is `0x020056a0..0x0200576e`, **206 bytes**, uses the global current object, and has no destination-pointer ABI. Even deleting the whole 188-byte S1C5 producer plus 2-byte tail yields only 190 bytes, **16 bytes less than that known body before any 16-slot loop, locking, validation, publication, or Note ABI repair**.
3. Calling `0x02005660` repeatedly is not a safe substitute. It mutates global bank/preset-selected current state, copies through `0x01c34c74`, calls four tail helpers, and writes through `*(0x01c33260+0x15c)`. No exact evidence proves 16 or 17 loader calls inside a MIDI Note handler are race-free, latency-safe, or UI/state-neutral.
4. The known R01d early hook at `0x02005f9c` is explicitly revoked. `0x02005fa4` is after the stock storage reads and loader, but it is still in the same pre-return boot initializer and has no evidence of being safe for custom work before USB enumeration.
5. No other executable cave or app extension is owned. Safe app extension is 0 bytes, and generic zero/`0xff` runs remain unproved.

## Exact S1C5 address and ABI baseline

| Item | Exact range/value |
|---|---|
| Note Off hook | `0x0201c63e`, 6 bytes `80fffa1a0000`, target `0x0201e13e` |
| Note On hook | `0x0201c67c`, 6 bytes `80ffc01a0000`, target `0x0201e142` |
| Note Off Playback Note reload | `0x0201c644..0x0201c64a`, `lb.z r5,[r0]` plus two NOP-equivalent moves |
| Note On Playback Note reload | `0x0201c682..0x0201c688`, `lb.z r6,[r0]` plus two NOP-equivalent moves |
| Note On velocity store | `0x0201c68c`, `8d42`, preserved |
| selector | `0x0201e13e..0x0201e196`, 88 bytes |
| producer | `0x0201e196..0x0201e252`, 188 bytes |
| inert tail | `0x0201e252..0x0201e254`, 2 bytes |
| resident voices | `0x01c46520..0x01c46f20`, 16 records at stride `0xa0`, voice length `0x9c` |
| lock/count/state | `0x01c465bd/0x01c465be/0x01c465bf` |
| Playback Note map | `0x01c46f20..0x01c46f30`, 16 volatile bytes used by S1C5 |

At the common dispatcher `0x0201c5ec`, `r9` is the channel nibble. Note Off has trigger note in `r5`; Note On has trigger note in `r6` and velocity in `r5`. Both hooks enter with `r0=event destination`, `r1=stock current source`, and `r2=0x9c`. The S1C5 selector preserves `r4..r9` and `rets`, returns `r0=original destination+0x9c`, and the patched caller reloads the mapped note from `[r0]`.

A lazy initializer inserted here would therefore have to preserve the same frame, preserve Note On velocity, reacquire or reload `r2=0x9c` after every call, publish each slot valid last, publish state `ARMED=2` last, and return through the existing metadata-pointer ABI. No bytes are assigned for this because placement is blocked.

## Lazy first-Ch10 Note On/Off assessment

A first-event trigger is the narrowest lifecycle that definitely avoids the R01d pre-USB stage. The logical integration point is the current state test at `0x0201e164..0x0201e16a`, after channel/range acceptance and before resident-slot consumption.

**RAM-only direct materialization could be admissible in principle**, if an exact destination-parameter unpack routine and executable placement were proved. It must use the existing `testset` lock and fail closed if the producer is active. It must not perform storage I/O, change selected bank/preset, or call the global loader.

**Loader-based lazy materialization is rejected.** A full-set implementation would set Bank D and presets 0..15, call `0x02005660`, copy `0x9c` from `0x01c34c74` to each resident slot, restore the original selection, and call the loader again. That is 17 global loader executions in one MIDI event and does not reverse every intermediate helper/UI side effect. Per-slot lazy loading merely spreads the same unsafe global mutation across later Note events and creates active-note/UI race questions.

The first event may be Note Off. Any approved design must make initialization idempotent for both adapter entries and must never emit a custom Note Off from a different slot/generation than its Note On.

## Post-storage-init hook assessment

The stock initializer establishes storage pointers and reads persistent tables before the revoked callsite:

- `0x02005eee`: store runtime handle to `g+0x160`.
- `0x02005ef2`: store factory pointer to `g+0x164`.
- `0x02005f0e`: `0x02004870` reads 0x80 flag bytes from `+0x9180`.
- `0x02005f20`: `0x02004870` reads 9 selection bytes from `+0x9200`.
- `0x02005f9c`: stock loader call, the exact R01d-redirection site that must not be reused.
- `0x02005fa4`: stock post-loader initializer call with `r0=*(g+0x15c)`.
- `0x02005faa`: function returns.

`0x02005fa4` is the narrowest syntactic after-storage callsite, but not a safe approved hook. Redirecting its 4-byte call would require a wrapper that first preserves `0x020057e0`, and there is neither placement nor live proof that additional pre-USB work is safe. The exact-v15 evidence therefore contains **no automatic safe post-storage boot hook**.

## Existing `0x02005660` calls

| Callsite | Bytes | Classification | Return consumer |
|---|---|---|---|
{call_rows}

The SysEx callsites are post-USB but require host traffic, so they cannot provide autonomous power-cycle restore. The UI callsite requires a user bank/preset change. The default-load callsite is conditional runtime behavior, not a proven every-boot post-storage callback.

## Bank D 1..16 without embedding 2,496 bytes

**Source-data result: PASS. Device materializer result: BLOCK.**

For zero-based bank 3 and presets 0..15, packed sources are contiguous at `*(g+0x164)+0x3000..+0x3800`. No reference table is needed for this exact set. The clean-dump physical model is `0x0f7000..0x0f7800`. All 16 saved flags are zero, so the loader's first `0x9c` result is the pure packed-voice expansion.

The stock raw `0xa3` table cannot be copied directly. In the clean dump, Bank D 1..16 raw prefixes are the same placeholder hash and differ from their desired runtime voices by 82 to 101 bytes.

| Slot | Trigger | Patch | Name | Packed offset | Raw offset | Raw/runtime differing bytes |
|---:|---:|---|---|---:|---:|---:|
{record_rows}

The shortest safe architecture after future placement proof is:

```text
first accepted Ch10 note while state != ARMED
  -> testset existing lock; if busy, fail closed to stock
  -> state = LOADING; clear count/valid
  -> for i=0..15:
       packed = *(0x01c33260+0x164) + 0x3000 + i*0x80
       dest   = 0x01c46520 + i*0xa0
       unpack packed128 -> dest[0..0x9b] with destination-parameter, no globals
       dest[0x9c] = VALID last
       playback_map[i] = selected fixed policy
  -> csync; state = ARMED last; unlock
  -> resume the original S1C5 selector ABI
```

This is an architecture only, not an address/byte patch. It remains blocked until an exact PI32 routine fits a proven executable range and independently matches all 16 pinned runtime hashes.

## Playback Note persistence options

| Option | Persistent bytes | Decision |
|---|---:|---|
| Derive Original as `36+slot` | 0 data bytes | Only fixed Original playback survives power cycle without new storage. It can be generated during materialization. |
| Compile a fixed custom 16-byte map into app-owned read-only data | 16 bytes | BLOCK preserving S1C5 because the audited window has 2 spare bytes and safe app extension is 0. |
| Keep S1C5 wire byte 161 / RAM `0x01c46f20+slot` | 16 volatile bytes | Existing live-good behavior, but lost on power cycle. The producer restores voice byte `0x9b` to `0x3f`, so it is not in-record persistence. |
| Put 16 map bytes in a separate custom A/B record | 16 bytes plus header/domain overhead | BLOCK until a non-overlapping storage allocation, read lifecycle, commit semantics, and corruption/power-loss behavior are proved. |
| Reuse stock `0xa3` records, flags, or selection bytes | nominally small | BLOCK. Those fields have stock schema and ownership; changing them would couple Drum Set state to stock Patch SAVE and rollback. |

## Exact blocking gates

1. Prove an executable range large enough for a destination-parameter unpacker plus 16-slot loop while preserving S1C5 producer and selector behavior, or produce a fully reassembled smaller S1C5 implementation with exact review.
2. Independently decode and hash-check the on-device unpacker against all 16 pinned Bank D runtime objects.
3. Keep the first-note path RAM-only. No loader, storage read/write, selected-bank mutation, or UI-object mutation.
4. Prove lock/state behavior for Note On, Note Off, concurrent producer ingress, repeated hits, active notes, and failure fallback.
5. For custom Playback Notes, prove either app-owned literal placement or a separately owned persistent record. Current safe budgets are 2 app-window bytes and 0 custom storage bytes.
6. Do not use `0x02005f9c`. Do not promote `0x02005fa4` without separate post-USB/live proof.

## Reproduction

```sh
python3 baselines/v15/analysis/persistence-s2/restore/analyze_restore.py
(cd baselines/v15/analysis/persistence-s2/restore && shasum -a 256 -c SHA256SUMS)
```

Expected result: `RESULT BLOCK`, with all evidence checks passing. BLOCK is the design decision, not a validator failure.
"""


def main() -> int:
    checks: list[str] = []
    input_hashes: dict[str, str] = {}
    for name, expected in EXPECTED_SHA256.items():
        actual = shaf(PATHS[name])
        input_hashes[name] = actual
        req(actual == expected, f"{name} SHA-256 {expected}", checks)

    official = PATHS["official_app"].read_bytes()
    s1c5 = PATHS["s1c5_app"].read_bytes()
    combined = PATHS["s1c5_combined"].read_bytes()
    req(len(official) == len(s1c5) == 617012, "official and S1C5 app sizes are 617012", checks)

    exact_slices = {
        "note_off_hook": (0x0201C63E, "80fffa1a0000"),
        "note_off_reload": (0x0201C644, "0d4000160016"),
        "note_on_hook": (0x0201C67C, "80ffc01a0000"),
        "note_on_reload": (0x0201C682, "0e4000160016"),
        "note_on_velocity": (0x0201C68C, "8d42"),
        "direct_product": (0x0201E468, "bfeadefe"),
        "direct_loader": (0x0201E46C, "bfeaf838"),
        "segmented_product": (0x0201E49C, "bfeac4fe"),
        "segmented_loader": (0x0201E4A0, "bfeade38"),
    }
    for name, (address, expected_hex) in exact_slices.items():
        req(app_slice(s1c5, address, len(bytes.fromhex(expected_hex))).hex() == expected_hex,
            f"S1C5 {name} bytes at {hx(address)}", checks)
    req(app_slice(s1c5, 0x0201E13E, 0x116) == combined,
        "S1C5 audited 278-byte selector/producer window equals pinned combined blob", checks)

    decode = read_decode()
    req(decode[0]["address"] == "0x0201e13e" and decode[-1]["address"] == "0x0201e252",
        "S1C5 decode spans exact owned window", checks)
    selector_rows = [r for r in decode if r["name"].startswith("selector.")]
    producer_rows = [r for r in decode if r["name"].startswith("producer.")]
    selector_end = int(selector_rows[-1]["address"], 16) + int(selector_rows[-1]["size"])
    producer_end = int(producer_rows[-1]["address"], 16) + int(producer_rows[-1]["size"])
    req(selector_end == 0x0201E196 and selector_end - 0x0201E13E == 88,
        "selector is 88 bytes at 0x0201e13e..0x0201e196", checks)
    req(producer_end == 0x0201E252 and producer_end - selector_end == 188,
        "producer is 188 bytes at 0x0201e196..0x0201e252", checks)

    rows, loader_calls = read_listing()
    loader_addresses = [int(r["address"], 16) for r in loader_calls]
    expected_loader_addresses = [0x02005F9C, 0x0201E46C, 0x0201E4A0, 0x0202422E, 0x020255A6]
    req(loader_addresses == expected_loader_addresses, "official v15 has exactly five decoded direct calls to 0x02005660", checks)
    listing_expect = {
        0x02005EEE: ("d1ec6106", "sw r0,[r6 + 0x160]"),
        0x02005EF2: ("d1ec6556", "sw r5,[r6 + 0x164]"),
        0x02005F0E: ("bfeaaff4", "call 0x02004870"),
        0x02005F20: ("bfeaa6f4", "call 0x02004870"),
        0x02005F9C: ("bfea60fb", "call 0x02005660"),
        0x02005FA4: ("bfea1cfc", "call 0x020057e0"),
        0x02005FAA: ("5f04", "pop {pc,r15,r14,r13,r12,r11,r10,r9,r8,r7,r6,r5,r4}"),
        0x02005660: ("7804", "push {rets,r8,r7,r6,r5,r4}"),
        0x020056A0: ("51ac", "lsl r1,r5,0xc"),
        0x0200576C: ("b84f", "_sb r0,[r3 + 0xf]"),
        0x0200576E: ("6840", "lb.z r0,[r6 + 0x0]"),
    }
    for address, (expected_bytes, expected_asm) in listing_expect.items():
        req(rows[address]["bytes"] == expected_bytes and rows[address]["asm"] == expected_asm,
            f"listing anchor {hx(address)} {expected_asm}", checks)

    r01d = read_json(PATHS["r01d"])
    req(r01d["conclusion"]["most_likely_pre_usb_cause"].startswith("0x02005f9c"),
        "R01d evidence revokes 0x02005f9c early hook", checks)
    factory = read_json(PATHS["factory_loader"])
    req(factory["factory_loader"]["function"] == "0x02005660" and
        factory["factory_loader"]["abi"]["prototype"] == "void factory_loader_02005660(void)",
        "factory loader is global void ABI", checks)

    cave_capacity = 0x0201E254 - 0x0201E13E
    selector_bytes = 88
    producer_bytes = 188
    tail_bytes = cave_capacity - selector_bytes - producer_bytes
    known_unpack_body = 0x0200576E - 0x020056A0
    req(cave_capacity == 278 and tail_bytes == 2, "S1C5 owned window capacity 278, free tail 2", checks)
    req(known_unpack_body == 206, "known stock packed-to-runtime body 0x020056a0..0x0200576e is 206 bytes", checks)
    req(producer_bytes + tail_bytes == 190 and known_unpack_body - 190 == 16,
        "deleting producer and tail still leaves a 16-byte deficit before loop/publication", checks)

    app_extension = read_json(PATHS["app_extension"])
    req(app_extension["byte_accounting"]["naive_tail_after_app_inside_app_area"]["owner"] == "cfg_tool.bin",
        "app tail is owned by cfg_tool.bin", checks)
    req(all(item["decision"] == "BLOCK" for item in app_extension["extension_decisions"]),
        "all exact app extension options remain BLOCK", checks)

    persistence = read_json(PATHS["persistence"])
    req(persistence["official_layout"]["app_tail"]["safe_append_bytes"] == 0,
        "safe app append budget is zero", checks)
    req(any(item["decision"] == "BLOCK" and item["option"] == "persist custom data after +0x9209"
            for item in persistence["safe_options_now"]),
        "custom storage after stock +0x9209 remains BLOCK", checks)

    records = bank_d_records(checks)
    raw_prefix_hashes = sorted({r["raw_prefix_sha256"] for r in records})
    req(len(raw_prefix_hashes) == 1, "all clean Bank D 1..16 raw163 prefixes are the same placeholder", checks)

    loader_meta = {
        0x02005F9C: ("revoked pre-USB init callsite", "loads *(r6+0x15c), then calls 0x020057e0"),
        0x0201E46C: ("post-product direct SysEx reload", "immediate pop; return ignored"),
        0x0201E4A0: ("post-product segmented-final SysEx reload", "goto common continuation; return ignored"),
        0x0202422E: ("UI bank/preset change reload", "loads *(g+0x15c), then calls 0x020057e0"),
        0x020255A6: ("conditional default-load/bank-block reload", "falls through; return ignored"),
    }
    census = []
    for row in loader_calls:
        address = int(row["address"], 16)
        classification, consumer = loader_meta[address]
        census.append({**row, "classification": classification, "return_consumer": consumer})

    evidence = {
        "format": "smk37-v15-s1c5-power-cycle-restore-analysis-v1",
        "scope": {
            "v15_only": True,
            "findings_only": True,
            "firmware_built_or_modified": False,
            "device_accessed": False,
            "midi_opened_or_sent": False,
            "flash_or_ota_performed": False,
            "reset_performed": False,
        },
        "decision": "BLOCK",
        "decision_summary": "No exact safe additive S1C5 restore address exists. Fixed Bank D source data is available without 2496 embedded bytes, but safe destination-parameter materialization and executable placement are unproved.",
        "input_sha256": input_hashes,
        "s1c5_layout": {
            "note_off_hook": {"address": "0x0201c63e", "bytes": exact_slices["note_off_hook"][1], "target": "0x0201e13e"},
            "note_on_hook": {"address": "0x0201c67c", "bytes": exact_slices["note_on_hook"][1], "target": "0x0201e142"},
            "note_off_reload": {"address": "0x0201c644", "bytes": exact_slices["note_off_reload"][1], "abi": "load [r0] into r5"},
            "note_on_reload": {"address": "0x0201c682", "bytes": exact_slices["note_on_reload"][1], "abi": "load [r0] into r6; preserve velocity r5"},
            "owned_window": {"start": "0x0201e13e", "end_exclusive": "0x0201e254", "bytes": cave_capacity},
            "selector": {"start": "0x0201e13e", "end_exclusive": "0x0201e196", "bytes": selector_bytes},
            "producer": {"start": "0x0201e196", "end_exclusive": "0x0201e252", "bytes": producer_bytes},
            "free_tail": {"start": "0x0201e252", "end_exclusive": "0x0201e254", "bytes": tail_bytes},
            "resident_ram": {"start": "0x01c46520", "end_exclusive": "0x01c46f20", "bytes": 0xA00, "slot_stride": 0xA0, "voice_bytes": 0x9C},
            "control": {"lock": "0x01c465bd", "count": "0x01c465be", "state": "0x01c465bf", "empty": 0, "loading": 1, "armed": 2},
            "playback_map": {"start": "0x01c46f20", "end_exclusive": "0x01c46f30", "bytes": 16, "volatile": True},
        },
        "note_hook_abi": {
            "common_dispatcher": "0x0201c5ec",
            "channel": "r9 low nibble, Ch10 == 9",
            "note_off": "r5 trigger note; adapter r3=r5",
            "note_on": "r6 trigger note, r5 velocity; adapter r3=r6",
            "common_entry": "r0 event destination, r1 stock source, r2 0x9c",
            "return": "r0 = original destination + 0x9c; caller reloads Playback Note from [r0]",
            "preserved_by_selector": "rets and r4..r9",
            "lazy_integration_point": "logical reassembly at 0x0201e164..0x0201e16a state load/gate; no address approved for added code",
        },
        "byte_budget": {
            "preserve_s1c5_free_bytes": tail_bytes,
            "if_entire_producer_and_tail_deleted": producer_bytes + tail_bytes,
            "known_stock_unpack_body": {"start": "0x020056a0", "end_exclusive": "0x0200576e", "bytes": known_unpack_body, "destination_abi": "global 0x01c34c74 only"},
            "deficit_after_deleting_producer_before_any_outer_logic": known_unpack_body - (producer_bytes + tail_bytes),
            "safe_app_extension_bytes": 0,
            "safe_custom_storage_bytes": 0,
        },
        "storage_init_trace": [rows[a] for a in [0x02005EEE, 0x02005EF2, 0x02005F0E, 0x02005F20, 0x02005F9C, 0x02005FA4, 0x02005FAA]],
        "loader_census": census,
        "bank_d_materialization": {
            "source_data": "PASS",
            "device_materializer": "BLOCK",
            "packed_runtime_formula": "*(0x01c33260+0x164) + 0x3000 + slot*0x80 for slot 0..15",
            "destination_formula": "0x01c46520 + slot*0xa0; publish valid at +0x9c last",
            "embedded_runtime_payload_bytes_required": 0,
            "reference_table_bytes_required_for_exact_contiguous_D1_D16": 0,
            "raw163_direct_copy_usable": False,
            "records": records,
        },
        "playback_note_options": [
            {"option": "derive Original as 36+slot", "persistent_data_bytes": 0, "decision": "PASS only for fixed Original policy"},
            {"option": "compile fixed custom map", "persistent_data_bytes": 16, "decision": "BLOCK placement while preserving S1C5"},
            {"option": "existing wire byte 161 to RAM map", "persistent_data_bytes": 16, "decision": "VOLATILE; lost on power cycle"},
            {"option": "separate custom A/B persistent record", "persistent_data_bytes": 16, "decision": "BLOCK storage ownership and commit semantics"},
            {"option": "reuse stock records/flags/selection", "persistent_data_bytes": "nominally small", "decision": "BLOCK stock schema and rollback coupling"},
        ],
        "blocked_candidates": [
            {"candidate": "0x02005f9c early wrapper", "reason": "R01d revoked; likely pre-USB boot-failure cause"},
            {"candidate": "0x02005fa4 post-loader wrapper", "reason": "storage is loaded, but still pre-return boot initializer; no post-USB/live proof and no code placement"},
            {"candidate": "first Ch10 Note loader loop", "reason": "17 global loader calls for full set, helper/UI/global selection side effects, no latency or race proof"},
            {"candidate": "first-use per-slot loader", "reason": "same prohibited global mutation in active Note path, repeated across notes"},
            {"candidate": "side-effect-free direct unpack", "reason": "correct architecture but exact routine/address absent; known body 206 bytes exceeds 190 bytes even after deleting producer"},
            {"candidate": "embed 2496 runtime bytes", "reason": "no owned data placement; current window 278 bytes total and safe app extension 0"},
        ],
        "required_next_gates": [
            "prove executable placement for an exact destination-parameter unpacker plus loop while preserving S1C5 behavior",
            "independently decode and hash-match all 16 runtime outputs",
            "keep first-note initialization RAM-only with no loader/storage/UI selection mutation",
            "prove lock/state/failure/active-note behavior for both Note adapters and concurrent producer ingress",
            "prove 16-byte playback literal placement or a separate persistent allocation for custom Playback Notes",
        ],
        "validation_check_count": len(checks),
    }

    report = render_report(evidence)
    validation = "S1C5 restore evidence validation: PASS\n" + "\n".join(checks) + "\nRESULT\tBLOCK\n"
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(report, encoding="utf-8")
    (HERE / "validation.txt").write_text(validation, encoding="utf-8")

    files = ["analyze_restore.py", "evidence.json", "report.md", "validation.txt"]
    (HERE / "SHA256SUMS").write_text(
        "".join(f"{shaf(HERE / name)}  {name}\n" for name in files), encoding="utf-8"
    )
    print(f"validation checks: {len(checks)} PASS")
    print("RESULT BLOCK")
    print("No firmware/device/MIDI/flash/reset action performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
