#!/usr/bin/env python3
"""Offline fit-first design for the safest post-S1C7 S1C5 persistence successor.

This intentionally emits a BLOCK/design package, not firmware. It never opens a
USB/MIDI/device path and never uploads, flashes, or resets hardware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import struct
import zlib
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
FLASH = HERE.parent
S1C5 = FLASH / "S1C5-playback-register-return"
S1C7 = FLASH / "S1C7-current-set-helper-checkpoint"
S1C6_BLOCK = FLASH / "S1C6-raw17-persistence-block"
S2_BLOCK = FLASH / "S2-persistent-default"
DUMPS = ROOT / "baselines/v15/device-dumps"
OUT = HERE / "data-package"

BASE = 0x02000000
SEL_START = 0x0201E13E
SEL_END = 0x0201E196
PRODUCER_START = 0x0201E196
PRODUCER_END = 0x0201E252
OWNED_END = 0x0201E254
SAVE_HELPER = 0x02026D80
SAVE_EXIT = 0x02026DD4
READ_WRAPPER = 0x02004870
WRITE_WRAPPER = 0x02004B02
RECORD_BASE = 96
MANIFEST_RECORD = 112
SLOTS = 16
RAW_PHYS_BASE = 0x0F8000
RAW_STRIDE = 0xA3
PREFIX_LEN = 0x9C
VOICE_PAYLOAD_LEN = 0x9C
MANIFEST_MAGIC = b"SMK37S8P"
MANIFEST_VERSION = 1
COMMITTED_FLAG = 0xA5
HEADER = bytes.fromhex("f0430000011b")

EXPECTED = {
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "s1c5_live_validation": "94fc5083ff1ce1061c474eba18a30ad3f10a277f85c84f6cee5a117c2593f152",
    "s1c5_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "s1c5_producer": "53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4",
    "s1c7_app": "71cfc1fcbeecd1a9277f88272be6b122a96f33fbd741d7486c670ffab6e58646",
    "s1c7_fwsc": "3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593",
    "s1c7_review": "f6618ee0246c8356ac77db1504e2f1e994677e4e4dacba2e68df92cc01759a13",
    "s1c6_block_report": "3dc0f88c91fb2a07b3ce9fa7c38ddd5d321974786e26a079b3158f754d209fcf",
    "s2_block_report": "451150aadbde8ce9967ec53b165b145023b1d04870db1d92925a86f2948e4dba",
    "clean_dump": "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b",
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


def app_off(address: int) -> int:
    return address - BASE


def u32le(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def gate_inputs() -> tuple[bytes, bytes, dict[str, Any]]:
    paths = {
        "s1c5_app": S1C5 / "app.bin",
        "s1c5_fwsc": S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc",
        "s1c5_live_validation": S1C5 / "live-validation-20260804.md",
        "s1c7_app": S1C7 / "app.bin",
        "s1c7_fwsc": S1C7 / "SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc",
        "s1c7_review": S1C7 / "reviews/jcode-independent-review-20260804T1251Z/report.md",
        "s1c6_block_report": S1C6_BLOCK / "report.md",
        "s2_block_report": S2_BLOCK / "report.md",
        "clean_dump_a": DUMPS / "v15-clean-baseline-a.bin",
        "clean_dump_b": DUMPS / "v15-clean-baseline-b.bin",
    }
    gates: dict[str, Any] = {}
    for name, path in paths.items():
        key = "clean_dump" if name.startswith("clean_dump_") else name
        actual = shaf(path)
        req(actual == EXPECTED[key], f"{name} hash")
        gates[name] = {"path": rel(path), "sha256": actual, "status": "PASS"}
    clean_a = paths["clean_dump_a"].read_bytes()
    clean_b = paths["clean_dump_b"].read_bytes()
    req(clean_a == clean_b and len(clean_a) == 1024 * 1024, "clean dump twins are identical 1MiB images")
    app = paths["s1c5_app"].read_bytes()
    req(sha(app[app_off(SEL_START):app_off(OWNED_END)]) == EXPECTED["s1c5_combined"], "S1C5 selector/producer combined hash")
    req(sha(app[app_off(PRODUCER_START):app_off(OWNED_END)]) == EXPECTED["s1c5_producer"], "S1C5 producer hash")
    gates["s1c5_selector_producer_identity"] = {
        "selector_start": hx(SEL_START),
        "selector_end_exclusive": hx(SEL_END),
        "producer_start": hx(PRODUCER_START),
        "producer_end_exclusive": hx(OWNED_END),
        "combined_sha256": EXPECTED["s1c5_combined"],
        "producer_sha256": EXPECTED["s1c5_producer"],
        "status": "PASS",
    }
    return app, clean_a, gates


def packet_payloads() -> list[dict[str, Any]]:
    manifest = json.loads((S1C5 / "inputs/packets/packet-manifest.json").read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for item in sorted(manifest["packets"], key=lambda x: x["slot"]):
        slot = int(item["slot"])
        pkt_path = S1C5 / "inputs/packets" / item["file"]
        pkt = pkt_path.read_bytes()
        req(len(pkt) == 163 and pkt.startswith(HEADER) and pkt[-1] == 0xF7, f"packet framing slot {slot}")
        payload = pkt[len(HEADER):-1]
        req(len(payload) == VOICE_PAYLOAD_LEN, f"packet payload length slot {slot}")
        rows.append({
            "slot": slot,
            "file": rel(pkt_path),
            "packet_sha256": sha(pkt),
            "payload": payload,
            "playback_note": payload[0x9B] & 0x7F,
        })
    req([r["slot"] for r in rows] == list(range(SLOTS)), "packet slots 0..15")
    return rows


def clean_record(clean: bytes, index: int) -> bytes:
    start = RAW_PHYS_BASE + index * RAW_STRIDE
    end = start + RAW_STRIDE
    req(end <= len(clean), f"clean raw record {index} in dump")
    return clean[start:end]


def build_records(clean: bytes) -> dict[str, Any]:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    rows = packet_payloads()
    payload_records: list[bytes] = []
    record_info: list[dict[str, Any]] = []
    notes = bytearray()
    for row in rows:
        slot = row["slot"]
        index = RECORD_BASE + slot
        base = bytearray(clean_record(clean, index))
        tail = bytes(base[PREFIX_LEN:RAW_STRIDE])
        payload = row["payload"]
        base[:0x9B] = payload[:0x9B]
        base[0x9B] = row["playback_note"]
        # 0x9c..0xa2 remain forced-seeded from the clean v15 twin dump.
        out_name = f"payload-record-{index:03d}-slot-{slot:02d}.bin"
        (OUT / out_name).write_bytes(base)
        payload_records.append(bytes(base))
        notes.append(row["playback_note"])
        record_info.append({
            "slot": slot,
            "trigger_note": 36 + slot,
            "record_index": index,
            "physical_offset": hx(RAW_PHYS_BASE + index * RAW_STRIDE, 6),
            "storage_offset": hx(0x4000 + index * RAW_STRIDE, 4),
            "file": out_name,
            "sha256": sha(base),
            "crc32": hx(crc32(base)),
            "playback_note": row["playback_note"],
            "tail_policy": "forced seeded from exact clean v15 dump twins, not preserved from an unknown target",
            "tail_hex": tail.hex(),
            "source_packet": row["file"],
            "source_packet_sha256": row["packet_sha256"],
        })
    joined = b"".join(payload_records)
    record_crcs = [crc32(r) for r in payload_records]
    manifest = bytearray(clean_record(clean, MANIFEST_RECORD))
    manifest[:PREFIX_LEN] = b"\x00" * PREFIX_LEN
    manifest[0:8] = MANIFEST_MAGIC
    manifest[8] = MANIFEST_VERSION
    manifest[9] = COMMITTED_FLAG
    manifest[10] = 1  # layout: full raw records, playback note in byte 0x9b.
    manifest[11] = SLOTS
    manifest[12] = RECORD_BASE
    manifest[13] = MANIFEST_RECORD
    manifest[14:16] = struct.pack("<H", RAW_STRIDE)
    manifest[16:18] = struct.pack("<H", RAW_STRIDE)
    manifest[18:20] = struct.pack("<H", PREFIX_LEN)
    manifest[20:24] = u32le(1)  # generation for this deterministic offline image.
    manifest[24:28] = u32le(crc32(joined))
    manifest[28:32] = u32le(crc32(notes))
    pos = 32
    for c in record_crcs:
        manifest[pos:pos + 4] = u32le(c)
        pos += 4
    manifest[96:112] = bytes(notes)
    manifest[112:116] = b"\x00" * 4
    header_crc = crc32(manifest[:PREFIX_LEN])
    manifest[112:116] = u32le(header_crc)
    manifest_name = f"manifest-record-{MANIFEST_RECORD:03d}.bin"
    (OUT / manifest_name).write_bytes(manifest)
    combined = joined + bytes(manifest)
    (OUT / "candidate-records-096-112.bin").write_bytes(combined)
    pkg = {
        "format": "smk37-v15-s1c8-manifest-gated-persistence-data-v1",
        "scope": {
            "offline_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "persistent_storage_write_performed": False,
            "firmware_candidate": False,
        },
        "record_range": [RECORD_BASE, MANIFEST_RECORD],
        "payload_record_count": SLOTS,
        "manifest_record": MANIFEST_RECORD,
        "manifest_magic": MANIFEST_MAGIC.decode("ascii"),
        "manifest_version": MANIFEST_VERSION,
        "committed_flag": hx(COMMITTED_FLAG, 2),
        "payload_crc32": hx(crc32(joined)),
        "notes_crc32": hx(crc32(notes)),
        "header_crc32": hx(header_crc),
        "combined_records_sha256": sha(combined),
        "combined_records_file": "candidate-records-096-112.bin",
        "records": record_info,
        "manifest_file": manifest_name,
        "manifest_sha256": sha(manifest),
        "rollback_requirement": "target-specific full pre-dump and full post-rollback byte equality are mandatory before any external seed writer may be considered",
        "positive_gate_contract": "firmware must reject unless magic/version/layout/count/record base/manifest record/lengths/committed flag/header CRC/payload CRC/per-record CRCs all validate before touching S1C5 RAM",
    }
    (OUT / "package-manifest.json").write_text(json.dumps(pkg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pkg


def lower_bounds() -> dict[str, Any]:
    helper_bytes = SAVE_EXIT - SAVE_HELPER
    s1c7_helper_payload = 84
    minimum_manifest_read_setup = 6 + 6 + 2 + 6  # mov32 storage, mov32 scratch, mov8 length, call read wrapper.
    minimum_magic_check = 8 * (2 + 4)  # lb + jne for each magic byte, before version/count/CRC.
    minimum_crc_status = "no exact callable runtime CRC routine or compact PI32 implementation is proven"
    return {
        "owned_s1c5_window": {
            "start": hx(SEL_START),
            "end_exclusive": hx(OWNED_END),
            "bytes": OWNED_END - SEL_START,
            "exact_s1c5_selector_bytes": SEL_END - SEL_START,
            "exact_s1c5_producer_bytes": PRODUCER_END - PRODUCER_START,
            "inert_tail_bytes": OWNED_END - PRODUCER_END,
            "producer_plus_tail_hash_window_bytes": OWNED_END - PRODUCER_START,
            "free_bytes_when_preserving_exact_s1c5_selector_and_producer": 0,
        },
        "disabled_save_helper_window": {
            "start": hx(SAVE_HELPER),
            "end_exclusive": hx(SAVE_EXIT),
            "bytes": helper_bytes,
            "s1c7_no_manifest_helper_bytes": s1c7_helper_payload,
            "free_after_s1c7_style_no_manifest_helper": helper_bytes - s1c7_helper_payload,
        },
        "positive_gate_floor": {
            "manifest_read_setup_floor_bytes": minimum_manifest_read_setup,
            "magic_only_compare_floor_bytes": minimum_magic_check,
            "version_layout_count_commit_crc_checks": "additional, not included in floor",
            "crc_implementation": minimum_crc_status,
            "decision": "BLOCK_FIT_AND_ABI",
            "reason": "The S1C7 no-manifest fallback already consumed the whole disabled SAVE helper window. Adding even manifest read plus magic checks exceeds it before CRC, payload reads, rollback fallback, or return ABI repair.",
        },
        "writer_floor": {
            "required": [
                f"write with {hx(WRITE_WRAPPER)} and accept only return == requested_length",
                f"read back with {hx(READ_WRAPPER)} and verify exact payload",
                "compute/update manifest CRC and write manifest last",
                "report failure rather than silently clearing dirty/SAVED state",
            ],
            "decision": "BLOCK_BY_PRIOR_FIT_AND_PLACEMENT_GATES",
            "basis": rel(S1C6_BLOCK / "report.md"),
        },
        "boot_or_lazy_load_hooks": {
            "post_storage_boot_hooks": "0x02005f9c revoked; 0x02005fa4 lacks live proof and wrapper placement",
            "first_note_lazy_load": "safest lifecycle if placement is later proved, because it keeps USB/WebMIDI initialized and can let dynamic SysEx ARMED RAM override persistent restore",
            "decision": "DESIGN_ONLY_BLOCKED_BY_PLACEMENT",
        },
    }


def build_evidence() -> dict[str, Any]:
    _, clean, gates = gate_inputs()
    data_pkg = build_records(clean)
    fit = lower_bounds()
    requirements = {
        "preserve_exact_s1c5_selector_producer_and_web_coremidi": {
            "status": "PASS_BY_NO_FIRMWARE_EMITTED_AND_PINNED_BASELINE",
            "selector_producer_sha256": EXPECTED["s1c5_combined"],
            "producer_sha256": EXPECTED["s1c5_producer"],
        },
        "unseeded_device_behaves_exactly_s1c5": {
            "status": "PASS_ONLY_FOR_BLOCK_PACKAGE",
            "rule_for_future_firmware": "on missing/invalid manifest, jump to exact S1C5 RAM/stock path without reading payload records or modifying Ch10 RAM",
        },
        "persistent_data_positively_gated_by_manifest_magic_crc": {
            "data_format_status": "PASS",
            "firmware_status": "BLOCK_FIT_ABI",
            "manifest_magic": data_pkg["manifest_magic"],
            "payload_crc32": data_pkg["payload_crc32"],
        },
        "dynamic_sysex_overrides_persistent_restore": {
            "status": "DESIGN_RULE_RECORDED_NO_FIRMWARE",
            "rule": "if S1C5 ARMED state and selected slot valid are present, selector must consume live RAM; persistent restore may run only when not ARMED and must stop once producer ingress arms RAM",
        },
        "playback_notes_may_duplicate": {
            "status": "PASS_IN_DATA_AND_S1C5_BASELINE",
            "notes": [r["playback_note"] for r in data_pkg["records"]],
        },
        "forced_seeded_tail_records": {
            "status": "DATA_PACKAGE_ONLY",
            "rule": "payload record tails 0x9c..0xa2 are forced to exact clean-v15 twin-dump bytes; target-specific rollback remains mandatory before any external writer",
        },
        "separate_manifest_record": {
            "status": "PASS_IN_DATA_FORMAT",
            "record": MANIFEST_RECORD,
        },
        "lazy_boot_load": {
            "status": "DESIGN_ONLY_BLOCKED",
            "rule": "first accepted Ch10 note after storage init is the least risky future hook, not pre-USB boot; exact placement is not available",
        },
    }
    evidence = {
        "format": "smk37-v15-s1c8-manifest-gated-persistence-block-v1",
        "decision": "BLOCK",
        "firmware_artifacts_emitted": False,
        "reason": "After S1C7 failed silent, a successor cannot trust raw records unless manifest/magic/CRC validation and fail-closed unseeded behavior are implemented. Exact S1C5 preservation leaves no defensible placement for that validator or a verified writer.",
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "reset_performed": False},
        "input_gates": gates,
        "s1c7_live_result_from_prompt": "failed silent; therefore S1C7 no-manifest fallback is treated as disqualified for successor promotion",
        "requirements": requirements,
        "data_package": data_pkg,
        "fit_and_abi_gates": fit,
        "successor_contract_if_unblocked": [
            "Start from exact S1C5 app and preserve the exact selector/producer behavior for ARMED RAM and all Web/CoreMIDI producer paths.",
            "Reserve payload records 96..111 and manifest record 112 only behind a manifest that validates magic/version/layout/count/record base/lengths/committed flag/header CRC/payload CRC/per-record CRCs.",
            "On unseeded or corrupt storage, do nothing and return through the exact S1C5 behavior. No silent partial restore is allowed.",
            "Make dynamic SysEx authoritative: producer ingress updates volatile RAM and Playback Note map, and valid ARMED RAM overrides any persistent default until reboot or explicit future save.",
            "For writes, write payloads first, verify each full-length write by readback, then write/verify manifest last; never report SAVED or clear dirty on unchecked writes.",
            "Keep playback notes as data bytes and never collapse duplicate notes into source-slot identity.",
        ],
        "blockers": [
            "No exact callable runtime CRC ABI or compact in-place CRC implementation is proved.",
            "S1C7's 84-byte helper had no positive manifest gate and already filled the disabled SAVE helper window.",
            "Preserving exact S1C5 selector and producer leaves no owned bytes in the 0x0201e13e..0x0201e254 window.",
            "A verified writer with 0x02004b02 full-length checks, 0x02004870 readback, CRC, commit-last ordering, and failure reporting has no defensible placement.",
            "Post-storage boot hooks remain unproved or revoked; first-note lazy load is only an architecture until code placement passes.",
        ],
    }
    return evidence


def render_report(e: dict[str, Any]) -> str:
    pkg = e["data_package"]
    fit = e["fit_and_abi_gates"]
    notes = ", ".join(str(n) for n in e["requirements"]["playback_notes_may_duplicate"]["notes"])
    return f"""# S1C8 manifest-gated persistence successor: BLOCK/design package

## Decision

**BLOCK.** No `app.bin`, FWSC, exact OTA wrapper, rollback flasher, or device writer is emitted.

S1C5 remains the only live-validated baseline. Because S1C7 failed silent, the next persistence successor must reject unseeded or corrupt data by positive manifest validation before touching runtime RAM. That stronger gate does not fit any owned/exact placement while preserving S1C5 selector, producer, WebMIDI/CoreMIDI behavior, and rollback expectations.

## Requirements outcome

| Requirement | Outcome |
|---|---|
| Preserve exact S1C5 selector/producer and Web/CoreMIDI behavior | PASS for this package by emitting no firmware; pinned combined SHA-256 `{EXPECTED['s1c5_combined']}` and producer SHA-256 `{EXPECTED['s1c5_producer']}`. |
| Unseeded device behaves exactly S1C5 | PASS only because no firmware is emitted. Future firmware must fail closed to the exact S1C5 path on missing/invalid manifest. |
| Persistent data gated by manifest/magic/CRC | Data-format PASS, firmware BLOCK. Manifest magic `{pkg['manifest_magic']}`, payload CRC `{pkg['payload_crc32']}`, header CRC `{pkg['header_crc32']}`. |
| Dynamic SysEx overrides persistent restore | Design rule recorded: ARMED+valid S1C5 RAM wins; persistent restore is only a not-ARMED fallback. |
| Playback notes may duplicate | PASS. Proposed record image carries notes `{notes}` and does not collapse source identity. |
| Forced-seeded tail records | Data package only. Payload record tails `0x9c..0xa2` are forced from exact clean-v15 twin dumps. |
| Separate manifest record | PASS in data format: record `{MANIFEST_RECORD}`. |
| Lazy boot load | Design only. The least risky future lifecycle is first accepted Ch10 note after storage init, not a pre-USB boot hook. |

## Offline data package, not a firmware candidate

The generated data package is under `data-package/`:

- `candidate-records-096-112.bin`: SHA-256 `{pkg['combined_records_sha256']}`.
- `manifest-record-112.bin`: SHA-256 `{pkg['manifest_sha256']}`.
- `package-manifest.json`: records 96..111 plus manifest record 112.

Payload encoding for each slot is:

```text
raw[0x00..0x9a] = exact S1C5 packet voice bytes 0x00..0x9a
raw[0x9b]       = Playback Note byte, 0..127
raw[0x9c..0xa2] = forced clean-v15 tail bytes from identical twin dumps
```

Manifest prefix fields include magic, version, committed flag, layout, record base, manifest record, lengths, generation, payload CRC32, note CRC32, per-record CRC32 values, the 16 Playback Notes, and a header CRC32 with its own field zeroed.

## Fit and ABI blockers

| Gate | Result |
|---|---|
| S1C5 owned window | `{fit['owned_s1c5_window']['bytes']}` bytes total, exact selector `{fit['owned_s1c5_window']['exact_s1c5_selector_bytes']}`, producer `{fit['owned_s1c5_window']['exact_s1c5_producer_bytes']}`, inert tail `{fit['owned_s1c5_window']['inert_tail_bytes']}`, no free bytes. |
| Disabled SAVE helper window | `{fit['disabled_save_helper_window']['bytes']}` bytes. The S1C7 no-manifest helper already consumed `{fit['disabled_save_helper_window']['s1c7_no_manifest_helper_bytes']}` bytes. |
| Positive manifest gate | BLOCK. Manifest read setup floor `{fit['positive_gate_floor']['manifest_read_setup_floor_bytes']}` bytes and magic-only compare floor `{fit['positive_gate_floor']['magic_only_compare_floor_bytes']}` bytes already exceed the filled helper before version/count/commit/CRC. |
| CRC ABI | BLOCK. {fit['positive_gate_floor']['crc_implementation']} |
| Writer | BLOCK. A writer still needs `0x02004b02` full-length checks, `0x02004870` readback, CRC, commit-last manifest, and non-silent failure reporting. |
| Boot/lazy hook | BLOCK for code. `0x02005f9c` is revoked; `0x02005fa4` lacks proof; first-note lazy load has no placement. |

## Safe successor contract if future evidence unblocks placement

1. Start from exact S1C5 and keep ARMED+valid volatile RAM behavior byte-for-byte.
2. Validate manifest magic/version/layout/count/record base/lengths/committed flag/header CRC/payload CRC/per-record CRC before any restore.
3. On unseeded, corrupt, short-read, ambiguous generation, or CRC mismatch, do nothing and return through exact S1C5 behavior.
4. Let dynamic SysEx producer override persistent restore for the session.
5. For future writes, write payloads first, verify by readback, then write/verify manifest last. Never silently claim SAVED.
6. Preserve duplicate Playback Notes as note data, not source-slot identity.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C8-manifest-gated-persistence-block && shasum -a 256 -c SHA256SUMS)
```
"""


def write_hashes() -> None:
    files = [p for p in HERE.rglob("*") if p.is_file() and p.name != "SHA256SUMS"]
    lines = []
    for p in sorted(files, key=lambda x: str(x.relative_to(HERE))):
        lines.append(f"{shaf(p)}  {p.relative_to(HERE)}")
    (HERE / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="rebuild and validate deterministic outputs")
    args = ap.parse_args()
    evidence = build_evidence()
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
    (HERE / "README.md").write_text("# S1C8 manifest-gated persistence block\n\nThis directory is a deterministic offline BLOCK/design package. Run `python3 analyze.py --check` and `python3 validate.py`.\n", encoding="utf-8")
    write_hashes()
    if args.check:
        req(evidence["decision"] == "BLOCK", "decision is BLOCK")
        req(not any((HERE / n).exists() for n in ["app.bin", "exact_ota.c", "SMK37Pro-v15-S1C8-manifest-gated-persistence-block.fwsc"]), "no firmware artifacts")
    print("S1C8 manifest-gated persistence analysis BLOCK; deterministic outputs rebuilt")


if __name__ == "__main__":
    main()
