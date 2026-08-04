#!/usr/bin/env python3
"""Independent minimum-budget S1C5 persistence fit analysis.

This emits a deterministic BLOCK/design package only. It never opens USB, MIDI,
flash, OTA, or device paths and never emits firmware bytes.
"""
from __future__ import annotations

import argparse
import gzip
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
DATA = HERE / "data-package"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
S1C7_ROOT = FLASH / "S1C7-live-failure-root-cause-20260804/report.md"
S1C8_BLOCK = FLASH / "S1C8-manifest-gated-persistence-block/report.md"

BASE = 0x02000000
SLOTS = 16
RECORD_BASE = 96
MANIFEST_RECORD = 112
PREFIX_LEN = 0x9C
RAW_STRIDE = 0xA3
HEADER = bytes.fromhex("f0430000011b")
MAGIC = b"SMK37S9P"
COMMITTED = 0xA5

ADDR = {
    "read_wrapper": 0x02004870,
    "write_wrapper": 0x02004B02,
    "factory_loader": 0x02005660,
    "factory_bank_bound": 0x02005670,
    "factory_preset_bound": 0x0200567E,
    "derived_init": 0x020057E0,
    "memcpy": 0x02048CCE,
    "strcmp": 0x02048DBC,
    "crc32_table": 0x02059210,
    "s1c5_selector_start": 0x0201E13E,
    "s1c5_selector_end": 0x0201E196,
    "s1c5_producer_start": 0x0201E196,
    "s1c5_owned_end": 0x0201E254,
    "save_helper_start": 0x02026D80,
    "save_helper_end": 0x02026DD4,
}

EXPECTED = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "quark_listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "s1c5_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "s1c5_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "s1c5_producer": "53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4",
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


def crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def load_listing_rows() -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    with gzip.open(LISTING, "rt", encoding="utf-8") as f:
        header = next(f).rstrip("\n").split("\t")
        for line in f:
            cols = line.rstrip("\n").split("\t")
            if len(cols) != len(header):
                continue
            row = dict(zip(header, cols))
            try:
                rows[int(row["address"], 16)] = row
            except ValueError:
                pass
    return rows


def gate_inputs() -> tuple[bytes, dict[str, Any]]:
    gates = {
        "official_app": {"path": rel(OFFICIAL_APP), "sha256": shaf(OFFICIAL_APP)},
        "official_fwsc": {"path": rel(OFFICIAL_FWSC), "sha256": shaf(OFFICIAL_FWSC)},
        "quark_listing": {"path": rel(LISTING), "sha256": shaf(LISTING)},
        "s1c5_app": {"path": rel(S1C5 / "app.bin"), "sha256": shaf(S1C5 / "app.bin")},
        "s1c5_fwsc": {"path": rel(S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc"), "sha256": shaf(S1C5 / "SMK37Pro-v15-S1C5-playback-register-return.fwsc")},
        "s1c7_root_cause_report": {"path": rel(S1C7_ROOT), "sha256": shaf(S1C7_ROOT)},
        "s1c8_prior_block_report": {"path": rel(S1C8_BLOCK), "sha256": shaf(S1C8_BLOCK)},
    }
    for key, expected in EXPECTED.items():
        if key not in gates:
            continue
        req(gates[key]["sha256"] == expected, f"{key} hash gate")
        gates[key]["status"] = "PASS"
    app = (S1C5 / "app.bin").read_bytes()
    combined = app[off(ADDR["s1c5_selector_start"]):off(ADDR["s1c5_owned_end"])]
    producer = app[off(ADDR["s1c5_producer_start"]):off(ADDR["s1c5_owned_end"])]
    req(sha(combined) == EXPECTED["s1c5_combined"], "S1C5 selector+producer combined hash")
    req(sha(producer) == EXPECTED["s1c5_producer"], "S1C5 producer hash")
    gates["s1c5_window_identity"] = {
        "status": "PASS",
        "selector_start": hx(ADDR["s1c5_selector_start"]),
        "selector_end_exclusive": hx(ADDR["s1c5_selector_end"]),
        "producer_start": hx(ADDR["s1c5_producer_start"]),
        "owned_end_exclusive": hx(ADDR["s1c5_owned_end"]),
        "combined_sha256": EXPECTED["s1c5_combined"],
        "producer_sha256": EXPECTED["s1c5_producer"],
    }
    return app, gates


def std_crc32_table() -> bytes:
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (0xEDB88320 ^ (c >> 1)) if (c & 1) else (c >> 1)
        table.append(c & 0xFFFFFFFF)
    return b"".join(struct.pack("<I", c) for c in table)


def helper_inventory(app: bytes, rows: dict[int, dict[str, str]]) -> dict[str, Any]:
    table = std_crc32_table()
    table_slice = app[off(ADDR["crc32_table"]):off(ADDR["crc32_table"])+len(table)]
    table_refs = []
    needle = struct.pack("<I", ADDR["crc32_table"])
    pos = app.find(needle)
    while pos != -1:
        table_refs.append(hx(BASE + pos))
        pos = app.find(needle, pos + 1)
    wanted_rows = [
        0x02004870, 0x02004872, 0x02004874, 0x02004876, 0x02004878, 0x0200487A, 0x0200487E, 0x02004880, 0x02004882,
        0x02004B02, 0x02004B04, 0x02004B06, 0x02004B08, 0x02004B0A, 0x02004B0C, 0x02004B10, 0x02004B12, 0x02004B14,
        0x02005660, 0x02005670, 0x0200567E, 0x02005694, 0x02005698, 0x0200569A, 0x020057DE,
        0x020057E0, 0x02005886,
        0x02048CCE, 0x02048D0E, 0x02048DBC, 0x02048E56, 0x02048E58,
    ]
    row_text = {hx(a): rows[a]["text"] for a in wanted_rows if a in rows}
    req("push" in row_text[hx(0x02048CCE)] and "pop" in row_text[hx(0x02048D0E)], "memcpy rows present")
    req("push" in row_text[hx(0x02048DBC)] and "pop" in row_text[hx(0x02048E56)], "strcmp rows present")
    req(table_slice == table, "standard CRC32 table present")
    req(not table_refs, "no direct 32-bit immediate refs to CRC32 table start")
    return {
        "crc_or_checksum": {
            "verdict": "BLOCK_NO_CALLABLE_ABI",
            "standard_crc32_table": {"address": hx(ADDR["crc32_table"]), "bytes": len(table), "sha256": sha(table_slice), "direct_imm32_refs_to_table_start": table_refs},
            "finding": "An exact IEEE CRC32 table is present as data, but no exact callable CRC/checksum routine ABI, callers, register convention, or side-effect profile is proven. A new PI32 CRC loop would still need code placement.",
        },
        "bounded_memcmp": {
            "verdict": "BLOCK_NOT_LOCATED",
            "closest_stock_helper": {"address": hx(ADDR["strcmp"]), "classification": "strcmp/zero-terminated compare", "entry_row": row_text[hx(0x02048DBC)], "return_row": row_text[hx(0x02048E56)]},
            "why_not_enough": "0x02048dbc has no length argument and stops at NUL, so it is not a binary bounded memcmp for a 0x9c manifest/prefix record.",
        },
        "memcpy": {
            "verdict": "PASS_COPY_ONLY",
            "address": hx(ADDR["memcpy"]),
            "abi": "r0=dst, r1=src, r2=len; preserves r6/r5/r4; clobbers volatile registers",
            "entry_row": row_text[hx(0x02048CCE)],
            "return_row": row_text[hx(0x02048D0E)],
        },
        "storage_read": {
            "verdict": "PASS_FULL_LENGTH_READ_WRAPPER",
            "address": hx(ADDR["read_wrapper"]),
            "abi": "r0=ram_destination, r1=storage_offset, r2=requested_length; returns requested_length on complete read, else 0",
            "rows": {k: v for k, v in row_text.items() if "0x0200487" in k or k == "0x02004882"},
        },
        "storage_write": {
            "verdict": "PASS_FULL_LENGTH_WRITE_WRAPPER_BUT_WRITER_UNPLACED",
            "address": hx(ADDR["write_wrapper"]),
            "abi": "r0=ram_source, r1=storage_offset, r2=requested_length; returns requested_length on complete write, else 0",
            "rows": {k: v for k, v in row_text.items() if "0x02004b" in k.lower()},
        },
        "bounds": {
            "verdict": "PASS_STOCK_GLOBAL_BANK_PRESET_ONLY",
            "callable": hx(ADDR["factory_loader"]),
            "rows": {hx(a): row_text[hx(a)] for a in [0x02005660, 0x02005670, 0x0200567E, 0x02005694, 0x02005698, 0x0200569A, 0x020057DE]},
            "why_not_enough": "0x02005660 bounds only selected global bank<=3 and preset<=31 before loading the current stock patch. It does not bound or validate a custom manifest, record base, slot count, generation, or per-record CRCs.",
        },
        "state_publication": {
            "verdict": "PASS_STOCK_CURRENT_STATE_AND_S1C5_ARMED_POLICY_IDENTIFIED",
            "stock_loader": hx(ADDR["factory_loader"]),
            "derived_initializer": hx(ADDR["derived_init"]),
            "s1c5_producer_window": {"start": hx(ADDR["s1c5_producer_start"]), "end_exclusive": hx(ADDR["s1c5_owned_end"]), "sha256": EXPECTED["s1c5_producer"], "policy": "runtime SysEx producer publishes resident slots and ARMED last; successor must leave ARMED+valid RAM override byte-for-byte"},
            "rows": {hx(a): row_text[hx(a)] for a in [0x020057E0, 0x02005886]},
        },
    }


def packet_rows() -> list[dict[str, Any]]:
    manifest = json.loads((S1C5 / "inputs/packets/packet-manifest.json").read_text(encoding="utf-8"))
    rows = []
    for item in sorted(manifest["packets"], key=lambda x: x["slot"]):
        slot = int(item["slot"])
        pkt = (S1C5 / "inputs/packets" / item["file"]).read_bytes()
        req(len(pkt) == 163 and pkt.startswith(HEADER) and pkt[-1] == 0xF7, f"packet {slot} framing")
        payload = pkt[len(HEADER):-1]
        req(len(payload) == PREFIX_LEN, f"packet {slot} payload length")
        prefix = payload[:0x9B] + bytes([payload[0x9B] & 0x7F])
        rows.append({"slot": slot, "file": item["file"], "packet_sha256": sha(pkt), "prefix": prefix, "playback_note": prefix[0x9B]})
    req([r["slot"] for r in rows] == list(range(SLOTS)), "packet slots 0..15")
    return rows


def build_data_package() -> dict[str, Any]:
    if DATA.exists():
        shutil.rmtree(DATA)
    DATA.mkdir(parents=True)
    rows = packet_rows()
    prefixes = []
    records = []
    notes = bytearray()
    for row in rows:
        slot = row["slot"]
        idx = RECORD_BASE + slot
        prefix = row["prefix"]
        name = f"payload-prefix-record-{idx:03d}-slot-{slot:02d}.bin"
        (DATA / name).write_bytes(prefix)
        prefixes.append(prefix)
        notes.append(row["playback_note"])
        records.append({
            "slot": slot,
            "record_index": idx,
            "storage_offset": hx(0x4000 + idx * RAW_STRIDE, 4),
            "physical_offset": hx(0x0F8000 + idx * RAW_STRIDE, 6),
            "prefix_file": name,
            "prefix_len": PREFIX_LEN,
            "prefix_sha256": sha(prefix),
            "prefix_crc32": hx(crc32(prefix)),
            "playback_note": row["playback_note"],
            "tail_policy": "do not write raw bytes 0x9c..0xa2; target-specific tails must remain unchanged",
            "source_packet": row["file"],
            "source_packet_sha256": row["packet_sha256"],
        })
    joined = b"".join(prefixes)
    manifest = bytearray(PREFIX_LEN)
    manifest[0:8] = MAGIC
    manifest[8] = 1
    manifest[9] = COMMITTED
    manifest[10] = 1  # layout: 16 payload prefixes + one manifest prefix.
    manifest[11] = SLOTS
    manifest[12] = RECORD_BASE
    manifest[13] = MANIFEST_RECORD
    manifest[14:16] = struct.pack("<H", PREFIX_LEN)
    manifest[16:18] = struct.pack("<H", RAW_STRIDE)
    manifest[18:22] = u32(1)
    manifest[22:26] = u32(crc32(joined))
    manifest[26:30] = u32(crc32(notes))
    p = 30
    for prefix in prefixes:
        manifest[p:p+4] = u32(crc32(prefix))
        p += 4
    manifest[94:110] = bytes(notes)
    manifest[112:116] = b"\x00" * 4
    header_crc = crc32(manifest)
    manifest[112:116] = u32(header_crc)
    manifest_name = f"manifest-prefix-record-{MANIFEST_RECORD:03d}.bin"
    (DATA / manifest_name).write_bytes(manifest)
    combined = joined + bytes(manifest)
    (DATA / "candidate-prefixes-096-112.bin").write_bytes(combined)
    pkg = {
        "format": "smk37-v15-s1c9-one-manifest-plus-16-prefixes-v1",
        "scope": {"offline_only": True, "firmware_candidate": False, "device_accessed": False, "midi_transport_opened": False, "persistent_storage_write_performed": False},
        "record_range": [RECORD_BASE, MANIFEST_RECORD],
        "payload_prefix_records": SLOTS,
        "manifest_record": MANIFEST_RECORD,
        "prefix_len": PREFIX_LEN,
        "raw_stride": RAW_STRIDE,
        "tail_policy": "preserve all target raw tails 0x9c..0xa2; this package writes/generates prefixes only",
        "manifest_magic": MAGIC.decode("ascii"),
        "committed_flag": hx(COMMITTED, 2),
        "payload_crc32": hx(crc32(joined)),
        "notes_crc32": hx(crc32(notes)),
        "header_crc32": hx(header_crc),
        "combined_prefixes_file": "candidate-prefixes-096-112.bin",
        "combined_prefixes_sha256": sha(combined),
        "manifest_prefix_file": manifest_name,
        "manifest_prefix_sha256": sha(manifest),
        "records": records,
        "restore_contract": "read/validate manifest before any RAM publication; absent, uncommitted, short, corrupt, wrong-layout, or CRC-failing seed must fall through exactly as stock S1C5",
        "runtime_override_contract": "if S1C5 RAM is already ARMED with the selected slot valid, use volatile SysEx RAM and skip persistent fallback for that event/session",
    }
    (DATA / "package-manifest.json").write_text(json.dumps(pkg, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return pkg


def fit_budget() -> dict[str, Any]:
    owned = ADDR["s1c5_owned_end"] - ADDR["s1c5_selector_start"]
    selector = ADDR["s1c5_selector_end"] - ADDR["s1c5_selector_start"]
    producer = ADDR["s1c5_owned_end"] - ADDR["s1c5_producer_start"]
    helper = ADDR["save_helper_end"] - ADDR["save_helper_start"]
    read_setup = 6 + 6 + 2 + 6
    magic_compare = 8 * (2 + 4)
    six_core_fields = 6 * (2 + 4)
    positive_floor_without_crc = read_setup + magic_compare + six_core_fields
    return {
        "owned_s1c5_window": {"start": hx(ADDR["s1c5_selector_start"]), "end_exclusive": hx(ADDR["s1c5_owned_end"]), "bytes": owned, "selector_bytes": selector, "producer_plus_tail_bytes": producer, "free_if_exact_s1c5_selector_and_producer_preserved": 0},
        "proven_disabled_save_helper": {"start": hx(ADDR["save_helper_start"]), "end_exclusive": hx(ADDR["save_helper_end"]), "bytes": helper, "s1c7_no_manifest_helper_bytes": 84, "free_after_s1c7_shape": 0},
        "minimum_positive_gate_floor": {
            "manifest_read_setup_bytes": read_setup,
            "inline_magic_compare_bytes": magic_compare,
            "version_commit_layout_count_base_record_field_bytes": six_core_fields,
            "floor_without_any_crc_or_payload_restore": positive_floor_without_crc,
            "available_single_helper_region_bytes": helper,
            "overflow_before_crc_bytes": positive_floor_without_crc - helper,
            "crc_status": "BLOCK: CRC32 table data is present, but no callable CRC/checksum ABI is proven; new CRC loop code is not included in this floor",
            "memcmp_status": "BLOCK: no bounded memcmp helper is proven; inline compares or unsafe strcmp do not fit the positive gate",
        },
        "split_region_review": {
            "proven_regions": [
                {"range": "0x0201e13e..0x0201e254", "bytes": owned, "status": "active S1C5 selector/producer; no free bytes if producer and runtime SysEx behavior stay exact"},
                {"range": "0x02026d80..0x02026dd4", "bytes": helper, "status": "quarantined disabled SAVE body; only standalone helper region; positive gate floor already overflows"},
            ],
            "rejected_regions": [
                {"range": "0x02005f9c/0x02005fa4", "status": "boot hook/design point only; revoked or lacks live proof for a new wrapper and placement"},
                {"range": "generic zero/ff data caves", "status": "not ownership proof; not promoted to executable placement"},
            ],
        },
        "boot_or_lazy_validation": {
            "boot_only": "BLOCK: earlier 0x02005f9c restore-wrapper architecture depends on a larger proven wrapper region and exact register continuation; current evidence revokes promotion to firmware.",
            "first_note_lazy": "BLOCK: safest lifecycle in principle because USB/SysEx is live and ARMED RAM can override, but the selector/helper pair still needs manifest validation or a cached valid state before touching RAM; no placement passes.",
            "boot_only_or_lazy_data_result": "PASS as data design: one manifest prefix plus 16 payload prefixes can fail closed if a future exact validator exists.",
        },
    }


def render_report(ev: dict[str, Any]) -> str:
    pkg = ev["data_package"]
    fit = ev["fit_budget"]
    helpers = ev["helpers"]
    return f"""# S1C9 minimum-budget S1C5 persistence: BLOCK with exact helper inventory

## Decision

**BLOCK.** No `app.bin`, FWSC, exact OTA wrapper, rollback flasher, writer, device action, or MIDI action is emitted.

The 17-record data layout is viable offline, but a manifest-gated restore that treats absent/invalid seed as exact stock S1C5 and lets runtime SysEx `ARMED` RAM override cannot be placed with exact helper ABI evidence.

## Exact callable helper inventory

| Need | Result | Exact evidence |
|---|---|---|
| CRC/checksum | {helpers['crc_or_checksum']['verdict']} | IEEE CRC32 table data exists at `{helpers['crc_or_checksum']['standard_crc32_table']['address']}` ({helpers['crc_or_checksum']['standard_crc32_table']['bytes']} bytes), but direct table refs count is `{len(helpers['crc_or_checksum']['standard_crc32_table']['direct_imm32_refs_to_table_start'])}` and no callable ABI is proven. |
| Bounded memcmp | {helpers['bounded_memcmp']['verdict']} | Closest exact helper is `strcmp` at `{helpers['bounded_memcmp']['closest_stock_helper']['address']}`, which has no length argument and is unsafe for binary records. |
| Storage read | {helpers['storage_read']['verdict']} | `{helpers['storage_read']['address']}` ABI: `{helpers['storage_read']['abi']}`. |
| Storage write | {helpers['storage_write']['verdict']} | `{helpers['storage_write']['address']}` ABI: `{helpers['storage_write']['abi']}`. |
| Bounds | {helpers['bounds']['verdict']} | Callable stock loader `{helpers['bounds']['callable']}` bounds global bank/preset only, not manifest fields. |
| State publication | {helpers['state_publication']['verdict']} | Stock loader `{helpers['state_publication']['stock_loader']}`, initializer `{helpers['state_publication']['derived_initializer']}`, and exact S1C5 producer `{helpers['state_publication']['s1c5_producer_window']['start']}..{helpers['state_publication']['s1c5_producer_window']['end_exclusive']}`. |

## One manifest record plus 16 prefixes

Generated under `data-package/`:

- Combined prefixes: `{pkg['combined_prefixes_file']}`, SHA-256 `{pkg['combined_prefixes_sha256']}`.
- Manifest prefix: `{pkg['manifest_prefix_file']}`, SHA-256 `{pkg['manifest_prefix_sha256']}`.
- Payload CRC32 `{pkg['payload_crc32']}`, notes CRC32 `{pkg['notes_crc32']}`, header CRC32 `{pkg['header_crc32']}`.
- Records `{pkg['record_range'][0]}..{pkg['record_range'][1]}`. Only bytes `0x00..0x9b` are represented. Tails `0x9c..0xa2` are not written.

Absent, all-zero, uncommitted, wrong-layout, short-read, corrupt, or CRC-failing seed must do nothing and return through exact S1C5 stock fallback.

## Fit blocker

| Budget | Bytes |
|---|---:|
| Proven disabled SAVE helper region | {fit['proven_disabled_save_helper']['bytes']} |
| Manifest read setup floor | {fit['minimum_positive_gate_floor']['manifest_read_setup_bytes']} |
| Inline 8-byte magic compare floor | {fit['minimum_positive_gate_floor']['inline_magic_compare_bytes']} |
| Six core field checks floor | {fit['minimum_positive_gate_floor']['version_commit_layout_count_base_record_field_bytes']} |
| Floor before any CRC or payload restore | {fit['minimum_positive_gate_floor']['floor_without_any_crc_or_payload_restore']} |
| Overflow before CRC | {fit['minimum_positive_gate_floor']['overflow_before_crc_bytes']} |

The exact S1C5 owned window has `{fit['owned_s1c5_window']['free_if_exact_s1c5_selector_and_producer_preserved']}` free bytes if the selector/producer behavior is preserved byte-for-byte. The only standalone helper region is `{fit['proven_disabled_save_helper']['bytes']}` bytes. The positive manifest gate floor is already `{fit['minimum_positive_gate_floor']['floor_without_any_crc_or_payload_restore']}` bytes before CRC, payload reads, publication, or rollback repair.

## Split-helper and boot/lazy result

- Split across proven regions fails: the active S1C5 selector/producer has no free budget, and the disabled SAVE helper overflows before CRC.
- Boot-only validation remains blocked: `0x02005f9c` was a design point, not a current promotable hook, and wrapper placement/register continuation are not proven for this successor.
- First-note lazy validation remains blocked by the same code placement and helper ABI limits. It is the preferred lifecycle if future placement is proven because runtime SysEx `ARMED` RAM can win first.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block && shasum -a 256 -c SHA256SUMS)
```
"""


def write_sha_inventory() -> None:
    paths = [p for p in sorted(HERE.rglob("*")) if p.is_file() and p.name != "SHA256SUMS"]
    (HERE / "SHA256SUMS").write_text("\n".join(f"{shaf(p)}  {p.relative_to(HERE)}" for p in paths) + "\n", encoding="utf-8")


def build(check: bool = False) -> dict[str, Any]:
    app, gates = gate_inputs()
    rows = load_listing_rows()
    helpers = helper_inventory((OFFICIAL_APP).read_bytes(), rows)
    data_pkg = build_data_package()
    fit = fit_budget()
    ev = {
        "format": "smk37-v15-s1c9-min-budget-persistence-block-v1",
        "decision": "BLOCK_NO_FIRMWARE_CANDIDATE",
        "candidate_built": False,
        "scope": {"offline_only": True, "device_accessed": False, "midi_transport_opened": False, "flash_performed": False, "ota_performed": False, "reset_performed": False, "firmware_artifacts_emitted": False},
        "input_gates": gates,
        "helpers": helpers,
        "data_package": data_pkg,
        "fit_budget": fit,
        "blockers": [
            "No exact callable CRC/checksum helper ABI is proven, only CRC32 table data.",
            "No exact bounded memcmp helper is proven; strcmp is zero-terminated and binary-unsafe.",
            "84-byte disabled SAVE helper region is smaller than the 104-byte positive gate floor before CRC or restore.",
            "No second proven cold executable region is promotable for split helper placement.",
            "Boot-only and first-note lazy validation remain design-only without exact placement and ABI proof.",
        ],
    }
    (HERE / "helpers.json").write_text(json.dumps(helpers, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "evidence.json").write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(render_report(ev), encoding="utf-8")
    (HERE / "README.md").write_text("# S1C9 minimum-budget persistence block\n\nDeterministic offline BLOCK/design package. Run `python3 analyze.py --check` and `python3 validate.py`.\n", encoding="utf-8")
    (HERE / "validation.txt").write_text("S1C9 minimum-budget persistence analysis: PASS BLOCK\nPASS exact input gates\nPASS helper inventory generated\nPASS one manifest plus 16 prefixes generated\nPASS no firmware artifacts emitted\nPASS fit blocker quantified\n", encoding="utf-8")
    write_sha_inventory()
    if check:
        import subprocess, sys
        subprocess.run([sys.executable, str(HERE / "validate.py")], check=True)
    print("S1C9 minimum-budget persistence BLOCK analysis rebuilt")
    return ev


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    build(check=args.check)


if __name__ == "__main__":
    main()
