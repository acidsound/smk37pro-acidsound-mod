#!/usr/bin/env python3
"""Offline raw-prefix encoder for the blocked S1C6 persistence design.

This is deliberately not a device writer. It never opens USB/MIDI/flash. It only
encodes a candidate 17-record raw-prefix image from already-captured 163-byte
S1C5 product SysEx packets so the storage format can be reviewed exactly.
"""
from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
S1C5 = HERE.parent / "S1C5-playback-register-return"
HEADER = bytes.fromhex("f0430000011b")
TERM = 0xF7
SLOTS = 16
RAW_RECORD_SIZE = 0xA3
PREFIX_SIZE = 0x9C
STORED_VOICE_BYTES = 0x9B
TAIL_SIZE = RAW_RECORD_SIZE - PREFIX_SIZE
DEFAULT_RECORD_BASE = 96  # Bank D preset 1, explicit reservation, not free space.
DEFAULT_MANIFEST_INDEX = DEFAULT_RECORD_BASE + SLOTS
MAGIC = b"S1C6R17\0"
FORMAT = "smk37-v15-s1c6-raw17-prefix-writer-v1"


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hx(value: int) -> str:
    return f"0x{value:04x}"


def crc32(data: bytes) -> int:
    return binascii.crc32(data) & 0xFFFFFFFF


def record_offset(index: int) -> int:
    return 0x4000 + index * RAW_RECORD_SIZE


def read_packet_set(packet_dir: Path, manifest_path: Path) -> list[dict[str, Any]]:
    manifest = json.loads(manifest_path.read_text())
    req(manifest.get("packet_count") == SLOTS, "16-packet manifest")
    packets: list[dict[str, Any]] = []
    for item in sorted(manifest["packets"], key=lambda x: x["slot"]):
        slot = int(item["slot"])
        req(slot == len(packets), f"contiguous slot order at {slot}")
        path = packet_dir / item["file"]
        packet = path.read_bytes()
        req(len(packet) == 163, f"163-byte packet {path.name}")
        req(packet.startswith(HEADER) and packet[-1] == TERM, f"packet framing {path.name}")
        payload = packet[len(HEADER):-1]
        req(len(payload) == PREFIX_SIZE, f"expanded payload prefix length {path.name}")
        playback = payload[STORED_VOICE_BYTES] & 0x7F
        req(0 <= playback <= 127, f"playback note range {path.name}")
        prefix = payload[:STORED_VOICE_BYTES] + bytes([playback])
        req(len(prefix) == PREFIX_SIZE, "encoded prefix length")
        packets.append({
            "slot": slot,
            "trigger_note": int(item["trigger_note"]),
            "playback_note": playback,
            "packet_file": item["file"],
            "packet_sha256": sha(packet),
            "prefix": prefix,
            "prefix_sha256": sha(prefix),
        })
    req(len(packets) == SLOTS, "16 packets loaded")
    return packets


def build_manifest_prefix(payload_prefixes: list[bytes], record_base: int, manifest_index: int, sequence: int) -> bytes:
    req(len(payload_prefixes) == SLOTS, "16 payload prefixes")
    req(0 <= record_base <= 111, "payload base keeps 16 records inside 0..127")
    req(manifest_index not in range(record_base, record_base + SLOTS), "manifest outside payload range")
    req(0 <= manifest_index < 128, "manifest record in stock raw table")
    payload_crc = crc32(b"".join(payload_prefixes))
    prefix = bytearray(PREFIX_SIZE)
    prefix[0:8] = MAGIC
    prefix[8] = 1                 # format version
    prefix[9] = 0xA5              # committed state marker
    prefix[10] = SLOTS
    prefix[11] = STORED_VOICE_BYTES
    prefix[12] = record_base
    prefix[13] = manifest_index
    struct.pack_into("<I", prefix, 14, sequence & 0xFFFFFFFF)
    struct.pack_into("<I", prefix, 18, payload_crc)
    # Header CRC covers the whole manifest prefix with its own field zeroed.
    struct.pack_into("<I", prefix, 22, 0)
    struct.pack_into("<I", prefix, 22, crc32(bytes(prefix)))
    return bytes(prefix)


def encode(packet_dir: Path, manifest_path: Path, record_base: int, manifest_index: int, sequence: int) -> dict[str, Any]:
    packets = read_packet_set(packet_dir, manifest_path)
    payload_prefixes = [p["prefix"] for p in packets]
    manifest_prefix = build_manifest_prefix(payload_prefixes, record_base, manifest_index, sequence)
    records = []
    for i, item in enumerate(packets):
        index = record_base + i
        records.append({
            "kind": "payload",
            "slot": item["slot"],
            "record_index": index,
            "record_offset": hx(record_offset(index)),
            "prefix_size": PREFIX_SIZE,
            "tail_policy": "preserve existing raw bytes 0x9c..0xa2 unchanged",
            "trigger_note": item["trigger_note"],
            "playback_note": item["playback_note"],
            "packet_file": item["packet_file"],
            "packet_sha256": item["packet_sha256"],
            "prefix_sha256": item["prefix_sha256"],
        })
    records.append({
        "kind": "manifest",
        "record_index": manifest_index,
        "record_offset": hx(record_offset(manifest_index)),
        "prefix_size": PREFIX_SIZE,
        "tail_policy": "preserve existing raw bytes 0x9c..0xa2 unchanged",
        "prefix_sha256": sha(manifest_prefix),
        "magic": MAGIC.hex(),
        "sequence": sequence & 0xFFFFFFFF,
        "payload_crc32": f"0x{crc32(b''.join(payload_prefixes)):08x}",
        "header_crc32": f"0x{struct.unpack_from('<I', manifest_prefix, 22)[0]:08x}",
    })
    return {
        "format": FORMAT,
        "writer_scope": {
            "offline_encoder_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "flash_performed": False,
            "persistent_storage_write_performed": False,
        },
        "record_base": record_base,
        "manifest_index": manifest_index,
        "record_count": len(records),
        "payload_record_count": SLOTS,
        "prefix_size": PREFIX_SIZE,
        "raw_record_size": RAW_RECORD_SIZE,
        "tail_bytes_preserved_per_record": TAIL_SIZE,
        "canonical_payload_crc32": f"0x{crc32(b''.join(payload_prefixes)):08x}",
        "records": records,
        "_payload_prefixes": payload_prefixes,
        "_manifest_prefix": manifest_prefix,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-dir", type=Path, default=S1C5 / "inputs" / "packets")
    parser.add_argument("--manifest", type=Path, default=S1C5 / "inputs" / "packets" / "packet-manifest.json")
    parser.add_argument("--record-base", type=int, default=DEFAULT_RECORD_BASE)
    parser.add_argument("--manifest-index", type=int, default=DEFAULT_MANIFEST_INDEX)
    parser.add_argument("--sequence", type=int, default=1)
    parser.add_argument("--out-dir", type=Path, help="optional local output directory for prefix blobs, never a device path")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = encode(args.packet_dir, args.manifest, args.record_base, args.manifest_index, args.sequence)
    payload_prefixes = result.pop("_payload_prefixes")
    manifest_prefix = result.pop("_manifest_prefix")
    if args.out_dir:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        for i, blob in enumerate(payload_prefixes):
            index = args.record_base + i
            (args.out_dir / f"record-{index:03d}-slot-{i:02d}.prefix").write_bytes(blob)
        (args.out_dir / f"record-{args.manifest_index:03d}-manifest.prefix").write_bytes(manifest_prefix)
        (args.out_dir / "prefix-manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("S1C6 raw-prefix offline encoder PASS")
        print(f"records={result['record_count']} payload={result['payload_record_count']} base={result['record_base']} manifest={result['manifest_index']}")
        print(f"payload_crc32={result['canonical_payload_crc32']}")


if __name__ == "__main__":
    main()
