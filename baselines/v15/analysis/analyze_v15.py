#!/usr/bin/env python3
"""Reproducible, v15-only static evidence extraction.

This script reads only:
  * build/v15-official-app.bin
  * baselines/v15/official/package-manifest.json

It does not import offsets, structures, or conclusions from any other firmware.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from collections import defaultdict
from pathlib import Path

EXPECTED_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
EXPECTED_RUNTIME_BASE = 0x02000000

PATTERNS = {
    "usb_device_descriptor": bytes.fromhex(
        "12 01 00 02 00 00 00 40 53 43 4d 4b 00 01 01 02 03 01"
    ),
    "midi_streaming_interface": bytes.fromhex("09 04 00 00 02 01 03 00 00"),
    "midi_streaming_header": bytes.fromhex("07 24 01 00 01 81 00"),
    "midi_in_endpoint": bytes.fromhex("09 05 84 02 40 00 00 00 00"),
    "midi_in_cs_endpoint": bytes.fromhex("07 25 01 03 08 0a 0c"),
    "midi_out_endpoint": bytes.fromhex("09 05 04 02 40 00 00 00 00"),
    "midi_out_cs_endpoint": bytes.fromhex("07 25 01 03 01 03 05"),
    "midi_jack_graph": bytes.fromhex(
        "06 24 02 01 01 20"
        "09 24 03 02 02 01 01 01 20"
        "06 24 02 01 03 21"
        "09 24 03 02 04 01 03 01 21"
        "06 24 02 01 05 22"
        "09 24 03 02 06 01 05 01 22"
        "09 24 03 01 08 01 07 01 20"
        "06 24 02 02 07 20"
        "09 24 03 01 0a 01 09 01 21"
        "06 24 02 02 09 21"
        "09 24 03 01 0c 01 0b 01 22"
        "06 24 02 02 0b 22"
    ),
    # USB-MIDI 1.0 Code Index Number payload byte counts, CIN 0x0 through 0xf.
    "usb_midi_cin_payload_lengths": bytes(
        [0, 0, 2, 3, 3, 1, 2, 3, 3, 3, 3, 3, 2, 2, 3, 1]
    ),
    "midi_route_ascii": b"midi_route\x00",
    "midi_product_utf16le": "SMK-37 Pro Midi".encode("utf-16le"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def all_offsets(data: bytes, needle: bytes) -> list[int]:
    result: list[int] = []
    start = 0
    while True:
        offset = data.find(needle, start)
        if offset < 0:
            return result
        result.append(offset)
        start = offset + 1


def ascii_strings(data: bytes, minimum: int = 8) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    offset = 0
    while offset < len(data):
        if 0x20 <= data[offset] <= 0x7E and (
            offset == 0 or not 0x20 <= data[offset - 1] <= 0x7E
        ):
            end = offset
            while end < len(data) and 0x20 <= data[end] <= 0x7E:
                end += 1
            if end - offset >= minimum:
                result.append((offset, data[offset:end].decode("ascii")))
            offset = end
        else:
            offset += 1
    return result


def pointer_words(data: bytes) -> dict[int, list[int]]:
    result: dict[int, list[int]] = defaultdict(list)
    for offset in range(0, len(data) - 3, 2):
        result[struct.unpack_from("<I", data, offset)[0]].append(offset)
    return result


def score_base(data: bytes, base: int) -> dict[str, object]:
    words = pointer_words(data)
    hits = []
    for offset, text in ascii_strings(data, minimum=8):
        refs = words.get(base + offset, [])
        if refs:
            hits.append(
                {
                    "target_offset": offset,
                    "target_va": base + offset,
                    "text": text,
                    "reference_offsets": refs,
                }
            )
    return {
        "base": base,
        "unique_long_string_targets": len(hits),
        "reference_count": sum(len(hit["reference_offsets"]) for hit in hits),
        "hits": hits,
    }


def derive_aligned_base_candidates(data: bytes) -> list[dict[str, object]]:
    """Rank 64-KiB-aligned bases implied by absolute pointers to long strings."""
    words = pointer_words(data)
    words_by_low16: dict[int, list[tuple[int, list[int]]]] = defaultdict(list)
    for pointer, reference_offsets in words.items():
        if 0x01000000 <= pointer < 0x04000000:
            words_by_low16[pointer & 0xFFFF].append((pointer, reference_offsets))

    candidates: dict[int, list[dict[str, object]]] = defaultdict(list)
    for target_offset, text in ascii_strings(data, minimum=8):
        for pointer, reference_offsets in words_by_low16[target_offset & 0xFFFF]:
            base = pointer - target_offset
            if base < 0 or base & 0xFFFF:
                continue
            candidates[base].append(
                {
                    "target_offset": target_offset,
                    "target_va": pointer,
                    "text": text,
                    "reference_offsets": reference_offsets,
                }
            )

    ranked = [
        {
            "base": base,
            "unique_long_string_targets": len(hits),
            "reference_count": sum(len(hit["reference_offsets"]) for hit in hits),
            "hits": hits,
        }
        for base, hits in candidates.items()
    ]
    ranked.sort(
        key=lambda item: (
            -int(item["reference_count"]),
            -int(item["unique_long_string_targets"]),
            int(item["base"]),
        )
    )
    return ranked


def decode_device_descriptor(blob: bytes) -> dict[str, int]:
    return {
        "bcdUSB": int.from_bytes(blob[2:4], "little"),
        "device_class": blob[4],
        "ep0_max_packet": blob[7],
        "vendor_id": int.from_bytes(blob[8:10], "little"),
        "product_id": int.from_bytes(blob[10:12], "little"),
        "bcdDevice": int.from_bytes(blob[12:14], "little"),
        "manufacturer_string_index": blob[14],
        "product_string_index": blob[15],
        "serial_string_index": blob[16],
        "configuration_count": blob[17],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, default=Path("build/v15-official-app.bin"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("baselines/v15/official/package-manifest.json"),
    )
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args()

    data = args.image.read_bytes()
    digest = sha256(data)
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            f"refusing analysis: SHA-256 {digest} != expected {EXPECTED_SHA256}"
        )

    manifest = json.loads(args.manifest.read_text())
    layout = manifest["layout"]
    if manifest["app_sha256"] != digest:
        raise SystemExit("manifest app_sha256 does not match the input image")
    if layout["app_data_size"] != len(data):
        raise SystemExit("manifest app_data_size does not match the input image")

    derived_bases = derive_aligned_base_candidates(data)
    if not derived_bases or derived_bases[0]["base"] != EXPECTED_RUNTIME_BASE:
        raise SystemExit("internal pointer/string evidence did not select 0x02000000")
    if len(derived_bases) > 1 and (
        derived_bases[0]["reference_count"] <= derived_bases[1]["reference_count"]
    ):
        raise SystemExit("internal pointer/string base evidence is tied")
    runtime_base = int(derived_bases[0]["base"])

    pattern_hits = {
        name: [
            {
                "file_offset": offset,
                "runtime_va": runtime_base + offset,
                "flash_offset": layout["app_data_start"] + offset,
            }
            for offset in all_offsets(data, pattern)
        ]
        for name, pattern in PATTERNS.items()
    }

    device_hits = pattern_hits["usb_device_descriptor"]
    device = None
    if device_hits:
        start = device_hits[0]["file_offset"]
        device = decode_device_descriptor(data[start : start + 18])

    report = {
        "input": {
            "path": str(args.image),
            "size": len(data),
            "sha256": digest,
        },
        "package_layout": {
            "app_data_start": layout["app_data_start"],
            "app_data_start_hex": f"0x{layout['app_data_start']:x}",
            "app_data_size": layout["app_data_size"],
            "interpretation": "package/flash storage offset, not the runtime virtual base",
        },
        "runtime_base_tests": [
            score_base(data, runtime_base),
            # Explicitly test and reject the common category error of adding the
            # package/flash storage offset to the runtime virtual base.
            score_base(data, runtime_base + layout["app_data_start"]),
        ],
        "derived_aligned_base_candidates": derived_bases[:10],
        "selected_runtime_base": runtime_base,
        "patterns": pattern_hits,
        "device_descriptor": device,
        "entry_point_result": {
            "status": "not_identified",
            "reason": (
                "No direct literal or upstream-Ghidra data/code xref connected the MIDI strings, "
                "descriptors, jack graph, endpoint descriptors, or CIN table to a unique PI32 "
                "receive or dispatch function."
            ),
        },
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"image_sha256={digest}")
    print(f"image_size={len(data)}")
    print(f"package_app_data_start=0x{layout['app_data_start']:x}")
    for base_test in report["runtime_base_tests"]:
        print(
            "base_test="
            f"0x{base_test['base']:08x} "
            f"long_string_targets={base_test['unique_long_string_targets']} "
            f"refs={base_test['reference_count']}"
        )
        for hit in base_test["hits"]:
            refs = ",".join(f"0x{x:x}" for x in hit["reference_offsets"])
            print(
                f"  target=0x{hit['target_offset']:x} "
                f"va=0x{hit['target_va']:08x} refs={refs} text={hit['text']!r}"
            )
    print("derived_aligned_base_candidates=" + ",".join(
        f"0x{x['base']:08x}:{x['reference_count']}refs/{x['unique_long_string_targets']}targets"
        for x in derived_bases[:10]
    ))
    print(f"selected_runtime_base=0x{runtime_base:08x}")
    for name, hits in pattern_hits.items():
        rendered = ", ".join(
            f"file=0x{x['file_offset']:x}/va=0x{x['runtime_va']:08x}/flash=0x{x['flash_offset']:x}"
            for x in hits
        )
        print(f"pattern={name} hits={len(hits)} {rendered}")
    if device:
        print(
            "device_descriptor="
            f"usb=0x{device['bcdUSB']:04x} vid=0x{device['vendor_id']:04x} "
            f"pid=0x{device['product_id']:04x} ep0={device['ep0_max_packet']}"
        )
    print("entry_point_status=not_identified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
