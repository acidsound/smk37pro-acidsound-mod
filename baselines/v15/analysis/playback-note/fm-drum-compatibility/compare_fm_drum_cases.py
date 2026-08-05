#!/usr/bin/env python3
"""Read-only FM Drum SysEx comparison and controlled Hi-Hat variants.

The source directory is ~/Downloads/fmDrumSet. Original files are never modified.
Generated variants are diagnostic host-side SysEx only. They are not firmware
artifacts and are not sent to a device by this script.
"""
from __future__ import annotations

import hashlib
import json
from itertools import combinations
from pathlib import Path

ROOT = Path.home() / "Downloads" / "fmDrumSet"
OUT = Path(__file__).resolve().parent
VARIANTS = OUT / "controlled-variants"


def parse(path: Path) -> tuple[bytes, bytes]:
    raw = path.read_bytes()
    if len(raw) != 163:
        raise ValueError(f"{path}: expected 163 bytes, got {len(raw)}")
    if raw[:6] != bytes.fromhex("f0 43 00 00 01 1b") or raw[-1] != 0xf7:
        raise ValueError(f"{path}: unsupported single-voice header/terminator")
    data = raw[6:161]
    expected = (-sum(data)) & 0x7F
    if raw[161] != expected:
        raise ValueError(f"{path}: checksum mismatch")
    return raw, data


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def semantic(data: bytes) -> dict[str, object]:
    return {
        "algorithm": data[134],
        "feedback": data[135],
        "osc_sync": data[136],
        "transpose": data[144],
        "name": data[145:155].decode("ascii", "replace").rstrip(),
        "operator_output": [data[op * 21 + 16] for op in range(6)],
    }


def make_variant(source: Path, name: str, changes: dict[int, int], rationale: str) -> dict[str, object]:
    raw, _ = parse(source)
    output = bytearray(raw)
    for runtime_offset, value in changes.items():
        if not 0 <= runtime_offset < 155 or not 0 <= value <= 0x7F:
            raise ValueError("variant change outside 7-bit runtime payload")
        output[6 + runtime_offset] = value
    output[161] = (-sum(output[6:161])) & 0x7F
    destination = VARIANTS / name
    destination.write_bytes(output)
    _, data = parse(destination)
    return {
        "file": str(destination.relative_to(OUT)),
        "source": str(source.relative_to(ROOT)),
        "changes": changes,
        "rationale": rationale,
        "sha256": sha256(bytes(output)),
        "semantic": semantic(data),
        "length": len(output),
    }


def main() -> None:
    if not ROOT.is_dir():
        raise SystemExit(f"missing source directory: {ROOT}")
    VARIANTS.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(ROOT.rglob("*.syx")):
        raw, data = parse(path)
        records.append({
            "file": str(path.relative_to(ROOT)),
            "category": path.parent.name,
            "length": len(raw),
            "sha256": sha256(raw),
            "semantic": semantic(data),
        })

    hh1 = ROOT / "HH" / "Hi-Hat 1.syx"
    hh2 = ROOT / "HH" / "Hi-Hat 2.syx"
    open_hh = ROOT / "HH" / "Open HiHat.syx"
    _, h1 = parse(hh1)
    _, h2 = parse(hh2)
    _, oh = parse(open_hh)
    h1_hh2_payload = {i: h2[i] for i in range(155) if h1[i] != h2[i]}
    h1_hh2_sound = {i: h2[i] for i in range(145) if h1[i] != h2[i]}
    h1_open_payload = {i: oh[i] for i in range(155) if h1[i] != oh[i]}
    h1_open_sound = {i: oh[i] for i in range(145) if h1[i] != oh[i]}
    variants = [
        make_variant(
            hh1,
            "Hi-Hat-1-feedback-7.syx",
            {135: h2[135]},
            "Hi-Hat 1 with only feedback changed to Hi-Hat 2's value",
        ),
        make_variant(
            hh1,
            "Hi-Hat-1-open-hihat-byte68.syx",
            {68: oh[68]},
            "Hi-Hat 1 with only Open HiHat runtime offset 68",
        ),
        make_variant(
            hh1,
            "Hi-Hat-1-open-hihat-byte106.syx",
            {106: oh[106]},
            "Hi-Hat 1 with only Open HiHat runtime offset 106",
        ),
    ]
    inventory = {
        "format": "smk37-fm-drum-comparison-v1",
        "source": str(ROOT),
        "source_file_count": len(records),
        "all_inputs_valid_163_byte_yamaha_single_voice": all(r["length"] == 163 for r in records),
        "records": records,
        "known_cases": {
            "known_good": "HH/Hi-Hat 1.syx",
            "known_fail": "HH/Hi-Hat 2.syx",
            "good_sha256": sha256(hh1.read_bytes()),
            "fail_sha256": sha256(hh2.read_bytes()),
            "good_to_fail_payload_changes": h1_hh2_payload,
            "good_to_fail_sound_changes": h1_hh2_sound,
            "good_to_open_payload_changes": h1_open_payload,
            "good_to_open_sound_changes": h1_open_sound,
        },
        "controlled_variants": variants,
    }
    (OUT / "inventory.json").write_text(json.dumps(inventory, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "source_file_count": len(records),
        "all_inputs_valid": inventory["all_inputs_valid_163_byte_yamaha_single_voice"],
        "known_good": inventory["known_cases"]["good_sha256"],
        "known_fail": inventory["known_cases"]["fail_sha256"],
        "good_to_fail_sound_change_count": len(h1_hh2_sound),
        "good_to_open_sound_change_count": len(h1_open_sound),
        "variants": variants,
    }, indent=2))


if __name__ == "__main__":
    main()
