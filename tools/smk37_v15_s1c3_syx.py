#!/usr/bin/env python3
"""Export, validate, and convert SMK-37 Pro S1-C3 single-voice SysEx files.

The S1-C3 firmware accepts a 163-byte Yamaha DX7 single-voice-shaped message,
but byte 161 is used as the SMK runtime flag (0x3f), not the Yamaha checksum.
Editor-facing .syx files use the standard Yamaha checksum. Runtime packet files
use 0x3f so they can be consumed by the proven S1-C3 producer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = REPO_ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/packets"
DEFAULT_EXPORT = REPO_ROOT / "patches/v15/s1c3-bank-d-demo"
HEADER = bytes.fromhex("f0430000011b")
PACKET_SIZE = 163
DATA_START = 6
DATA_END = 161
CHECKSUM_OFFSET = 161
SMK_RUNTIME_FLAG = 0x3F
NAME_START = 151
NAME_END = 161
PAD_TO_NOTE = (40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47)
NOTE_TO_PAD = {note: pad for pad, note in enumerate(PAD_TO_NOTE, 1)}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def yamaha_checksum(data: bytes) -> int:
    return (-sum(data[DATA_START:DATA_END])) & 0x7F


def patch_name(data: bytes) -> str:
    return data[NAME_START:NAME_END].decode("ascii", "replace").rstrip()


def safe_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name.strip())
    return cleaned.strip("_") or "unnamed"


def validate_common(data: bytes, path: Path) -> None:
    if len(data) != PACKET_SIZE:
        raise ValueError(f"{path}: expected {PACKET_SIZE} bytes, got {len(data)}")
    if data[:2] != HEADER[:2] or data[2] & 0xF0 or data[3:6] != HEADER[3:6]:
        raise ValueError(f"{path}: not a Yamaha DX7 single-voice SysEx header")
    if data[-1] != 0xF7:
        raise ValueError(f"{path}: missing F7 terminator")
    if any(value > 0x7F for value in data[1:-1]):
        raise ValueError(f"{path}: contains non-7-bit SysEx data")


def validate_editor_syx(data: bytes, path: Path) -> None:
    validate_common(data, path)
    expected = yamaha_checksum(data)
    if data[CHECKSUM_OFFSET] != expected:
        raise ValueError(
            f"{path}: Yamaha checksum mismatch, stored 0x{data[CHECKSUM_OFFSET]:02x}, expected 0x{expected:02x}"
        )


def validate_runtime_packet(data: bytes, path: Path) -> None:
    validate_common(data, path)
    if data[CHECKSUM_OFFSET] != SMK_RUNTIME_FLAG:
        raise ValueError(
            f"{path}: SMK runtime flag mismatch, got 0x{data[CHECKSUM_OFFSET]:02x}, expected 0x{SMK_RUNTIME_FLAG:02x}"
        )


def editor_from_runtime(data: bytes, path: Path) -> bytes:
    validate_runtime_packet(data, path)
    result = bytearray(data)
    result[CHECKSUM_OFFSET] = yamaha_checksum(result)
    return bytes(result)


def runtime_from_editor(data: bytes, path: Path) -> bytes:
    validate_editor_syx(data, path)
    result = bytearray(data)
    result[CHECKSUM_OFFSET] = SMK_RUNTIME_FLAG
    return bytes(result)


def source_for_note(source_dir: Path, note: int) -> Path:
    matches = sorted(source_dir.glob(f"slot*-note{note}-direct-product-163.bin"))
    if len(matches) != 1:
        raise ValueError(f"{source_dir}: expected one runtime packet for note {note}, found {len(matches)}")
    return matches[0]


def export_current(source_dir: Path, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    for pad, note in enumerate(PAD_TO_NOTE, 1):
        source = source_for_note(source_dir, note)
        runtime = source.read_bytes()
        editor = editor_from_runtime(runtime, source)
        name = patch_name(editor)
        filename = f"pad{pad:02d}-note{note:02d}-{safe_name(name)}.syx"
        destination = output_dir / filename
        destination.write_bytes(editor)
        rows.append(
            {
                "physical_pad": pad,
                "midi_note": note,
                "patch_name": name,
                "file": filename,
                "size": len(editor),
                "editor_syx_sha256": sha256(editor),
                "smk_runtime_packet_sha256": sha256(runtime),
                "yamaha_checksum": editor[CHECKSUM_OFFSET],
                "smk_runtime_flag": SMK_RUNTIME_FLAG,
            }
        )
    manifest = {
        "format": "smk37-v15-s1c3-editor-syx-pad-set-v1",
        "source": str(source_dir.relative_to(REPO_ROOT)),
        "packet_contract": {
            "size": PACKET_SIZE,
            "header": HEADER.hex(),
            "editor_byte_161": "Yamaha 7-bit checksum",
            "device_byte_161": "SMK runtime flag 0x3f",
            "terminator": "f7",
        },
        "physical_pad_note_sequence": list(PAD_TO_NOTE),
        "patches": rows,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"exported {len(rows)} editor-compatible .syx files to {output_dir}")


def find_pad_file(directory: Path, pad: int) -> Path:
    matches = sorted(directory.glob(f"pad{pad:02d}-*.syx"))
    if len(matches) != 1:
        raise ValueError(f"{directory}: expected exactly one pad{pad:02d}-*.syx, found {len(matches)}")
    return matches[0]


def validate_set(directory: Path) -> list[dict[str, object]]:
    rows = []
    for pad, note in enumerate(PAD_TO_NOTE, 1):
        path = find_pad_file(directory, pad)
        data = path.read_bytes()
        validate_editor_syx(data, path)
        rows.append(
            {
                "physical_pad": pad,
                "midi_note": note,
                "patch_name": patch_name(data),
                "file": path.name,
                "sha256": sha256(data),
                "checksum": data[CHECKSUM_OFFSET],
            }
        )
    return rows


def prepare_runtime(directory: Path, output_dir: Path) -> None:
    rows = validate_set(directory)
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True)
    by_note = {row["midi_note"]: row for row in rows}
    runtime_rows = []
    for slot, note in enumerate(range(36, 52)):
        row = by_note[note]
        source = directory / str(row["file"])
        runtime = runtime_from_editor(source.read_bytes(), source)
        filename = f"slot{slot:02d}-note{note}-direct-product-163.bin"
        (output_dir / filename).write_bytes(runtime)
        runtime_rows.append(
            {
                **row,
                "slot": slot,
                "runtime_file": filename,
                "runtime_sha256": sha256(runtime),
            }
        )
    manifest = {
        "format": "smk37-v15-s1c3-runtime-packet-set-v1",
        "source_pad_set": str(directory),
        "order": "MIDI notes 36..51, slot = note - 36",
        "packets": runtime_rows,
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"prepared {len(runtime_rows)} SMK runtime packets in {output_dir}")


def inspect(paths: list[Path]) -> None:
    for path in paths:
        data = path.read_bytes()
        validate_editor_syx(data, path)
        print(
            f"{path}: name={patch_name(data)!r} size={len(data)} "
            f"checksum=0x{data[CHECKSUM_OFFSET]:02x} sha256={sha256(data)}"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    export_parser = sub.add_parser("export-current", help="export the proven 16-patch set as editor-compatible .syx")
    export_parser.add_argument("--source-dir", type=Path, default=DEFAULT_SOURCE)
    export_parser.add_argument("--output-dir", type=Path, default=DEFAULT_EXPORT)

    validate_parser = sub.add_parser("validate-set", help="validate pad01..pad16 editor .syx files")
    validate_parser.add_argument("directory", type=Path)

    prepare_parser = sub.add_parser("prepare-runtime", help="convert a pad set into note-ordered SMK runtime packets")
    prepare_parser.add_argument("directory", type=Path)
    prepare_parser.add_argument("output_dir", type=Path)

    inspect_parser = sub.add_parser("inspect", help="inspect one or more editor-compatible .syx files")
    inspect_parser.add_argument("files", type=Path, nargs="+")

    args = parser.parse_args()
    try:
        if args.command == "export-current":
            export_current(args.source_dir.resolve(), args.output_dir.resolve())
        elif args.command == "validate-set":
            rows = validate_set(args.directory.resolve())
            for row in rows:
                print(f"Pad {row['physical_pad']:02d} note {row['midi_note']}: {row['patch_name']} [{row['file']}]")
            print("16-pad editor SysEx set: PASS")
        elif args.command == "prepare-runtime":
            prepare_runtime(args.directory.resolve(), args.output_dir.resolve())
        elif args.command == "inspect":
            inspect([path.resolve() for path in args.files])
        else:
            parser.error("unknown command")
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
