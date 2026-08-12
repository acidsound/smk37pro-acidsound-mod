#!/usr/bin/env python3
"""Inspect and repack the SMK-37 Pro v15 application area safely.

This deliberately accepts only the byte-exact official v15 FWSC package.  It
can alter bytes inside app.bin while preserving the boot/update loader, flash
layout, device configuration, resources, and reserved areas.

The container details were independently implemented from observed v12 data
and the MIT-licensed jl-misctools format documentation/code:
https://github.com/kagaimiq/jl-misctools
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


OFFICIAL_V15_SHA256 = (
    "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
)
OFFICIAL_V15_SIZE = 701_140
OFFICIAL_V15_PAYLOAD_SHA256 = (
    "141f8b1780b18c0cddc4bdcfbe13690029804a5b0021f92869ec756c2f2d3ad9"
)
OFFICIAL_V15_PAYLOAD_SIZE = 701_120
FWSC_BLOCK_SIZE = 48
FWSC_DATA_SIZE = 47
FWSC_SLOTS = 20
UFW_HEADER_SIZE = 0x40
UFW_ENTRY_SIZE = 0x50
UFW_KEY = 0xFFFF
FLASH_SIZE = 0x9C000
APP_AREA_BASE = 0x4000
APP_AREA_END = 0x9ACD3
APP_ENTRY_HEADER = 0x4020
APP_DATA_OFFSET = 0x4120
APP_DATA_SIZE = 617_012
CHIP_KEY = 0x980F


class FormatError(RuntimeError):
    """Input is not the exact, structurally valid package expected here."""


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def crc16(data: bytes | bytearray, initial: int = 0) -> int:
    """Jieli CRC16: polynomial 0x1021, init 0, non-reflected."""
    crc = initial
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def enc_cipher(data: bytearray, offset: int, size: int, key: int = UFW_KEY) -> int:
    for index in range(size):
        data[offset + index] ^= key & 0xFF
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 0xFFFF
    return key


def sfc_cipher(
    data: bytearray,
    offset: int,
    size: int,
    base: int,
    key: int,
    block_size: int = 32,
) -> None:
    for relative in range(0, size, block_size):
        chunk_size = min(size - relative, block_size)
        block_key = key ^ ((offset + relative - base) >> 2)
        enc_cipher(data, offset + relative, chunk_size, block_key)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise FormatError(message)


def difference_offsets(before: bytes | bytearray, after: bytes | bytearray) -> list[int]:
    require(len(before) == len(after), "cannot compare differently sized buffers")
    return [index for index, pair in enumerate(zip(before, after)) if pair[0] != pair[1]]


def compact_ranges(offsets: Iterable[int]) -> list[dict[str, int]]:
    values = sorted(set(offsets))
    if not values:
        return []
    result: list[dict[str, int]] = []
    start = previous = values[0]
    for value in values[1:]:
        if value != previous + 1:
            result.append({"start": start, "end_exclusive": previous + 1})
            start = value
        previous = value
    result.append({"start": start, "end_exclusive": previous + 1})
    return result


def decode_fwsc_metadata(raw: bytes) -> tuple[str, int]:
    decoded = bytes(
        (raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] + 0xFF - index) & 0xFF
        for index in range(FWSC_SLOTS)
    )
    require(decoded.startswith(b"SMK-37 Pro_015"), "unexpected FWSC product/version metadata")
    return "SMK-37 Pro", 15


def unpack_fwsc(raw: bytes) -> tuple[bytearray, bytes]:
    require(len(raw) == OFFICIAL_V15_SIZE, "official v15 FWSC size mismatch")
    require(sha256(raw) == OFFICIAL_V15_SHA256, "input is not the byte-exact official v15 FWSC")
    decode_fwsc_metadata(raw)
    metadata = bytes(
        raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for index in range(FWSC_SLOTS)
    )
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])
    require(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "FWSC payload size mismatch")
    require(sha256(payload) == OFFICIAL_V15_PAYLOAD_SHA256, "official v15 payload hash mismatch")
    return payload, metadata


def repack_fwsc(original: bytes, payload: bytes | bytearray, metadata: bytes) -> bytes:
    require(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "repacked payload size changed")
    require(len(metadata) == FWSC_SLOTS, "FWSC metadata slot count changed")
    output = bytearray(original)
    payload_offset = 0
    for index in range(FWSC_SLOTS):
        file_offset = index * FWSC_BLOCK_SIZE
        output[file_offset : file_offset + FWSC_DATA_SIZE] = payload[
            payload_offset : payload_offset + FWSC_DATA_SIZE
        ]
        output[file_offset + FWSC_DATA_SIZE] = metadata[index]
        payload_offset += FWSC_DATA_SIZE
    output[FWSC_SLOTS * FWSC_BLOCK_SIZE :] = payload[payload_offset:]
    require(len(output) == len(original), "repacked FWSC size changed")
    return bytes(output)


@dataclass
class UfwEntry:
    index_in_list: int
    entry_type: int
    entry_index: int
    data_crc: int
    unknown: int
    offset: int
    size: int
    aligned_size: int
    extra: bytes
    name_raw: bytes

    @property
    def name(self) -> str:
        return self.name_raw.split(b"\0", 1)[0].decode("ascii", "strict")

    def encode_plain(self) -> bytes:
        return struct.pack(
            "<HHHHIII44s16s",
            self.entry_type,
            self.entry_index,
            self.data_crc,
            self.unknown,
            self.offset,
            self.size,
            self.aligned_size,
            self.extra,
            self.name_raw,
        )


@dataclass
class Ufw:
    payload: bytearray
    header_plain: bytearray
    entries: list[UfwEntry]
    header_size: int

    @classmethod
    def parse(cls, payload: bytes | bytearray) -> "Ufw":
        work = bytearray(payload)
        header = bytearray(work[:UFW_HEADER_SIZE])
        enc_cipher(header, 0, len(header))
        require(crc16(header[2:]) == struct.unpack_from("<H", header, 0)[0], "UFW header CRC mismatch")
        _, list_crc, image_size, entry_count, unknown1, unknown2, chip_name = struct.unpack(
            "<HHIHHI48s", header
        )
        require(image_size == len(work), "UFW image size field mismatch")
        require(entry_count == 8, "unexpected UFW entry count")
        require(unknown1 == 4 and unknown2 == 512, "unexpected UFW header constants")
        require(chip_name.split(b"\0", 1)[0] == b"AC791N", "unexpected UFW chip family")
        header_size = UFW_HEADER_SIZE + entry_count * UFW_ENTRY_SIZE
        require(crc16(work[UFW_HEADER_SIZE:header_size]) == list_crc, "UFW encrypted entry-list CRC mismatch")

        entries: list[UfwEntry] = []
        for index in range(entry_count):
            offset = UFW_HEADER_SIZE + index * UFW_ENTRY_SIZE
            entry_plain = bytearray(work[offset : offset + UFW_ENTRY_SIZE])
            enc_cipher(entry_plain, 0, len(entry_plain))
            values = struct.unpack("<HHHHIII44s16s", entry_plain)
            entry = UfwEntry(index, *values)
            require(entry.entry_index == index, f"UFW entry {index} index mismatch")
            require(entry.offset + entry.size <= len(work), f"UFW entry {index} exceeds payload")
            if entry.entry_type == 0:
                require(crc16(work[entry.offset : entry.offset + entry.size]) == entry.data_crc,
                        f"UFW flash entry {index} ({entry.name}) data CRC mismatch")
            entries.append(entry)
        return cls(work, header, entries, header_size)

    def flash_entry(self) -> UfwEntry:
        matches = [entry for entry in self.entries if entry.entry_type == 0 and entry.name == "flash.bin"]
        require(len(matches) == 1, "UFW does not contain exactly one flash.bin entry")
        entry = matches[0]
        require(entry.offset == 0x400 and entry.size == FLASH_SIZE, "unexpected v15 flash.bin layout")
        return entry

    def flash(self) -> bytearray:
        entry = self.flash_entry()
        return bytearray(self.payload[entry.offset : entry.offset + entry.size])

    def replace_flash(self, flash: bytes | bytearray) -> None:
        entry = self.flash_entry()
        require(len(flash) == entry.size, "flash image size changed")
        self.payload[entry.offset : entry.offset + entry.size] = flash
        entry.data_crc = crc16(flash)

        entry_offset = UFW_HEADER_SIZE + entry.index_in_list * UFW_ENTRY_SIZE
        encrypted_entry = bytearray(entry.encode_plain())
        enc_cipher(encrypted_entry, 0, len(encrypted_entry))
        self.payload[entry_offset : entry_offset + UFW_ENTRY_SIZE] = encrypted_entry

        list_crc = crc16(self.payload[UFW_HEADER_SIZE : self.header_size])
        struct.pack_into("<H", self.header_plain, 2, list_crc)
        struct.pack_into("<H", self.header_plain, 0, crc16(self.header_plain[2:]))
        encrypted_header = bytearray(self.header_plain)
        enc_cipher(encrypted_header, 0, len(encrypted_header))
        self.payload[:UFW_HEADER_SIZE] = encrypted_header


@dataclass
class JlfsEntry:
    header_offset: int
    header_crc: int
    data_crc: int
    offset: int
    size: int
    flags: int
    reserved: int
    index: int
    name_raw: bytes

    @property
    def name(self) -> str:
        return self.name_raw.rstrip(b"\xff").split(b"\0", 1)[0].decode("ascii", "strict")


def parse_jlfs_entry(data: bytes | bytearray, offset: int) -> JlfsEntry:
    header_crc, header_data = struct.unpack_from("<H30s", data, offset)
    require(crc16(header_data) == header_crc, f"JLFS header CRC mismatch at 0x{offset:x}")
    fields = struct.unpack("<HIIBBH16s", header_data)
    return JlfsEntry(offset, header_crc, *fields)


def update_jlfs_crc(data: bytearray, entry: JlfsEntry, data_offset: int, data_size: int) -> None:
    struct.pack_into("<H", data, entry.header_offset + 2, crc16(data[data_offset : data_offset + data_size]))
    struct.pack_into("<H", data, entry.header_offset, crc16(data[entry.header_offset + 2 : entry.header_offset + 32]))


@dataclass
class AppImage:
    encrypted_flash: bytearray
    plain_flash: bytearray
    area: JlfsEntry
    app: JlfsEntry

    @classmethod
    def parse(cls, encrypted_flash: bytes | bytearray) -> "AppImage":
        require(len(encrypted_flash) == FLASH_SIZE, "unexpected flash image size")
        plain = bytearray(encrypted_flash)
        sfc_cipher(plain, APP_AREA_BASE, APP_AREA_END - APP_AREA_BASE, APP_AREA_BASE, CHIP_KEY)

        area = parse_jlfs_entry(plain, APP_AREA_BASE)
        require(area.name == "app_area_head", "app-area header name mismatch")
        require(area.offset == 0x02000120, "application entry point changed")
        require(area.size == APP_AREA_END - APP_AREA_BASE, "application-area size changed")
        require(area.flags == 0x83 and area.reserved == 0xFF and area.index == 0,
                "application-area JLFS flags changed")
        require(crc16(plain[APP_AREA_BASE + 32 : APP_AREA_END]) == area.data_crc,
                "application-area data CRC mismatch")

        app = parse_jlfs_entry(plain, APP_ENTRY_HEADER)
        require(app.name == "app.bin", "first application entry is not app.bin")
        require(app.offset == 0x120 and app.size == APP_DATA_SIZE, "app.bin layout changed")
        require(app.flags == 0x82 and app.reserved == 0xFF and app.index == 0,
                "app.bin JLFS flags changed")
        require(crc16(plain[APP_DATA_OFFSET : APP_DATA_OFFSET + APP_DATA_SIZE]) == app.data_crc,
                "app.bin data CRC mismatch")
        return cls(bytearray(encrypted_flash), plain, area, app)

    def app_bytes(self) -> bytes:
        return bytes(self.plain_flash[APP_DATA_OFFSET : APP_DATA_OFFSET + APP_DATA_SIZE])

    def replace_app_bytes(self, app_data: bytes) -> tuple[bytearray, list[int]]:
        require(len(app_data) == APP_DATA_SIZE, "replacement app.bin size changed")
        original_plain = bytes(self.plain_flash)
        original_app = self.app_bytes()
        self.plain_flash[APP_DATA_OFFSET : APP_DATA_OFFSET + APP_DATA_SIZE] = app_data
        update_jlfs_crc(self.plain_flash, self.app, APP_DATA_OFFSET, APP_DATA_SIZE)
        update_jlfs_crc(
            self.plain_flash,
            self.area,
            APP_AREA_BASE + 32,
            APP_AREA_END - APP_AREA_BASE - 32,
        )

        output = bytearray(self.plain_flash)
        sfc_cipher(output, APP_AREA_BASE, APP_AREA_END - APP_AREA_BASE, APP_AREA_BASE, CHIP_KEY)
        require(output[:APP_AREA_BASE] == self.encrypted_flash[:APP_AREA_BASE],
                "protected boot/config prefix changed")
        require(output[APP_AREA_END:] == self.encrypted_flash[APP_AREA_END:],
                "protected resource/reserved suffix changed")

        changed_plain = difference_offsets(original_plain, self.plain_flash)
        allowed = set(range(APP_AREA_BASE, APP_AREA_BASE + 4))
        allowed.update(range(APP_ENTRY_HEADER, APP_ENTRY_HEADER + 4))
        allowed.update(
            APP_DATA_OFFSET + index
            for index, pair in enumerate(zip(original_app, app_data))
            if pair[0] != pair[1]
        )
        unexpected = sorted(set(changed_plain) - allowed)
        if unexpected:
            raise FormatError(f"unexpected plaintext changes at 0x{unexpected[0]:x}")
        return output, changed_plain


def protected_hashes(encrypted_flash: bytes | bytearray) -> dict[str, str]:
    return {
        "boot_and_flash_layout_0x0000_0x3fff": sha256(encrypted_flash[:APP_AREA_BASE]),
        "post_app_resources_and_reserved": sha256(encrypted_flash[APP_AREA_END:]),
        "uboot_boot_raw_0x00a0_0x38cf": sha256(encrypted_flash[0xA0:0x38D0]),
        "isd_config_raw_0x38d0_0x3b8a": sha256(encrypted_flash[0x38D0:0x3B8B]),
    }


def build_package(original: bytes, replacement_app: bytes) -> tuple[bytes, dict[str, object]]:
    payload, metadata = unpack_fwsc(original)
    original_payload = bytes(payload)
    ufw = Ufw.parse(payload)
    original_flash = ufw.flash()
    app_image = AppImage.parse(original_flash)
    original_app = app_image.app_bytes()
    output_flash, changed_plain = app_image.replace_app_bytes(replacement_app)
    ufw.replace_flash(output_flash)
    output = repack_fwsc(original, ufw.payload, metadata)

    before_protected = protected_hashes(original_flash)
    after_protected = protected_hashes(output_flash)
    require(before_protected == after_protected, "a protected flash hash changed")

    flash_changes = difference_offsets(original_flash, output_flash)
    allowed_flash = set(changed_plain)
    require(set(flash_changes) == allowed_flash, "encrypted flash changes do not match audited plaintext changes")

    payload_changes = difference_offsets(original_payload, ufw.payload)
    flash_entry = ufw.flash_entry()
    allowed_payload = set(range(0, UFW_HEADER_SIZE))
    allowed_payload.update(range(UFW_HEADER_SIZE, UFW_HEADER_SIZE + UFW_ENTRY_SIZE))
    allowed_payload.update(flash_entry.offset + offset for offset in flash_changes)
    require(not (set(payload_changes) - allowed_payload), "unexpected OTA wrapper bytes changed")

    reparsed_payload, _ = unpack_fwsc(output) if output == original else (None, None)
    if output == original:
        require(reparsed_payload == original_payload, "no-op package failed strict reparse")
    else:
        reparsed = Ufw.parse(ufw.payload)
        reparsed_app = AppImage.parse(reparsed.flash())
        require(reparsed_app.app_bytes() == replacement_app, "repacked app.bin verification failed")

    manifest: dict[str, object] = {
        "format": "smk37-v15-application-only-patch-v1",
        "safety_gate": "PASS",
        "input": {
            "size": len(original),
            "sha256": sha256(original),
            "payload_sha256": sha256(original_payload),
            "app_sha256": sha256(original_app),
        },
        "output": {
            "size": len(output),
            "sha256": sha256(output),
            "payload_sha256": sha256(ufw.payload),
            "app_sha256": sha256(replacement_app),
        },
        "layout": {
            "ufw_flash_offset": flash_entry.offset,
            "ufw_flash_size": flash_entry.size,
            "app_area_start": APP_AREA_BASE,
            "app_area_end_exclusive": APP_AREA_END,
            "app_data_start": APP_DATA_OFFSET,
            "app_data_size": APP_DATA_SIZE,
        },
        "changes": {
            "app_byte_count": len(difference_offsets(original_app, replacement_app)),
            "app_ranges": compact_ranges(difference_offsets(original_app, replacement_app)),
            "flash_byte_count_including_crc_fields": len(flash_changes),
            "flash_ranges": compact_ranges(flash_changes),
            "ota_payload_byte_count_including_wrapper_crc_fields": len(payload_changes),
            "fwsc_byte_count": len(difference_offsets(original, output)),
        },
        "protected_flash_hashes_before": before_protected,
        "protected_flash_hashes_after": after_protected,
    }
    return output, manifest


def inspect_package(raw: bytes) -> dict[str, object]:
    payload, _ = unpack_fwsc(raw)
    ufw = Ufw.parse(payload)
    flash = ufw.flash()
    app = AppImage.parse(flash)
    entry = ufw.flash_entry()
    return {
        "format": "smk37-v15-inspection-v1",
        "safety_gate": "PASS",
        "package_sha256": sha256(raw),
        "payload_sha256": sha256(payload),
        "flash_sha256": sha256(flash),
        "app_sha256": sha256(app.app_bytes()),
        "ufw_entries": [
            {
                "index": item.entry_index,
                "type": item.entry_type,
                "name": item.name,
                "offset": item.offset,
                "size": item.size,
                "data_crc16": f"0x{item.data_crc:04x}",
            }
            for item in ufw.entries
        ],
        "layout": {
            "flash_offset": entry.offset,
            "flash_size": entry.size,
            "app_area_start": APP_AREA_BASE,
            "app_area_end_exclusive": APP_AREA_END,
            "app_data_start": APP_DATA_OFFSET,
            "app_data_size": APP_DATA_SIZE,
            "chip_key": f"0x{CHIP_KEY:04x}",
        },
        "protected_flash_hashes": protected_hashes(flash),
    }


def write_json(path: Path | None, value: dict[str, object]) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if path is None:
        sys.stdout.write(rendered)
    else:
        path.write_text(rendered, encoding="utf-8")


def self_test() -> None:
    require(crc16(b"123456789") == 0x31C3, "CRC16 known vector failed")
    sample = bytearray(range(128))
    original = bytes(sample)
    enc_cipher(sample, 0, len(sample))
    require(sample != original, "ENC cipher did not transform data")
    enc_cipher(sample, 0, len(sample))
    require(sample == original, "ENC cipher is not reversible")
    sample = bytearray(range(128))
    original = bytes(sample)
    sfc_cipher(sample, 32, 64, 32, CHIP_KEY)
    sfc_cipher(sample, 32, 64, 32, CHIP_KEY)
    require(sample == original, "SFC cipher is not reversible")
    print("smk37_v15_app_patch self-test: PASS")


def parse_hex_bytes(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def apply_unique_replacements(
    original: bytes, replacements: list[tuple[bytes, bytes]]
) -> tuple[bytes, list[dict[str, object]]]:
    require(len(replacements) > 0, "at least one replacement is required")
    located: list[tuple[int, bytes, bytes]] = []
    for old, new in replacements:
        require(len(old) > 0, "empty search sequence is not allowed")
        require(len(old) == len(new),
                "replacement must have exactly the same length")
        count = original.count(old)
        require(count == 1,
                f"search sequence {old.hex()} occurs {count} times; exactly one is required")
        located.append((original.index(old), old, new))

    located.sort(key=lambda item: item[0])
    previous_end = 0
    for offset, old, _ in located:
        require(offset >= previous_end, "replacement ranges overlap")
        previous_end = offset + len(old)

    output = bytearray(original)
    audit: list[dict[str, object]] = []
    for offset, old, new in located:
        output[offset : offset + len(old)] = new
        audit.append({
            "app_offset": offset,
            "old_hex": old.hex(),
            "new_hex": new.hex(),
        })
    return bytes(output), audit


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("self-test", help="run cipher and CRC unit tests")

    inspect_parser = subparsers.add_parser("inspect", help="validate and describe official v15")
    inspect_parser.add_argument("input", type=Path)
    inspect_parser.add_argument("--manifest", type=Path)

    extract_parser = subparsers.add_parser(
        "extract-app", help="extract the byte-exact app.bin from official v15"
    )
    extract_parser.add_argument("input", type=Path)
    extract_parser.add_argument("output", type=Path)

    roundtrip_parser = subparsers.add_parser("roundtrip", help="decode/re-encode without changing app.bin")
    roundtrip_parser.add_argument("input", type=Path)
    roundtrip_parser.add_argument("output", type=Path)
    roundtrip_parser.add_argument("--manifest", type=Path)

    patch_parser = subparsers.add_parser(
        "patch-bytes",
        help="replace one or more unique equal-length byte sequences in app.bin",
    )
    patch_parser.add_argument("input", type=Path)
    patch_parser.add_argument("output", type=Path)
    patch_parser.add_argument("--old-hex", type=parse_hex_bytes)
    patch_parser.add_argument("--new-hex", type=parse_hex_bytes)
    patch_parser.add_argument(
        "--replace-hex", action="append", nargs=2,
        metavar=("OLD", "NEW"), type=parse_hex_bytes,
        help="repeatable OLD NEW hex pair",
    )
    patch_parser.add_argument("--manifest", type=Path)

    app_parser = subparsers.add_parser(
        "repack-app",
        help="repack one exact-size replacement app.bin into official v15",
    )
    app_parser.add_argument("input", type=Path)
    app_parser.add_argument("replacement_app", type=Path)
    app_parser.add_argument("output", type=Path)
    app_parser.add_argument("--manifest", type=Path)

    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return 0

    raw = args.input.read_bytes()
    if args.command == "inspect":
        write_json(args.manifest, inspect_package(raw))
        return 0

    payload, _ = unpack_fwsc(raw)
    current_app = AppImage.parse(Ufw.parse(payload).flash()).app_bytes()
    if args.command == "extract-app":
        args.output.write_bytes(current_app)
        return 0
    if args.command == "repack-app":
        replacement = args.replacement_app.read_bytes()
        require(len(replacement) == APP_DATA_SIZE, "replacement app.bin size changed")
        replacement_audit = []
    elif args.command == "roundtrip":
        replacement = current_app
        replacement_audit = []
    else:
        legacy_pair_supplied = args.old_hex is not None or args.new_hex is not None
        require(not legacy_pair_supplied or
                (args.old_hex is not None and args.new_hex is not None),
                "--old-hex and --new-hex must be supplied together")
        require(not (legacy_pair_supplied and args.replace_hex),
                "use either --old-hex/--new-hex or --replace-hex, not both")
        requested = ([(args.old_hex, args.new_hex)] if legacy_pair_supplied
                     else (args.replace_hex or []))
        replacement, replacement_audit = apply_unique_replacements(
            current_app, requested)

    output, manifest = build_package(raw, replacement)
    if replacement_audit:
        manifest["requested_replacements"] = replacement_audit
    if args.command == "roundtrip":
        require(output == raw, "no-op roundtrip is not byte-identical")
        manifest["roundtrip_byte_identical"] = True
    args.output.write_bytes(output)
    write_json(args.manifest, manifest)
    if args.manifest is not None:
        print(f"safety gate: PASS; manifest: {args.manifest}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FormatError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
