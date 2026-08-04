#!/usr/bin/env python3
"""Offline validator for S1C9 minimum-budget persistence BLOCK package."""
from __future__ import annotations

import hashlib
import json
import struct
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATA = HERE / "data-package"
PREFIX_LEN = 0x9C
SLOTS = 16


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def crc32(data: bytes | bytearray) -> int:
    return zlib.crc32(bytes(data)) & 0xFFFFFFFF


def le32(data: bytes | bytearray, off: int) -> int:
    return struct.unpack_from("<I", bytes(data), off)[0]


def main() -> None:
    ev = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
    pkg = json.loads((DATA / "package-manifest.json").read_text(encoding="utf-8"))
    helpers = json.loads((HERE / "helpers.json").read_text(encoding="utf-8"))
    req(ev["decision"] == "BLOCK_NO_FIRMWARE_CANDIDATE", "decision is BLOCK")
    req(not ev["candidate_built"], "candidate_built false")
    for forbidden in ["app.bin", "exact_ota.c", "SMK37Pro-v15-S1C9-min-budget-persistence-block.fwsc"]:
        req(not (HERE / forbidden).exists(), f"forbidden firmware artifact absent: {forbidden}")
    req(helpers["storage_read"]["verdict"].startswith("PASS"), "storage read helper located")
    req(helpers["crc_or_checksum"]["verdict"] == "BLOCK_NO_CALLABLE_ABI", "CRC callable blocked")
    req(helpers["bounded_memcmp"]["verdict"] == "BLOCK_NOT_LOCATED", "bounded memcmp blocked")
    records = pkg["records"]
    req(len(records) == SLOTS, "16 payload prefixes")
    prefixes = []
    notes = bytearray()
    for rec in records:
        p = DATA / rec["prefix_file"]
        data = p.read_bytes()
        req(len(data) == PREFIX_LEN, f"prefix len {p.name}")
        req(sha(p) == rec["prefix_sha256"], f"prefix sha {p.name}")
        req(f"0x{crc32(data):08x}" == rec["prefix_crc32"], f"prefix crc {p.name}")
        req(data[0x9B] == rec["playback_note"], f"playback note byte {p.name}")
        prefixes.append(data)
        notes.append(data[0x9B])
    joined = b"".join(prefixes)
    manifest = (DATA / pkg["manifest_prefix_file"]).read_bytes()
    req(len(manifest) == PREFIX_LEN, "manifest prefix len")
    req(manifest[:8] == b"SMK37S9P", "manifest magic")
    req(manifest[8] == 1 and manifest[9] == 0xA5 and manifest[11] == SLOTS, "manifest core fields")
    req(f"0x{le32(manifest, 22):08x}" == pkg["payload_crc32"], "payload crc field")
    req(le32(manifest, 22) == crc32(joined), "payload crc recomputes")
    req(le32(manifest, 26) == crc32(notes), "notes crc recomputes")
    for i, data in enumerate(prefixes):
        req(le32(manifest, 30 + i * 4) == crc32(data), f"manifest per-prefix crc {i}")
    req(manifest[94:110] == bytes(notes), "manifest note array")
    zeroed = bytearray(manifest)
    zeroed[112:116] = b"\x00" * 4
    req(le32(manifest, 112) == crc32(zeroed), "manifest header crc")
    combined = (DATA / pkg["combined_prefixes_file"]).read_bytes()
    req(combined == joined + manifest, "combined prefixes exact")
    req(hashlib.sha256(combined).hexdigest() == pkg["combined_prefixes_sha256"], "combined sha")
    print("S1C9 minimum-budget persistence BLOCK validation PASS")


if __name__ == "__main__":
    main()
