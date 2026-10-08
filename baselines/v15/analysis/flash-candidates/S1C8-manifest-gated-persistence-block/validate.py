#!/usr/bin/env python3
"""Offline validator for S1C8 manifest-gated persistence BLOCK package."""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
MAGIC = b"SMK37S8P"
RECORD_BASE = 96
MANIFEST_RECORD = 112
SLOTS = 16
RAW_STRIDE = 0xA3
PREFIX_LEN = 0x9C


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


def le32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def main() -> None:
    result = subprocess.run([sys.executable, str(HERE / "analyze.py"), "--check"], cwd=HERE, text=True, capture_output=True, check=False)
    req(result.returncode == 0, "analyze.py --check")

    evidence = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))
    req(evidence["decision"] == "BLOCK", "decision is BLOCK")
    req(evidence["firmware_artifacts_emitted"] is False, "no firmware emitted flag")
    req(evidence["scope"] == {
        "offline_only": True,
        "device_accessed": False,
        "midi_transport_opened": False,
        "flash_performed": False,
        "ota_performed": False,
        "reset_performed": False,
    }, "offline-only scope")
    for forbidden in ["app.bin", "exact_ota.c", "SMK37Pro-v15-S1C8-manifest-gated-persistence-block.fwsc"]:
        req(not (HERE / forbidden).exists(), f"forbidden firmware artifact absent: {forbidden}")

    req(evidence["requirements"]["unseeded_device_behaves_exactly_s1c5"]["status"] == "PASS_ONLY_FOR_BLOCK_PACKAGE", "unseeded rule recorded")
    req(evidence["requirements"]["persistent_data_positively_gated_by_manifest_magic_crc"]["firmware_status"].startswith("BLOCK"), "positive-gate firmware block")
    req(evidence["requirements"]["dynamic_sysex_overrides_persistent_restore"]["status"] == "DESIGN_RULE_RECORDED_NO_FIRMWARE", "dynamic SysEx override rule")
    req(evidence["fit_and_abi_gates"]["positive_gate_floor"]["decision"] == "BLOCK_FIT_AND_ABI", "fit gate blocks")

    pkg = json.loads((HERE / "data-package/package-manifest.json").read_text(encoding="utf-8"))
    req(pkg["scope"]["firmware_candidate"] is False, "data package not firmware")
    req(pkg["manifest_magic"] == MAGIC.decode("ascii"), "manifest magic metadata")
    req(pkg["payload_record_count"] == SLOTS and pkg["manifest_record"] == MANIFEST_RECORD, "record counts")
    req([r["record_index"] for r in pkg["records"]] == list(range(RECORD_BASE, RECORD_BASE + SLOTS)), "payload record sequence")

    payloads = []
    for r in pkg["records"]:
        p = HERE / "data-package" / r["file"]
        data = p.read_bytes()
        req(len(data) == RAW_STRIDE, f"payload size {p.name}")
        req(sha(p) == r["sha256"], f"payload sha {p.name}")
        req(f"0x{crc32(data):08x}" == r["crc32"], f"payload crc {p.name}")
        req(0 <= r["playback_note"] <= 127, f"playback note range {p.name}")
        req(len(bytes.fromhex(r["tail_hex"])) == RAW_STRIDE - PREFIX_LEN, f"tail length {p.name}")
        payloads.append(data)
    joined = b"".join(payloads)

    manifest = (HERE / "data-package" / pkg["manifest_file"]).read_bytes()
    req(len(manifest) == RAW_STRIDE, "manifest record size")
    req(manifest[:8] == MAGIC, "manifest magic bytes")
    req(manifest[8] == 1 and manifest[9] == 0xA5 and manifest[10] == 1, "manifest version/commit/layout")
    req(manifest[11] == SLOTS and manifest[12] == RECORD_BASE and manifest[13] == MANIFEST_RECORD, "manifest counts/base")
    req(struct.unpack_from("<H", manifest, 14)[0] == RAW_STRIDE, "manifest raw stride")
    req(struct.unpack_from("<H", manifest, 16)[0] == RAW_STRIDE, "manifest record length")
    req(struct.unpack_from("<H", manifest, 18)[0] == PREFIX_LEN, "manifest prefix length")
    req(f"0x{le32(manifest, 24):08x}" == pkg["payload_crc32"], "manifest payload crc field")
    req(le32(manifest, 24) == crc32(joined), "payload crc recomputes")
    notes = bytes(r["playback_note"] for r in pkg["records"])
    req(le32(manifest, 28) == crc32(notes), "note crc recomputes")
    for i, data in enumerate(payloads):
        req(le32(manifest, 32 + i * 4) == crc32(data), f"per-record crc {i}")
    req(manifest[96:112] == notes, "manifest note vector")
    zeroed = bytearray(manifest[:PREFIX_LEN])
    zeroed[112:116] = b"\x00" * 4
    req(le32(manifest, 112) == crc32(zeroed), "manifest header crc")

    combined = (HERE / "data-package/candidate-records-096-112.bin").read_bytes()
    req(combined == joined + manifest, "combined record image content")
    req(hashlib.sha256(combined).hexdigest() == pkg["combined_records_sha256"], "combined hash")

    print("S1C8 manifest-gated persistence BLOCK validation PASS")


if __name__ == "__main__":
    main()
