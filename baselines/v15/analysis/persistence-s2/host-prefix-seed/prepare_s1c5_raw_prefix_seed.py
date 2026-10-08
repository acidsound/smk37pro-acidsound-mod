#!/usr/bin/env python3
"""Prepare and validate S1-C5 raw-record-prefix seed sectors.

This tool is intentionally offline-only. It reads ordinary dump files and packet
files, writes ordinary artifact files, and never opens a device path, USB path,
MIDI path, physical drive, or flash transport.

The emitted write package is a forced-sector read-modify-write fallback only. It
must not be used unless a separate live process has produced two identical full
1 MiB dumps and those bytes are passed here as regular files. Runtime firmware
wrapper persistence through 0x02004b02/0x02004870 remains blocked in the current
S1C5 evidence set; see report.md in this directory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import stat
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
DEFAULT_PACKET_DIR = (
    ROOT
    / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/inputs/packets"
)

FORMAT = "smk37-v15-s1c5-raw-prefix-seed-rmw-v1"
DUMP_SIZE = 0x100000
SECTOR_SIZE = 0x1000
RAW_TABLE_PHYS_BASE = 0x0F8000
RAW_RECORD_STRIDE = 0xA3
PREFIX_LEN = 0x9C
VOICE_BYTES = 0x9B
TAIL_LEN = RAW_RECORD_STRIDE - PREFIX_LEN
SLOTS = 16
BANK = 3
PRESET0 = 0
RECORD_BASE_INDEX = BANK * 32 + PRESET0
PACKET_LEN = 163
PACKET_HEADER = bytes.fromhex("f0430000011b")
PACKET_TERM = 0xF7
WIRE_PAYLOAD_OFFSET = len(PACKET_HEADER)
WIRE_PLAYBACK_NOTE_OFFSET = 161
EXPECTED_PACKET_MANIFEST_FORMAT = (
    "smk37-v15-s1c5-playback-register-return.playback-transport-packets-v1"
)
EXPECTED_TRIGGER0 = 36
EXPECTED_PLAYBACK_NOTE = 60


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def hx(value: int, width: int = 5) -> str:
    return "0x" + format(value, f"0{width}x")


def reject_device_path(path: Path, label: str) -> None:
    raw = str(path)
    lower = raw.lower()
    forbidden_prefixes = (
        "\\\\.\\physicaldrive",
        "\\\\.\\",
        "/dev/",
        "disk",
    )
    if lower.startswith(forbidden_prefixes):
        raise SystemExit(f"FAIL: {label} looks like a device path, refusing offline tool: {raw}")
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise SystemExit(f"FAIL: {label} is not a regular file: {raw}")


def read_dump(path: Path, label: str) -> bytes:
    reject_device_path(path, label)
    data = path.read_bytes()
    req(len(data) == DUMP_SIZE, f"{label} must be exactly 1 MiB")
    return data


def load_packets(packet_dir: Path) -> tuple[list[dict[str, Any]], list[bytes]]:
    manifest_path = packet_dir / "packet-manifest.json"
    reject_device_path(manifest_path, "packet manifest")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    req(manifest["format"] == EXPECTED_PACKET_MANIFEST_FORMAT, "packet manifest format")
    req(manifest["status"] == "PASS", "packet manifest status PASS")
    req(manifest["packet_count"] == SLOTS, "packet count 16")
    req(manifest["packet_bytes"] == PACKET_LEN, "packet byte count")
    req(manifest["payload_playback_note_offset"] == VOICE_BYTES, "payload playback-note offset")
    req(manifest["wire_playback_note_offset"] == WIRE_PLAYBACK_NOTE_OFFSET, "wire playback-note offset")
    req(manifest["duplicate_playback_note_test"]["value"] == EXPECTED_PLAYBACK_NOTE, "all-C4 playback value")

    items = manifest["packets"]
    req(len(items) == SLOTS, "manifest packet list length")
    packets: list[bytes] = []
    normalized_items: list[dict[str, Any]] = []
    for slot, item in enumerate(items):
        req(item["slot"] == slot, f"slot {slot} manifest slot")
        req(item["trigger_note"] == EXPECTED_TRIGGER0 + slot, f"slot {slot} trigger note")
        req(item["playback_note"] == EXPECTED_PLAYBACK_NOTE, f"slot {slot} playback note")
        p = packet_dir / item["file"]
        reject_device_path(p, f"packet {slot}")
        pkt = p.read_bytes()
        req(len(pkt) == PACKET_LEN, f"packet {slot} length")
        req(pkt.startswith(PACKET_HEADER), f"packet {slot} header")
        req(pkt[-1] == PACKET_TERM, f"packet {slot} terminator")
        req(sha(pkt) == item["sha256"], f"packet {slot} sha256")
        req(pkt[WIRE_PLAYBACK_NOTE_OFFSET] == EXPECTED_PLAYBACK_NOTE, f"packet {slot} wire playback byte")
        prefix = pkt[WIRE_PAYLOAD_OFFSET:WIRE_PLAYBACK_NOTE_OFFSET] + bytes([pkt[WIRE_PLAYBACK_NOTE_OFFSET]])
        req(len(prefix) == PREFIX_LEN, f"packet {slot} prefix length")
        req(prefix[VOICE_BYTES] < 0x80, f"packet {slot} playback note high bit clear")
        packets.append(prefix)
        normalized_items.append(
            {
                "slot": slot,
                "trigger_note": item["trigger_note"],
                "playback_note": item["playback_note"],
                "packet_file": str(p.relative_to(ROOT)),
                "packet_sha256": item["sha256"],
                "prefix_sha256": sha(prefix),
            }
        )
    return normalized_items, packets


def record_offset(index: int) -> int:
    return RAW_TABLE_PHYS_BASE + index * RAW_RECORD_STRIDE


def sector_base(offset: int) -> int:
    return offset & ~(SECTOR_SIZE - 1)


def sector_name(base: int, kind: str) -> str:
    return f"{kind}-sector-{base:05x}.bin"


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_package(pre_dump: bytes, packet_items: list[dict[str, Any]], prefixes: list[bytes], out: Path) -> dict[str, Any]:
    patched = bytearray(pre_dump)
    records: list[dict[str, Any]] = []
    changed_offsets: set[int] = set()

    for slot, prefix in enumerate(prefixes):
        index = RECORD_BASE_INDEX + slot
        off = record_offset(index)
        before_prefix = bytes(pre_dump[off:off + PREFIX_LEN])
        before_tail = bytes(pre_dump[off + PREFIX_LEN:off + RAW_RECORD_STRIDE])
        req(len(before_tail) == TAIL_LEN, f"slot {slot} tail length")
        patched[off:off + PREFIX_LEN] = prefix
        for rel, (old, new) in enumerate(zip(before_prefix, prefix)):
            if old != new:
                changed_offsets.add(off + rel)
        req(bytes(patched[off + PREFIX_LEN:off + RAW_RECORD_STRIDE]) == before_tail, f"slot {slot} tail preserved")
        records.append(
            {
                **packet_items[slot],
                "reserved_record_index": index,
                "reserved_record_bank": BANK,
                "reserved_record_preset": PRESET0 + slot,
                "physical_record_offset": hx(off),
                "prefix_length": PREFIX_LEN,
                "tail_range": f"{hx(off + PREFIX_LEN)}..{hx(off + RAW_RECORD_STRIDE)}",
                "tail_sha256": sha(before_tail),
                "pre_prefix_sha256": sha(before_prefix),
                "post_prefix_sha256": sha(prefix),
                "changed_prefix_byte_count": sum(a != b for a, b in zip(before_prefix, prefix)),
            }
        )

    sectors = sorted({sector_base(o) for o in changed_offsets})
    req(sectors, "at least one sector changes")
    req(all(0 <= s and s + SECTOR_SIZE <= DUMP_SIZE for s in sectors), "sector bounds")

    write_dir = out / "write-sectors"
    rollback_dir = out / "rollback-sectors"
    if out.exists():
        shutil.rmtree(out)
    write_dir.mkdir(parents=True)
    rollback_dir.mkdir(parents=True)

    sector_items: list[dict[str, Any]] = []
    for base in sectors:
        pre_sector = pre_dump[base:base + SECTOR_SIZE]
        post_sector = bytes(patched[base:base + SECTOR_SIZE])
        req(len(pre_sector) == SECTOR_SIZE and len(post_sector) == SECTOR_SIZE, "sector length")
        write_rel = Path("write-sectors") / sector_name(base, "patched")
        rollback_rel = Path("rollback-sectors") / sector_name(base, "original")
        (out / write_rel).write_bytes(post_sector)
        (out / rollback_rel).write_bytes(pre_sector)
        sector_items.append(
            {
                "sector_base": hx(base),
                "length": SECTOR_SIZE,
                "write_file": str(write_rel),
                "rollback_file": str(rollback_rel),
                "expected_pre_sha256": sha(pre_sector),
                "patched_sha256": sha(post_sector),
                "changed_byte_count": sum(a != b for a, b in zip(pre_sector, post_sector)),
            }
        )

    reconstructed = bytearray(pre_dump)
    for item in sector_items:
        base = int(item["sector_base"], 16)
        reconstructed[base:base + SECTOR_SIZE] = (out / item["write_file"]).read_bytes()
    req(bytes(reconstructed) == bytes(patched), "write-sector reconstruction")

    rollback = bytearray(patched)
    for item in sector_items:
        base = int(item["sector_base"], 16)
        rollback[base:base + SECTOR_SIZE] = (out / item["rollback_file"]).read_bytes()
    req(bytes(rollback) == pre_dump, "rollback-sector reconstruction")

    manifest: dict[str, Any] = {
        "format": FORMAT,
        "decision": "FALLBACK_PACKAGE_BUILT_FROM_SUPPLIED_REGULAR_DUMPS",
        "offline_only": True,
        "device_accessed": False,
        "flash_accessed": False,
        "transport_opened": False,
        "safety_boundary": {
            "primary_path": "normal-firmware helper using 0x02004b02/0x02004870 is BLOCKED in current S1C5 evidence; see report.md",
            "this_artifact": "forced-sector read-modify-write fallback package generated from two identical regular-file dumps",
            "never_do": [
                "do not write a full 1 MiB image",
                "do not write package-managed 0x00000..0x9bfff sectors for this persistence seed",
                "do not touch raw tail bytes 0x9c..0xa2",
                "do not use without target-specific pre-dump hashes matching exactly",
            ],
        },
        "input_dump": {
            "size": len(pre_dump),
            "sha256": sha(pre_dump),
            "required_double_dump_identity": True,
        },
        "raw_record_model": {
            "physical_raw_table_base": hx(RAW_TABLE_PHYS_BASE),
            "record_stride": RAW_RECORD_STRIDE,
            "prefix_length": PREFIX_LEN,
            "voice_bytes_stored": VOICE_BYTES,
            "playback_note_offset": VOICE_BYTES,
            "tail_bytes_preserved_per_record": TAIL_LEN,
            "reserved_record_base_index": RECORD_BASE_INDEX,
            "reserved_record_count": SLOTS,
            "reserved_bank": "D",
            "reserved_presets": "1..16",
        },
        "records": records,
        "sectors": sector_items,
        "changed_absolute_offsets": [hx(o) for o in sorted(changed_offsets)],
        "post_dump_sha256_if_sectors_applied": sha(patched),
        "rollback_restores_exact_input_dump": True,
        "readback_validation": "After any external sector write, run this tool's validate-readback on two regular-file readback dumps before trusting the state.",
    }
    write_json(out / "manifest.json", manifest)

    lines = [f"{shaf(out / 'manifest.json')}  manifest.json"]
    for rel in sorted([Path(item["write_file"]) for item in sector_items] + [Path(item["rollback_file"]) for item in sector_items]):
        lines.append(f"{shaf(out / rel)}  {rel.as_posix()}")
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def command_build(args: argparse.Namespace) -> int:
    a = read_dump(args.pre_dump_a, "pre dump A")
    b = read_dump(args.pre_dump_b, "pre dump B")
    req(a == b, "pre-dump A/B byte identity")
    packet_items, prefixes = load_packets(args.packet_dir)
    manifest = build_package(a, packet_items, prefixes, args.output_dir)
    print(
        "BUILD PASS: %s sectors, manifest=%s, input_sha256=%s, post_sha256=%s"
        % (len(manifest["sectors"]), args.output_dir / "manifest.json", manifest["input_dump"]["sha256"], manifest["post_dump_sha256_if_sectors_applied"])
    )
    return 0


def load_manifest(path: Path) -> dict[str, Any]:
    reject_device_path(path, "manifest")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    req(manifest["format"] == FORMAT, "manifest format")
    return manifest


def apply_sector_files(base_dump: bytes, manifest: dict[str, Any], manifest_dir: Path, key: str) -> bytes:
    work = bytearray(base_dump)
    for item in manifest["sectors"]:
        base = int(item["sector_base"], 16)
        rel = item[key]
        path = manifest_dir / rel
        reject_device_path(path, rel)
        sector = path.read_bytes()
        req(len(sector) == SECTOR_SIZE, f"{rel} sector length")
        expected_hash = item["patched_sha256"] if key == "write_file" else item["expected_pre_sha256"]
        req(sha(sector) == expected_hash, f"{rel} sha256")
        work[base:base + SECTOR_SIZE] = sector
    return bytes(work)


def check_sha256s(manifest_dir: Path) -> None:
    sums = manifest_dir / "SHA256SUMS"
    reject_device_path(sums, "SHA256SUMS")
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        path = manifest_dir / rel
        reject_device_path(path, rel)
        req(shaf(path) == digest, "SHA256SUMS " + rel)


def validate_artifacts(manifest: dict[str, Any], manifest_dir: Path) -> None:
    check_sha256s(manifest_dir)
    req(manifest["offline_only"] is True, "offline-only flag")
    req(manifest["device_accessed"] is False and manifest["flash_accessed"] is False, "no device/flash flags")
    req(manifest["rollback_restores_exact_input_dump"] is True, "rollback flag")
    for item in manifest["records"]:
        req(item["reserved_record_index"] == RECORD_BASE_INDEX + item["slot"], "record index arithmetic")
        off = int(item["physical_record_offset"], 16)
        req(off == record_offset(item["reserved_record_index"]), "record physical offset arithmetic")
    for item in manifest["sectors"]:
        base = int(item["sector_base"], 16)
        req(base % SECTOR_SIZE == 0 and 0 <= base < DUMP_SIZE, "sector base bounds")
        for key in ["write_file", "rollback_file"]:
            path = manifest_dir / item[key]
            reject_device_path(path, item[key])
            req(path.exists() and path.stat().st_size == SECTOR_SIZE, item[key] + " exists")


def command_check_artifacts(args: argparse.Namespace) -> int:
    manifest_path = args.manifest
    manifest = load_manifest(manifest_path)
    validate_artifacts(manifest, manifest_path.parent)
    print("ARTIFACT CHECK PASS: " + str(manifest_path))
    return 0


def command_validate_readback(args: argparse.Namespace) -> int:
    manifest_path = args.manifest
    manifest = load_manifest(manifest_path)
    manifest_dir = manifest_path.parent
    validate_artifacts(manifest, manifest_dir)
    pre_a = read_dump(args.pre_dump_a, "pre dump A")
    pre_b = read_dump(args.pre_dump_b, "pre dump B")
    req(pre_a == pre_b, "pre-dump A/B byte identity")
    req(sha(pre_a) == manifest["input_dump"]["sha256"], "pre dump sha256 matches manifest")

    post_a = read_dump(args.post_dump_a, "post/readback dump A")
    post_b = read_dump(args.post_dump_b, "post/readback dump B")
    req(post_a == post_b, "post/readback dump A/B byte identity")
    expected_post = apply_sector_files(pre_a, manifest, manifest_dir, "write_file")
    req(sha(expected_post) == manifest["post_dump_sha256_if_sectors_applied"], "expected post sha256")
    req(post_a == expected_post, "post/readback dump equals manifest-applied write sectors")

    for item in manifest["records"]:
        off = int(item["physical_record_offset"], 16)
        tail_pre = pre_a[off + PREFIX_LEN:off + RAW_RECORD_STRIDE]
        tail_post = post_a[off + PREFIX_LEN:off + RAW_RECORD_STRIDE]
        req(tail_pre == tail_post, f"slot {item['slot']} tail preserved")
        req(sha(post_a[off:off + PREFIX_LEN]) == item["post_prefix_sha256"], f"slot {item['slot']} prefix sha")
    print("READBACK VALIDATION PASS: " + str(manifest_path))
    return 0


def command_validate_rollback(args: argparse.Namespace) -> int:
    manifest_path = args.manifest
    manifest = load_manifest(manifest_path)
    manifest_dir = manifest_path.parent
    validate_artifacts(manifest, manifest_dir)
    pre = read_dump(args.pre_dump, "pre dump")
    req(sha(pre) == manifest["input_dump"]["sha256"], "pre dump sha256 matches manifest")
    rolled = read_dump(args.rollback_readback_dump, "rollback readback dump")
    req(rolled == pre, "rollback readback equals exact original pre dump")
    expected_rollback = apply_sector_files(apply_sector_files(pre, manifest, manifest_dir, "write_file"), manifest, manifest_dir, "rollback_file")
    req(expected_rollback == pre, "rollback files reconstruct exact pre dump")
    print("ROLLBACK VALIDATION PASS: " + str(manifest_path))
    return 0


def command_self_test(args: argparse.Namespace) -> int:
    del args
    packet_items, prefixes = load_packets(DEFAULT_PACKET_DIR)
    with tempfile.TemporaryDirectory(prefix="s1c5-prefix-seed-selftest-") as tmp_s:
        tmp = Path(tmp_s)
        dump = bytes(((i * 37 + 11) & 0xFF) for i in range(DUMP_SIZE))
        a = tmp / "pre-a.bin"
        b = tmp / "pre-b.bin"
        a.write_bytes(dump)
        b.write_bytes(dump)
        out = tmp / "pkg"
        manifest = build_package(dump, packet_items, prefixes, out)
        validate_artifacts(manifest, out)
        expected_post = apply_sector_files(dump, manifest, out, "write_file")
        post_a = tmp / "post-a.bin"
        post_b = tmp / "post-b.bin"
        post_a.write_bytes(expected_post)
        post_b.write_bytes(expected_post)
        ns = argparse.Namespace(manifest=out / "manifest.json", pre_dump_a=a, pre_dump_b=b, post_dump_a=post_a, post_dump_b=post_b)
        command_validate_readback(ns)
        rollback = apply_sector_files(expected_post, manifest, out, "rollback_file")
        rolled = tmp / "rolled.bin"
        rolled.write_bytes(rollback)
        ns2 = argparse.Namespace(manifest=out / "manifest.json", pre_dump=a, rollback_readback_dump=rolled)
        command_validate_rollback(ns2)
    print("SELF-TEST PASS: offline regular-file RMW package, readback, and rollback")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("build", help="Build guarded RMW sector artifacts from two identical regular-file dumps")
    p.add_argument("--pre-dump-a", type=Path, required=True)
    p.add_argument("--pre-dump-b", type=Path, required=True)
    p.add_argument("--packet-dir", type=Path, default=DEFAULT_PACKET_DIR)
    p.add_argument("--output-dir", type=Path, required=True)
    p.set_defaults(func=command_build)

    p = sub.add_parser("check-artifacts", help="Check manifest, sector files, hashes, and offline flags")
    p.add_argument("--manifest", type=Path, required=True)
    p.set_defaults(func=command_check_artifacts)

    p = sub.add_parser("validate-readback", help="Validate two post-write regular-file dumps against the guarded write manifest")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--pre-dump-a", type=Path, required=True)
    p.add_argument("--pre-dump-b", type=Path, required=True)
    p.add_argument("--post-dump-a", type=Path, required=True)
    p.add_argument("--post-dump-b", type=Path, required=True)
    p.set_defaults(func=command_validate_readback)

    p = sub.add_parser("validate-rollback", help="Validate a rollback readback dump returns to the exact pre dump")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--pre-dump", type=Path, required=True)
    p.add_argument("--rollback-readback-dump", type=Path, required=True)
    p.set_defaults(func=command_validate_rollback)

    p = sub.add_parser("self-test", help="Run deterministic synthetic offline self-test")
    p.set_defaults(func=command_self_test)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
