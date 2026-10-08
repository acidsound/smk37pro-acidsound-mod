#!/usr/bin/env python3
"""Independent offline validator for S1-C3 16-slot functional release.

No device, OTA upload, flash, reset, MIDI, USB transport, or live send is opened.
This validator checks bytes, hashes, local manifests, rollback reconstruction,
C check/dry-run tooling, and fail-closed reject paths only.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
BOUNDARY_DIR = HERE.parent / "S1C3-16slot-boundary-only"
sys.path.insert(0, str(BOUNDARY_DIR))
from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_SIZE,
    AppImage,
    Ufw,
    difference_offsets,
    unpack_fwsc,
)

FORMAT = "smk37-v15-s1c3-16slot-functional-release-v1"
PACKAGE_NAME = "SMK37Pro-v15-S1C3-16slot-functional.fwsc"
BASE = 0x02000000
SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
PRODUCER_START = 0x0201E1A2
PRODUCER_END = 0x0201E24E
PRODUCER_DIRECT_ENTRY = 0x0201E224
SEGMENTED_STUB = 0x0201E220
DIRECT_PRODUCT_CALL = 0x0201E468
DIRECT_RELOAD_CALL = 0x0201E46C
SEGMENTED_PRODUCT_CALL = 0x0201E49C
SEGMENTED_RELOAD_CALL = 0x0201E4A0
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
EXPECTED_PAD_TO_SLOT = [4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 2, 3, 8, 9, 10, 11]

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "boundary_app": "c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14",
    "boundary_fwsc": "2345102aadded732b13e22d1410d3f7b05f104ffc408bd1d6eba03ea2afc058c",
    "selector": "ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915",
    "selector_live_code": "894f61ee4eedb942b6653bd36dc72934d3719b54a9a413f6c94f29d0084f8ffc",
    "producer": "5c0ec6675c29b8f20d055938425ceb12c356513c29b79b761f1a469eaa068a75",
    "producer_source_evidence": "0bed1fd8ba8dba7e42c371eec8d5cb71e8296ced3b95d688407e9732eeb8a288",
    "packet_source_manifest": "98b3258ad107f5421d4a3e23db7baca3f15fd7f15690d4df979a191093d949e9",
    "app": "a6f99cf6672ae3bd5b00312876a77ce1ed0e8a909ef56df7af0db34a2f726e05",
    "package": "974c1675426e5d43f6b48e7ac7a1142f40062fca945dc6ba1b3ace8b0d144496",
    "ota_token": "INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-974C1675",
    "sender_token": "SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7",
    "commits": {
        "compact_producer": "3507a5634cf1379f63dc40fa65c55456d4bb9091",
        "bank_d_packet_set": "fe3350063c56a0cff7ab855735b0c7e8a04c957e",
        "selector": "3e99ac3e8b40a1c0733cf6a2a6e6fd5aabbbfa90",
        "boundary": "779356aa3565c43de8141ca289c269e5c1e57796",
        "pad_permutation": "2a23cf5017eff520f775e511f8d3d80e15163e7d",
    },
    "packet_hashes": [
        "1c9239621563722eaac0a85db411571963f9ebbd0dbbb00b21044b76b1581427",
        "afa8957005341e6144962ce3120bb1d829475714077617ea8da2c3fee4a0aa21",
        "8a87a409056457e61944d01bf4bbc0266414b8385c3a848125700da9e8417de3",
        "a5c086a77b4de1ce9546e747b72f79d8f6ad7b0dbd7c3b6e1665ef7edf83ff58",
        "ffd1bcc6c7a7c5d8a1bb35f5bf7e39bf63058e62ac574e1e308ba53edc6670ff",
        "57136706fa633b5b47008ed2616471f72ae629d69e601e33c66daad991df94e9",
        "0f202d88578152ca024b3822f56a7c74c485c42996695033a4c239449d30f366",
        "d4ee6f2ccfce2d0c548917bb58ead4988dc3038c2b84edaaa37f047d2e006ea2",
        "c8c489b72b195dfe5f373b6a860b32f0d07a29a83a9f2c070299df5af88a9cb3",
        "9c895d925a6cb79c4dff9f9f27727cce02f6dd0ed86467c994d7f459f1036258",
        "802944d0e1a8f4e85f1a3a694e2a0dbbfe9bb55972814f11ed4c7be7575b6704",
        "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d",
        "622a06870f189b6e4582f0093255f450403d4112836f09563c0b4623c1b287cd",
        "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
        "b159db617616621759bb9990991a8214c585d1f7ecd1be0f36d53a0b71b160c8",
        "39a3e4eca1c740f719b3495f2a88c63e3b5d575a16a98c7b05fbc211fbfa4775",
    ],
}


def req(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def off(address: int) -> int:
    value = address - BASE
    req(0 <= value < APP_DATA_SIZE, f"address outside app: 0x{address:08x}")
    return value


def short_call_target(at: int, blob: bytes) -> int:
    req(len(blob) == 4 and blob[:2] == b"\xbf\xea", f"short-call encoding at 0x{at:08x}")
    half = struct.unpack("<H", blob[2:])[0]
    return ((at + 4 + half * 2) & 0xFFFF) | (at & 0xFFFF0000)


def unpack_any_fwsc(raw: bytes) -> bytearray:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    req(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "FWSC payload size")
    return payload


def flash_and_app_from_fwsc(path: Path, official: bool = False) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    payload = unpack_fwsc(raw)[0] if official else unpack_any_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def run(args: list[str], *, cwd: Path = HERE, expect: int = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    if result.returncode != expect:
        raise SystemExit(
            "FAIL: command returned %d expected %d: %s\nstdout:\n%s\nstderr:\n%s"
            % (result.returncode, expect, " ".join(args), result.stdout, result.stderr)
        )
    return result


def validate_release_manifests() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    evidence = read_json(HERE / "evidence.json")
    app_manifest = read_json(HERE / "app-manifest.json")
    package_manifest = read_json(HERE / "package-manifest.json")
    req(evidence["format"] == FORMAT, "evidence format")
    req(evidence["decision"] == "PASS" and evidence["candidate_built"] is True, "release PASS decision")
    req(evidence["device_accessed"] is False and evidence["midi_transport_opened"] is False and evidence["flash_performed"] is False, "offline scope flags")
    req(evidence["flash"]["confirmation_token"] == EXPECTED["ota_token"], "OTA token")
    req(evidence["sender"]["confirmation_token"] == EXPECTED["sender_token"], "sender token")
    req(evidence["sender"]["default_compile_live_usb_enabled"] is False, "sender live USB default disabled")
    req(evidence["sender"]["inter_packet_delay_ms"] == 100, "sender producer pacing")
    req(evidence["pad_mapping"]["scope"] == "UI_ONLY", "pad mapping UI-only")
    req(evidence["pad_mapping"]["producer_selector_packet_order"] == "note_order_36_51", "pad mapping cannot change note order")
    req(evidence["pad_mapping"]["physical_pad_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "pad permutation sequence")
    req(evidence["source_commits"] == EXPECTED["commits"], "source commits pinned")
    req(app_manifest["format"] == FORMAT + ".app-manifest-v1", "app manifest format")
    req(package_manifest["safety_gate"] == "PASS", "package repack safety gate PASS")
    req(package_manifest["output"]["sha256"] == EXPECTED["package"], "package manifest output hash")
    req(package_manifest["output"]["app_sha256"] == EXPECTED["app"], "package manifest app hash")
    gates = {gate["name"]: gate for gate in evidence["input_gates"]}
    req(set(gates) == {"exact-live-pass-s1c3-boundary-app", "reviewed-96-byte-16-note-selector", "compact-16-slot-producer", "exact-16-packet-set"}, "exact gate set")
    for gate in gates.values():
        req(gate["status"] == "PASS", f"gate PASS {gate['name']}")
    req(gates["exact-live-pass-s1c3-boundary-app"]["app_hash"] == EXPECTED["boundary_app"], "boundary app hash")
    req(gates["exact-live-pass-s1c3-boundary-app"]["fwsc_hash"] == EXPECTED["boundary_fwsc"], "boundary FWSC hash")
    req(gates["reviewed-96-byte-16-note-selector"]["selector_hash"] == EXPECTED["selector"], "selector hash")
    req(gates["reviewed-96-byte-16-note-selector"]["live_code_hash"] == EXPECTED["selector_live_code"], "selector live-code hash")
    req(gates["reviewed-96-byte-16-note-selector"]["note_first_inclusive"] == 36 and gates["reviewed-96-byte-16-note-selector"]["note_last_inclusive"] == 51, "selector note range")
    req(gates["compact-16-slot-producer"]["producer_hash"] == EXPECTED["producer"], "producer hash")
    req(gates["compact-16-slot-producer"]["source_evidence_sha256"] == EXPECTED["producer_source_evidence"], "producer source evidence hash")
    req(gates["compact-16-slot-producer"]["source_exact_pi32_producer_bytes"] == "PASS", "producer exact bytes PASS")
    packet_gate = gates["exact-16-packet-set"]
    req(len(packet_gate["packets"]) == 16, "16 packets")
    req(packet_gate["pad_permutation"]["ui_only"] is True, "packet gate Pad UI-only")
    req(packet_gate["pad_permutation"]["pad_1_to_16_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "packet gate Pad permutation")
    return evidence, app_manifest, package_manifest


def validate_images_and_rollback(evidence: dict[str, Any], app_manifest: dict[str, Any], package_manifest: dict[str, Any]) -> None:
    official_fwsc = HERE.parent / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
    req(sha_path(official_fwsc) == EXPECTED["official_fwsc"], "official FWSC input hash")
    req(sha_path(HERE / "app.bin") == EXPECTED["app"], "candidate app file hash")
    req(sha_path(HERE / PACKAGE_NAME) == EXPECTED["package"], "candidate package file hash")

    official_raw, official_flash, official_app = flash_and_app_from_fwsc(official_fwsc, official=True)
    candidate_raw, candidate_flash, candidate_app = flash_and_app_from_fwsc(HERE / PACKAGE_NAME)
    req(sha(official_raw) == EXPECTED["official_fwsc"], "official raw hash")
    req(sha(official_app) == EXPECTED["official_app"], "official app extracted hash")
    req(sha(candidate_raw) == EXPECTED["package"], "candidate raw hash")
    req(candidate_app == (HERE / "app.bin").read_bytes(), "FWSC embeds candidate app")
    req(package_manifest["output"]["payload_sha256"] == sha(unpack_any_fwsc(candidate_raw)), "package payload hash")

    selector = candidate_app[off(SELECTOR_START):off(SELECTOR_END)]
    producer = candidate_app[off(PRODUCER_START):off(PRODUCER_END)]
    req(len(selector) == 96 and sha(selector) == EXPECTED["selector"], "candidate selector slice")
    req(selector == (HERE.parents[1] / "patch-set-ui/s1c3/selector/selector.bin").read_bytes(), "selector slice equals source")
    req(len(producer) == 172 and sha(producer) == EXPECTED["producer"], "candidate producer slice")
    req(producer == (HERE / "inputs/producer/producer.bin").read_bytes(), "producer slice equals input")
    req(candidate_app[off(SEGMENTED_STUB):off(SEGMENTED_STUB) + 4] == bytes.fromhex("79045904"), "segmented stub immediate return bytes")

    req(short_call_target(DIRECT_PRODUCT_CALL, candidate_app[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL) + 4]) == PRODUCER_DIRECT_ENTRY, "direct product reset-wrapper target")
    req(candidate_app[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL) + 4].hex() == "bfeadcfe", "direct product reset-wrapper bytes")
    req(short_call_target(SEGMENTED_PRODUCT_CALL, candidate_app[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL) + 4]) == SEGMENTED_STUB, "segmented product call target")
    req(candidate_app[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL) + 4].hex() == "bfeac0fe", "segmented product call bytes")
    req(candidate_app[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL) + 4].hex() == "bfeaf838", "direct reload preserved")
    req(candidate_app[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL) + 4].hex() == "bfeade38", "segmented reload preserved")

    app_diffs = difference_offsets(official_app, candidate_app)
    req(len(app_diffs) == evidence["package"]["changed_app_byte_count_vs_official"], "app diff count vs evidence")
    req(package_manifest["changes"]["app_byte_count"] == len(app_diffs), "app diff count vs package manifest")
    req(package_manifest["changes"]["fwsc_byte_count"] == len(difference_offsets(official_raw, candidate_raw)), "FWSC diff count")
    req(package_manifest["protected_flash_hashes_before"] == package_manifest["protected_flash_hashes_after"], "protected flash hashes unchanged")

    rollback_manifest = read_json(HERE / "rollback/official-v15-recovery-sectors/manifest.json")
    req(rollback_manifest["format"] == FORMAT + ".official-v15-sector-rollback-v1", "rollback manifest format")
    req(rollback_manifest["rollback_restores_official_flash"] is True, "rollback manifest PASS")
    reconstructed = bytearray(candidate_flash)
    for item in rollback_manifest["changed_sectors"]:
        base = int(item["sector_base"], 16)
        data = (HERE / item["file"]).read_bytes()
        req(len(data) == item["size"] == rollback_manifest["sector_size"], f"rollback sector size {item['sector_base']}")
        req(sha(data) == item["sha256"], f"rollback sector hash {item['sector_base']}")
        reconstructed[base:base + len(data)] = data
    req(bytes(reconstructed) == bytes(official_flash), "rollback reconstructs official flash")
    req(sha(reconstructed) == rollback_manifest["official_flash_sha256"] == evidence["package"]["official_flash_sha256"], "rollback official flash hash")


def validate_inputs_and_packets() -> None:
    producer_manifest = read_json(HERE / "inputs/producer/evidence.json")
    req(producer_manifest["status"] == "PASS", "producer input PASS")
    req(producer_manifest["device_accessed"] is False and producer_manifest["midi_transport_opened"] is False and producer_manifest["flash_performed"] is False, "producer input offline")
    req(producer_manifest["source"]["commit"] == EXPECTED["commits"]["compact_producer"], "producer source commit")
    req(producer_manifest["source"]["evidence_sha256"] == EXPECTED["producer_source_evidence"], "producer source hash")
    req(sha_path(HERE / "inputs/producer/producer.bin") == EXPECTED["producer"], "producer input hash")

    packet_manifest = read_json(HERE / "inputs/packets/packet-manifest.json")
    permutation = read_json(HERE / "inputs/packets/physical-pad-permutation.json")
    sender_manifest = read_json(HERE / "inputs/packets/sender-manifest.json")
    req(packet_manifest["status"] == "PASS", "packet manifest PASS")
    req(packet_manifest["send_enabled"] is False and packet_manifest["device_accessed"] is False and packet_manifest["midi_transport_opened"] is False, "packet input offline")
    req(packet_manifest["source"]["commit"] == EXPECTED["commits"]["bank_d_packet_set"], "packet source commit")
    req(packet_manifest["source"]["manifest_sha256"] == EXPECTED["packet_source_manifest"], "packet source manifest hash")
    req(packet_manifest["order_basis"] == sender_manifest["order_basis"] == "note_order_36_51", "packet/sender note order")
    req(sender_manifest["send_enabled"] is False and sender_manifest["device_accessed"] is False, "sender manifest dry-run only")
    req(packet_manifest["physical_pad_permutation"]["ui_only"] is True and permutation["ui_only"] is True, "Pad permutation UI-only")
    req(packet_manifest["physical_pad_permutation"]["pad_1_to_16_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "packet manifest Pad permutation")
    req(permutation["pad_1_to_16_to_note_order_slot"] == EXPECTED_PAD_TO_SLOT, "Pad permutation file sequence")
    req("producer_order" in permutation["blocked_from"] and "packet_send_order" in permutation["blocked_from"], "Pad permutation blocked from producer/send order")
    for index, item in enumerate(packet_manifest["packets"]):
        req(item["order"] == index + 1 and item["slot"] == index and item["note"] == 36 + index, f"packet note order {index}")
        req(item["order_basis"] == "note_order_36_51", f"packet order basis {index}")
        req(item["sha256"] == EXPECTED["packet_hashes"][index], f"packet manifest hash {index}")
        packet = (HERE / "inputs/packets" / item["file"]).read_bytes()
        req(len(packet) == 163, f"packet length {index}")
        req(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing {index}")
        req(sha(packet) == item["sha256"], f"packet file hash {index}")


def validate_builder_check_inputs_is_non_destructive() -> None:
    evidence_before = sha_path(HERE / "evidence.json")
    sha_before = sha_path(HERE / "SHA256SUMS")
    result = run([sys.executable, "build_s1c3_16slot_functional.py", "check-inputs"])
    req("input gate: PASS" in result.stdout, "builder check-inputs PASS")
    req(sha_path(HERE / "evidence.json") == evidence_before, "check-inputs preserves release evidence")
    req(sha_path(HERE / "SHA256SUMS") == sha_before, "check-inputs preserves SHA inventory")


def validate_generated_tools_and_reject_paths() -> None:
    run([sys.executable, "dry_run_validate.py", "--json"])
    dry = json.loads(run([sys.executable, "dry_run_validate.py", "--json"]).stdout)
    req(dry["status"] == "DRY_RUN_PASS" and dry["send_enabled"] is False and dry["device_accessed"] is False, "dry-run validator PASS/offline")
    req(dry["packet_order_basis"] == "note_order_36_51" and dry["physical_pad_permutation_scope"] == "UI_ONLY", "dry-run order and Pad scope")

    with tempfile.TemporaryDirectory(prefix="s1c3-functional-validate-") as tmp_name:
        tmp = Path(tmp_name)
        pkg_config = subprocess.run(["pkg-config", "--cflags", "--libs", "libusb-1.0"], text=True, capture_output=True, check=False)
        req(pkg_config.returncode == 0, "pkg-config libusb-1.0 available for exact_ota check build")
        usb_flags = pkg_config.stdout.split()
        exact_ota = tmp / "exact_ota"
        sender = tmp / "exact_16_packet_sender"
        run([
            "cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
            "exact_ota.c",
            "../../../../../src/device_info.c",
            "../../../../../src/fwsc.c",
            "../../../../../src/protocol.c",
            "../../../../../src/sha256.c",
            "../../../../../src/usb_probe.c",
            "-o", str(exact_ota),
            *usb_flags,
        ])
        run([str(exact_ota), "check", PACKAGE_NAME])
        official_fwsc = HERE.parent / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
        reject = run([str(exact_ota), "check", str(official_fwsc)], expect=1)
        req("offline check rejected" in reject.stderr, "exact OTA rejects non-candidate hash")

        run([
            "cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
            "exact_16_packet_sender.c",
            "../../../../../src/sha256.c",
            "-o", str(sender),
        ])
        run([str(sender), "dry-run", "inputs/packets"])
        blocked = run([str(sender), "send", "inputs/packets", "--confirm", EXPECTED["sender_token"]], expect=2)
        req("send BLOCK" in blocked.stderr, "sender send path fail-closed in offline build")

        corrupt_dir = tmp / "corrupt-packets"
        corrupt_dir.mkdir()
        for packet in sorted((HERE / "inputs/packets").glob("slot*.bin")):
            shutil.copyfile(packet, corrupt_dir / packet.name)
        first = corrupt_dir / "slot00-note36-direct-product-163.bin"
        data = bytearray(first.read_bytes())
        data[10] ^= 0x01
        first.write_bytes(data)
        corrupt = run([str(sender), "dry-run", str(corrupt_dir)], expect=2)
        req("SHA-256 mismatch" in corrupt.stderr, "sender rejects corrupted packet")


def validate_sha_inventory() -> None:
    for line in (HERE / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        path = HERE / rel
        req(path.exists(), f"SHA256SUMS path exists: {rel}")
        req(sha_path(path) == digest, f"SHA256SUMS hash: {rel}")


def main() -> int:
    evidence, app_manifest, package_manifest = validate_release_manifests()
    validate_images_and_rollback(evidence, app_manifest, package_manifest)
    validate_inputs_and_packets()
    validate_builder_check_inputs_is_non_destructive()
    validate_generated_tools_and_reject_paths()
    validate_sha_inventory()
    print("S1-C3 16-slot functional release validation PASS")
    print(f"app_sha256={EXPECTED['app']}")
    print(f"package_sha256={EXPECTED['package']}")
    print(f"ota_confirmation_token={EXPECTED['ota_token']}")
    print(f"sender_confirmation_token={EXPECTED['sender_token']}")
    print("BLOCK device access, flash/upload, reset, MIDI transport, and live send during validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
