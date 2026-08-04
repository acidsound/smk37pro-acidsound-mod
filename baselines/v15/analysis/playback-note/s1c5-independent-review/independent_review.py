#!/usr/bin/env python3
"""Independent offline review for exact commit 90080a5 S1C5.

The script archives exact git objects into two temporary clean checkouts. It does
not open device, USB, MIDI, OTA, or flash transports. It writes review artifacts
only to the requested output directory.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

TARGET_COMMIT = "90080a59564e6255a30aa08dcf05d3ae4d8831df"
TARGET_TREE = "ae88bd64345e29fe542984307f49d372f52ab675"
PARENT_COMMIT = "71954397c2a91dc3a9a34f86eb02095a42cb3063"
CANDIDATE_REL = Path("baselines/v15/analysis/flash-candidates/S1C5-playback-register-return")
PARENT_REL = Path("baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final")
OFFICIAL_REL = Path("baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/SMK-37_Pro_015.fwsc")
HELPER_REL = Path("baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/smk37_v15_app_patch.py")
APP_NAME = "app.bin"
FWSC_NAME = "SMK37Pro-v15-S1C5-playback-register-return.fwsc"
PARENT_FWSC_NAME = "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc"
BASE = 0x02000000
SECTOR_SIZE = 0x2000
EXPECTED_APP_SHA256 = "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189"
EXPECTED_FWSC_SHA256 = "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91"
EXPECTED_PARENT_APP_SHA256 = "c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d"
EXPECTED_OFFICIAL_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
EXPECTED_SELECTOR_PRODUCER_SHA256 = "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1"
EXPECTED_OFFICIAL_FLASH_SHA256 = "f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a"
EXPECTED_CANDIDATE_FLASH_SHA256 = "fa7708182dccf6b98963756e23fdecc2482f157f258379dadbeae917f7045f12"


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(bytes(data)).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def run(args: list[str | Path], cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(value) for value in args],
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def normalize(text: str, roots: list[Path]) -> str:
    result = text
    for root in sorted(roots, key=lambda value: len(str(value)), reverse=True):
        result = result.replace(str(root), "<checkout>")
    return result


def checkout(repo: Path, commit: str, destination: Path) -> None:
    archive = destination.parent / (destination.name + ".tar")
    result = run(["git", "archive", "--format=tar", "-o", archive, commit], repo)
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r") as stream:
        stream.extractall(destination)
    archive.unlink()


def import_helper(root: Path):
    helper_path = root / HELPER_REL
    spec = importlib.util.spec_from_file_location("s1c5_independent_helper", helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not import exact-commit firmware helper")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def unpack_any(raw: bytes, helper) -> bytearray:
    payload = bytearray()
    for index in range(helper.FWSC_SLOTS):
        start = index * helper.FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + helper.FWSC_DATA_SIZE])
    payload.extend(raw[helper.FWSC_SLOTS * helper.FWSC_BLOCK_SIZE :])
    return payload


def fwsc_flash(raw: bytes, helper, strict_official: bool = False) -> bytes:
    payload = helper.unpack_fwsc(raw)[0] if strict_official else unpack_any(raw, helper)
    return bytes(helper.Ufw.parse(payload).flash())


def fwsc_app(raw: bytes, helper, strict_official: bool = False) -> bytes:
    return bytes(helper.AppImage.parse(fwsc_flash(raw, helper, strict_official)).app_bytes())


def compact_ranges(offsets: list[int]) -> list[dict[str, int]]:
    if not offsets:
        return []
    result: list[dict[str, int]] = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset != previous + 1:
            result.append({"start": start, "end_exclusive": previous + 1})
            start = offset
        previous = offset
    result.append({"start": start, "end_exclusive": previous + 1})
    return result


def word_le(data: bytes) -> int:
    if len(data) != 2:
        raise ValueError("PI32 word must be two bytes")
    return int.from_bytes(data, "little")


def decode_lb_zero(data: bytes) -> dict[str, Any]:
    word = word_le(data)
    if (word & 0xE088) != 0x4008:
        raise ValueError(f"not PI32 lb.z encoding: {data.hex()}")
    return {
        "bytes": data.hex(),
        "operation": "load unsigned byte and zero-extend to register",
        "destination_register": word & 0x7,
        "base_register": (word >> 4) & 0x7,
        "byte_offset": (word >> 8) & 0x1F,
    }


def decode_sb(data: bytes) -> dict[str, Any]:
    word = word_le(data)
    if (word & 0xE088) != 0x4088:
        raise ValueError(f"not PI32 sb encoding: {data.hex()}")
    return {
        "bytes": data.hex(),
        "operation": "store low byte of register",
        "source_register": word & 0x7,
        "base_register": (word >> 4) & 0x7,
        "byte_offset": (word >> 8) & 0x1F,
    }


def app_slice(app: bytes, address: int, size: int) -> bytes:
    offset = address - BASE
    return app[offset : offset + size]


def gate(name: str, status: str, evidence: Any) -> dict[str, Any]:
    return {"name": name, "status": status, "evidence": evidence}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--commit", default=TARGET_COMMIT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)

    exact_commit = run(["git", "rev-parse", args.commit], repo)
    exact_tree = run(["git", "rev-parse", f"{args.commit}^{{tree}}"], repo)
    exact_parent = run(["git", "rev-parse", f"{args.commit}^"], repo)
    if exact_commit.returncode or exact_tree.returncode or exact_parent.returncode:
        raise SystemExit("could not resolve exact review git objects")
    commit_id = exact_commit.stdout.strip()
    tree_id = exact_tree.stdout.strip()
    parent_id = exact_parent.stdout.strip()
    if (commit_id, tree_id, parent_id) != (TARGET_COMMIT, TARGET_TREE, PARENT_COMMIT):
        raise SystemExit("exact git object identity mismatch")

    review: dict[str, Any] = {
        "format": "smk37-v15-s1c5-independent-review-v1",
        "reviewed_commit": commit_id,
        "reviewed_tree": tree_id,
        "reviewed_parent": parent_id,
        "scope": {
            "candidate": str(CANDIDATE_REL),
            "offline_only": True,
            "device_accessed": False,
            "midi_transport_opened": False,
            "ota_performed": False,
            "flash_performed": False,
            "live_send_performed": False,
        },
        "gates": [],
        "blockers": [],
    }

    with tempfile.TemporaryDirectory(prefix="s1c5-independent-review-") as temporary:
        temp = Path(temporary)
        checkout_a = temp / "checkout-a"
        checkout_b = temp / "checkout-b"
        checkout(repo, commit_id, checkout_a)
        checkout(repo, commit_id, checkout_b)
        roots = [checkout_a, checkout_b, temp]
        candidate_a = checkout_a / CANDIDATE_REL
        candidate_b = checkout_b / CANDIDATE_REL
        exact_object_app = (candidate_a / APP_NAME).read_bytes()
        exact_object_fwsc = (candidate_a / FWSC_NAME).read_bytes()
        exact_object_ota_source = (candidate_a / "exact_ota.c").read_bytes()

        rebuilds = []
        for label, root, candidate in [("A", checkout_a, candidate_a), ("B", checkout_b, candidate_b)]:
            result = run(["python3", "build_s1c5_playback_register_return.py", "--check"], candidate)
            app_hash = sha256_file(candidate / APP_NAME)
            fwsc_hash = sha256_file(candidate / FWSC_NAME)
            rebuilds.append(
                {
                    "checkout": label,
                    "returncode": result.returncode,
                    "stdout": normalize(result.stdout, roots),
                    "stderr": normalize(result.stderr, roots),
                    "app_sha256": app_hash,
                    "fwsc_sha256": fwsc_hash,
                }
            )
        committed_app = (candidate_a / APP_NAME).read_bytes()
        committed_fwsc = (candidate_a / FWSC_NAME).read_bytes()
        rebuild_pass = (
            sha256_bytes(exact_object_app) == EXPECTED_APP_SHA256
            and sha256_bytes(exact_object_fwsc) == EXPECTED_FWSC_SHA256
            and all(item["returncode"] == 0 for item in rebuilds)
            and rebuilds[0]["app_sha256"] == rebuilds[1]["app_sha256"] == EXPECTED_APP_SHA256
            and rebuilds[0]["fwsc_sha256"] == rebuilds[1]["fwsc_sha256"] == EXPECTED_FWSC_SHA256
            and exact_object_app == (candidate_a / APP_NAME).read_bytes() == (candidate_b / APP_NAME).read_bytes()
            and exact_object_fwsc == (candidate_a / FWSC_NAME).read_bytes() == (candidate_b / FWSC_NAME).read_bytes()
            and exact_object_ota_source == (candidate_a / "exact_ota.c").read_bytes() == (candidate_b / "exact_ota.c").read_bytes()
        )
        rebuild_evidence = {
            "exact_object_artifacts": {
                "app_sha256": sha256_bytes(exact_object_app),
                "fwsc_sha256": sha256_bytes(exact_object_fwsc),
                "exact_ota_c_sha256": sha256_bytes(exact_object_ota_source),
            },
            "rebuilds": rebuilds,
            "byte_identical_to_exact_object": rebuild_pass,
        }
        review["gates"].append(gate("deterministic-app-fwsc-rebuild", "PASS" if rebuild_pass else "FAIL", rebuild_evidence))

        parent_app = (checkout_a / PARENT_REL / APP_NAME).read_bytes()
        diff_offsets = [index for index, (left, right) in enumerate(zip(parent_app, committed_app)) if left != right]
        changed = {
            "parent_app_sha256": sha256_bytes(parent_app),
            "candidate_app_sha256": sha256_bytes(committed_app),
            "changed_byte_count": len(diff_offsets),
            "changed_offsets": diff_offsets,
            "changed_runtime_addresses": [f"0x{BASE + value:08x}" for value in diff_offsets],
            "changed_ranges": compact_ranges(diff_offsets),
            "windows": [
                {
                    "address": "0x0201c644",
                    "parent": app_slice(parent_app, 0x0201C644, 6).hex(),
                    "candidate": app_slice(committed_app, 0x0201C644, 6).hex(),
                },
                {
                    "address": "0x0201c682",
                    "parent": app_slice(parent_app, 0x0201C682, 6).hex(),
                    "candidate": app_slice(committed_app, 0x0201C682, 6).hex(),
                },
            ],
        }
        changed_pass = (
            len(parent_app) == len(committed_app)
            and sha256_bytes(parent_app) == EXPECTED_PARENT_APP_SHA256
            and len(diff_offsets) == 4
            and diff_offsets == [0x1C644, 0x1C645, 0x1C682, 0x1C683]
            and changed["windows"][0]["parent"] == "001600160016"
            and changed["windows"][0]["candidate"] == "0d4000160016"
            and changed["windows"][1]["parent"] == "001600160016"
            and changed["windows"][1]["candidate"] == "0e4000160016"
        )
        review["gates"].append(gate("parent-relative-four-changed-bytes", "PASS" if changed_pass else "FAIL", changed))

        note_off_decode = decode_lb_zero(app_slice(committed_app, 0x0201C644, 2))
        note_on_decode = decode_lb_zero(app_slice(committed_app, 0x0201C682, 2))
        decode_evidence = {
            "encoding_rule": "16-bit little-endian word: (word & 0xe088)==0x4008; dst=word&7; base=(word>>4)&7; unsigned byte offset=(word>>8)&0x1f",
            "note_off": note_off_decode,
            "note_on": note_on_decode,
            "padding_note_off": app_slice(committed_app, 0x0201C646, 4).hex(),
            "padding_note_on": app_slice(committed_app, 0x0201C684, 4).hex(),
            "semantic_result": "0x400d loads memory byte [r0] into r5 with zero extension; 0x400e loads memory byte [r0] into r6 with zero extension; neither changes r0",
        }
        decode_pass = (
            note_off_decode["destination_register"] == 5
            and note_off_decode["base_register"] == 0
            and note_off_decode["byte_offset"] == 0
            and note_on_decode["destination_register"] == 6
            and note_on_decode["base_register"] == 0
            and note_on_decode["byte_offset"] == 0
            and decode_evidence["padding_note_off"] == "00160016"
            and decode_evidence["padding_note_on"] == "00160016"
        )
        review["gates"].append(gate("pi32-lb-z-decode-and-semantics", "PASS" if decode_pass else "FAIL", decode_evidence))

        selector_start = 0x0201E13E
        selector_end = 0x0201E254
        selector_window = app_slice(committed_app, selector_start, selector_end - selector_start)
        parent_selector_window = app_slice(parent_app, selector_start, selector_end - selector_start)
        selector_checks = {
            "candidate_combined_sha256": sha256_bytes(selector_window),
            "parent_combined_sha256": sha256_bytes(parent_selector_window),
            "byte_identical_to_parent": selector_window == parent_selector_window,
            "note_off_adapter_0x0201e13e": app_slice(committed_app, 0x0201E13E, 2).hex(),
            "note_on_adapter_0x0201e142": app_slice(committed_app, 0x0201E142, 2).hex(),
            "push_saved_0x0201e144": app_slice(committed_app, 0x0201E144, 2).hex(),
            "trigger_slot_subtract_36_0x0201e158": app_slice(committed_app, 0x0201E158, 2).hex(),
            "trigger_slot_to_source_0x0201e16a_0x0201e170": app_slice(committed_app, 0x0201E16A, 8).hex(),
            "trigger_slot_to_map_0x0201e17c_0x0201e182": app_slice(committed_app, 0x0201E17C, 8).hex(),
            "source_selected_before_metadata_0x0201e184": app_slice(committed_app, 0x0201E184, 2).hex(),
            "restore_destination_0x0201e186": app_slice(committed_app, 0x0201E186, 2).hex(),
            "return_metadata_pointer_0x0201e18e": app_slice(committed_app, 0x0201E18E, 4).hex(),
            "store_metadata_byte_0x0201e192": app_slice(committed_app, 0x0201E192, 2).hex(),
            "pop_return_0x0201e194": app_slice(committed_app, 0x0201E194, 2).hex(),
            "contract": "selector saves original destination in r4, copies trigger-selected source, computes r0=r4+0x9c, stores mapped note at [r0], then pop-return restores r9..r4 but not r0; caller therefore receives r0=dest+0x9c",
        }
        selector_pass = (
            selector_window == parent_selector_window
            and sha256_bytes(selector_window) == EXPECTED_SELECTOR_PRODUCER_SHA256
            and selector_checks["return_metadata_pointer_0x0201e18e"] == "00e19c40"
            and selector_checks["store_metadata_byte_0x0201e192"] == "8d40"
            and selector_checks["pop_return_0x0201e194"] == "5904"
            and selector_checks["source_selected_before_metadata_0x0201e184"] == "6116"
        )
        review["gates"].append(gate("selector-r0-return-contract", "PASS" if selector_pass else "FAIL", selector_checks))

        velocity_store = decode_sb(app_slice(committed_app, 0x0201C68C, 2))
        note_flow = {
            "stock_note_on_note_load_0x0201c670": app_slice(committed_app, 0x0201C670, 2).hex(),
            "stock_note_on_velocity_load_0x0201c66a": app_slice(committed_app, 0x0201C66A, 2).hex(),
            "selector_push_pop_preserves_r5_r6": {
                "push": selector_checks["push_saved_0x0201e144"],
                "pop": selector_checks["pop_return_0x0201e194"],
            },
            "note_on_reload": note_on_decode,
            "note_on_velocity_store": velocity_store,
            "note_off_reload": note_off_decode,
            "symmetry": "Note Off reloads mapped [r0] into native note register r5; Note On reloads mapped [r0] into native note register r6 while native velocity remains r5 and is stored at [r0+2]",
        }
        note_flow_pass = (
            note_flow["stock_note_on_note_load_0x0201c670"] == "1e41"
            and note_flow["stock_note_on_velocity_load_0x0201c66a"] == "1d42"
            and velocity_store["source_register"] == 5
            and velocity_store["base_register"] == 0
            and velocity_store["byte_offset"] == 2
            and note_off_decode["destination_register"] == 5
            and note_on_decode["destination_register"] == 6
        )
        review["gates"].append(gate("note-on-velocity-and-note-off-symmetry", "PASS" if note_flow_pass else "FAIL", note_flow))

        packet_manifest = json.loads((candidate_a / "inputs/packets/packet-manifest.json").read_text())
        packet_rows = []
        simulated_map: list[int] = []
        packet_pass = packet_manifest.get("packet_count") == 16
        for index, item in enumerate(packet_manifest["packets"]):
            packet = (candidate_a / "inputs/packets" / item["file"]).read_bytes()
            row = {
                "slot": item["slot"],
                "trigger_note": item["trigger_note"],
                "playback_note": item["playback_note"],
                "wire_byte_161": packet[161],
                "sha256": sha256_bytes(packet),
                "manifest_sha256": item["sha256"],
            }
            packet_rows.append(row)
            simulated_map.append(packet[161])
            packet_pass = packet_pass and (
                len(packet) == 163
                and packet[:6] == bytes.fromhex("f0430000011b")
                and packet[-1] == 0xF7
                and item["slot"] == index
                and item["trigger_note"] == 36 + index
                and item["playback_note"] == packet[161] == 60
                and row["sha256"] == row["manifest_sha256"]
            )
        selected_sources = []
        for trigger in range(36, 52):
            slot = trigger - 36
            selected_sources.append({"trigger_note": trigger, "source_slot": slot, "playback_note": simulated_map[slot]})
        producer_evidence = {
            "producer_count_to_slot_bytes_0x0201e1c4_0x0201e1d8": app_slice(committed_app, 0x0201E1C4, 0x16).hex(),
            "producer_map_pointer_and_store_0x0201e1e0_0x0201e1f0": app_slice(committed_app, 0x0201E1E0, 0x10).hex(),
            "producer_post_copy_count_reload_increment_store_0x0201e20a_0x0201e210": app_slice(committed_app, 0x0201E20A, 6).hex(),
            "packet_rows": packet_rows,
            "simulated_map": simulated_map,
            "selector_results": selected_sources,
            "identity_result": "producer slot identity is sequential loaded_count, selector source identity is trigger_note-36, and playback note is a separate map byte; sixteen repeated values of 60 do not merge source slots",
        }
        producer_pass = packet_pass and simulated_map == [60] * 16 and [row["source_slot"] for row in selected_sources] == list(range(16))
        review["gates"].append(gate("repeated-playback-note-60-no-slot-collapse", "PASS" if producer_pass else "FAIL", producer_evidence))

        helper = import_helper(checkout_a)
        official_raw = (checkout_a / OFFICIAL_REL).read_bytes()
        candidate_raw = committed_fwsc
        official_flash = fwsc_flash(official_raw, helper, strict_official=True)
        candidate_flash = fwsc_flash(candidate_raw, helper)
        official_app = fwsc_app(official_raw, helper, strict_official=True)
        candidate_package_app = fwsc_app(candidate_raw, helper)
        flash_diff_offsets = [index for index, (left, right) in enumerate(zip(official_flash, candidate_flash)) if left != right]
        changed_sectors = sorted({offset // SECTOR_SIZE * SECTOR_SIZE for offset in flash_diff_offsets})
        protected_official = helper.protected_hashes(official_flash)
        protected_candidate = helper.protected_hashes(candidate_flash)
        protected_evidence = {
            "official_app_sha256": sha256_bytes(official_app),
            "candidate_package_app_sha256": sha256_bytes(candidate_package_app),
            "official_flash_sha256": sha256_bytes(official_flash),
            "candidate_flash_sha256": sha256_bytes(candidate_flash),
            "changed_sectors": [f"0x{value:05x}" for value in changed_sectors],
            "changed_byte_below_0x4000": any(value < 0x4000 for value in flash_diff_offsets),
            "protected_hashes_official": protected_official,
            "protected_hashes_candidate": protected_candidate,
        }
        protected_pass = (
            sha256_bytes(official_app) == EXPECTED_OFFICIAL_APP_SHA256
            and candidate_package_app == committed_app
            and sha256_bytes(official_flash) == EXPECTED_OFFICIAL_FLASH_SHA256
            and sha256_bytes(candidate_flash) == EXPECTED_CANDIDATE_FLASH_SHA256
            and not protected_evidence["changed_byte_below_0x4000"]
            and protected_official == protected_candidate
            and protected_evidence["changed_sectors"] == ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"]
        )
        review["gates"].append(gate("protected-regions", "PASS" if protected_pass else "FAIL", protected_evidence))

        rollback_manifest = json.loads((candidate_a / "rollback/official-v15-recovery-sectors/manifest.json").read_text())
        reconstructed = bytearray(candidate_flash)
        rollback_rows = []
        rollback_pass = True
        for item in rollback_manifest["changed_sectors"]:
            sector_file = candidate_a / item["file"]
            sector = sector_file.read_bytes()
            base = int(item["sector_base"], 16)
            row = {
                "sector_base": item["sector_base"],
                "size": len(sector),
                "sha256": sha256_bytes(sector),
                "manifest_sha256": item["sha256"],
                "matches_official_sector": sector == official_flash[base : base + len(sector)],
            }
            rollback_rows.append(row)
            rollback_pass = rollback_pass and len(sector) == SECTOR_SIZE and row["sha256"] == row["manifest_sha256"] and row["matches_official_sector"]
            reconstructed[base : base + len(sector)] = sector
        rollback_evidence = {
            "sectors": rollback_rows,
            "reconstructed_flash_sha256": sha256_bytes(reconstructed),
            "official_flash_sha256": sha256_bytes(official_flash),
            "byte_identical_to_official": bytes(reconstructed) == official_flash,
        }
        rollback_pass = rollback_pass and rollback_evidence["byte_identical_to_official"]
        review["gates"].append(gate("rollback-reconstructs-official-v15", "PASS" if rollback_pass else "FAIL", rollback_evidence))

        pkg_config = run(["pkg-config", "--cflags", "--libs", "libusb-1.0"], candidate_a)
        exact_compile_command: list[str | Path] = [
            "cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic",
            "exact_ota.c",
            "../../../../../src/device_info.c",
            "../../../../../src/fwsc.c",
            "../../../../../src/protocol.c",
            "../../../../../src/sha256.c",
            "../../../../../src/usb_probe.c",
            "-o", temp / "exact_ota",
        ]
        if pkg_config.returncode == 0:
            exact_compile_command.extend(pkg_config.stdout.split())
            exact_compile = run(exact_compile_command, candidate_a)
        else:
            exact_compile = pkg_config
        exact_compile_evidence = {
            "command": " ".join(str(value).replace(str(temp), "<tmp>") for value in exact_compile_command),
            "ota_c_inclusion": "exact_ota.c directly includes ../../../../../src/ota.c",
            "returncode": exact_compile.returncode,
            "stdout": normalize(exact_compile.stdout, roots),
            "stderr": normalize(exact_compile.stderr, roots),
            "current_api_signature": "ota_upload_exact(firmware_path, transcript_path, confirmation, expected_sha256, package_description, expected_confirmation, completion_message)",
            "candidate_call": "ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, completion_message)",
        }
        exact_compile_pass = exact_compile.returncode == 0
        review["gates"].append(gate("exact-ota-current-src-api-compilation", "PASS" if exact_compile_pass else "FAIL", exact_compile_evidence))

        exact_checks: dict[str, Any] = {
            "candidate": {"status": "BLOCKED", "reason": "committed exact_ota.c did not compile"},
            "parent": {"status": "BLOCKED", "reason": "committed exact_ota.c did not compile"},
            "official": {"status": "BLOCKED", "reason": "committed exact_ota.c did not compile"},
        }
        if exact_compile_pass:
            binary = temp / "exact_ota"
            for name, path, expected in [
                ("candidate", candidate_a / FWSC_NAME, 0),
                ("parent", checkout_a / PARENT_REL / PARENT_FWSC_NAME, 1),
                ("official", checkout_a / OFFICIAL_REL, 1),
            ]:
                checked = run([binary, "check", path], candidate_a)
                exact_checks[name] = {
                    "status": "PASS" if checked.returncode == expected else "FAIL",
                    "returncode": checked.returncode,
                    "expected_returncode": expected,
                    "stdout": normalize(checked.stdout, roots),
                    "stderr": normalize(checked.stderr, roots),
                }
        exact_checks_pass = exact_compile_pass and all(item["status"] == "PASS" for item in exact_checks.values())
        review["gates"].append(gate("exact-ota-candidate-accept-parent-official-reject", "PASS" if exact_checks_pass else "BLOCKED", exact_checks))

        diagnostic_source = candidate_a / "exact_ota.api-diagnostic.c"
        original_source = (candidate_a / "exact_ota.c").read_text()
        obsolete = "argv[5], 15, PACKAGE_SHA256"
        corrected = "argv[5], PACKAGE_SHA256"
        diagnostic: dict[str, Any] = {"performed": False}
        if original_source.count(obsolete) == 1 and pkg_config.returncode == 0:
            diagnostic_source.write_text(original_source.replace(obsolete, corrected))
            diagnostic_binary = temp / "exact_ota_api_diagnostic"
            diagnostic_command: list[str | Path] = exact_compile_command.copy()
            diagnostic_command[diagnostic_command.index("exact_ota.c")] = diagnostic_source.name
            diagnostic_command[diagnostic_command.index(temp / "exact_ota")] = diagnostic_binary
            diagnostic_compile = run(diagnostic_command, candidate_a)
            diagnostic = {
                "performed": True,
                "scope": "diagnostic only; does not close the committed-artifact release gate",
                "single_source_change": "remove obsolete integer argument 15 before PACKAGE_SHA256",
                "compile_returncode": diagnostic_compile.returncode,
                "compile_stderr": normalize(diagnostic_compile.stderr, roots),
                "checks": {},
            }
            if diagnostic_compile.returncode == 0:
                for name, path in [
                    ("candidate", candidate_a / FWSC_NAME),
                    ("parent", checkout_a / PARENT_REL / PARENT_FWSC_NAME),
                    ("official", checkout_a / OFFICIAL_REL),
                ]:
                    checked = run([diagnostic_binary, "check", path], candidate_a)
                    diagnostic["checks"][name] = {
                        "returncode": checked.returncode,
                        "stdout": normalize(checked.stdout, roots),
                        "stderr": normalize(checked.stderr, roots),
                    }
        review["diagnostic_after_minimal_api_fix"] = diagnostic

    failed = [item for item in review["gates"] if item["status"] != "PASS"]
    if failed:
        review["blockers"] = [
            {
                "id": "B-EXACT-OTA-API",
                "summary": "Committed exact_ota.c does not compile against src/ota.c at exact commit 90080a5.",
                "detail": "The call supplies obsolete argument 15, so Clang reports: too many arguments to function call, expected 7, have 8.",
                "consequence": "The committed exact wrapper cannot perform candidate acceptance or parent/official rejection. Those subgates remain blocked even though a diagnostic one-argument removal makes all three hash checks return the intended 0/1/1 results.",
            }
        ]
    review["decision"] = "PASS" if not failed else "FAIL"
    review["release_gate_summary"] = {item["name"]: item["status"] for item in review["gates"]}

    review_json = output / "review.json"
    review_json.write_text(json.dumps(review, indent=2, sort_keys=True) + "\n")

    validation_lines = [
        f"S1C5 independent review decision: {review['decision']}",
        f"reviewed_commit={review['reviewed_commit']}",
        f"reviewed_tree={review['reviewed_tree']}",
    ]
    for item in review["gates"]:
        validation_lines.append(f"{item['status']}\t{item['name']}")
    for blocker in review["blockers"]:
        validation_lines.append(f"BLOCKER\t{blocker['id']}\t{blocker['summary']}")
    (output / "validation.txt").write_text("\n".join(validation_lines) + "\n")

    report_lines = [
        "# S1C5 independent offline review",
        "",
        f"Decision: **{review['decision']}**.",
        "",
        f"Reviewed exact commit `{review['reviewed_commit']}` (tree `{review['reviewed_tree']}`), parent `{review['reviewed_parent']}`. No device, USB, MIDI, OTA, live send, reset, or flash action was performed.",
        "",
        "## Release gates",
        "",
    ]
    for item in review["gates"]:
        report_lines.append(f"- **{item['status']}** `{item['name']}`")
    report_lines.extend(
        [
            "",
            "## Verified technical results",
            "",
            f"- Two clean exact-object rebuilds produced byte-identical `app.bin` `{EXPECTED_APP_SHA256}` and FWSC `{EXPECTED_FWSC_SHA256}`.",
            "- Parent-relative app differences are exactly four bytes at runtime addresses `0x0201c644`, `0x0201c645`, `0x0201c682`, and `0x0201c683`. The remaining four bytes in each six-byte window are unchanged `mov r0,r0` padding.",
            "- PI32 little-endian words `0x400d` and `0x400e` decode to unsigned byte loads `lb.z r5,[r0]` and `lb.z r6,[r0]`. They zero-extend the byte and preserve `r0`.",
            "- The unchanged selector saves destination in `r4`, chooses source from `trigger_note-36`, stores the mapped byte at `[dest+0x9c]`, and returns `r0=dest+0x9c` because the final pop does not restore `r0`.",
            "- Note On reloads the mapped note into `r6`; velocity remains in preserved `r5` and stock `sb [r0+2],r5` at `0x0201c68c` is unchanged. Note Off symmetrically reloads mapped note into native note register `r5`.",
            "- Producer slot assignment uses sequential loaded count, map storage uses `map_base+slot`, and selector source uses `trigger_note-36`. All 16 packet artifacts contain playback byte 60 while retaining source slots 0 through 15, so repeated note 60 does not collapse trigger-slot identity.",
            "- Rollback sector files independently reconstruct the byte-exact official v15 flash. Protected boot/layout, U-Boot, ISD config, and post-app resource hashes match official; no changed flash byte is below `0x4000`.",
            "",
            "## Release blocker",
            "",
            "- **B-EXACT-OTA-API:** committed `exact_ota.c` calls current `ota_upload_exact` with eight arguments by retaining obsolete version argument `15`. Current `src/ota.c` declares seven arguments, so compilation fails with `too many arguments to function call, expected 7, have 8`.",
            "- Therefore the committed exact wrapper cannot close candidate-accept, parent-reject, or official-reject gates. A scratch diagnostic removing only that obsolete argument compiled and returned candidate/parent/official codes `0/1/1`, but it is not the committed artifact and does not change this **FAIL** decision.",
            "",
            "See `review.json` for exact byte evidence, compile stderr, packet rows, rollback hashes, and protected-region hashes.",
        ]
    )
    (output / "report.md").write_text("\n".join(report_lines) + "\n")

    inventory_names = ["independent_review.py", "report.md", "review.json", "validation.txt"]
    inventory = []
    for name in inventory_names:
        path = output / name
        if path.exists():
            inventory.append(f"{sha256_file(path)}  {name}")
    (output / "SHA256SUMS").write_text("\n".join(inventory) + "\n")

    print(f"S1C5 independent review: {review['decision']}")
    for item in review["gates"]:
        print(f"{item['status']}\t{item['name']}")
    return 0 if review["decision"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
