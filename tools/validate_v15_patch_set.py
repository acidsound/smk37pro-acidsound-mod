#!/usr/bin/env python3
"""Validate the official-v15 host-side 16-pad patch-set compiler."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DUMP = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin"
CATALOG = ROOT / "baselines/v15/analysis/patch-set-ui/catalog/factory-voices.json"
CONFIG = ROOT / "baselines/v15/analysis/patch-set-ui/examples/bank-d-01-16/config.json"
BUILDER = ROOT / "tools/build_v15_patch_set.py"
EXPECTED_DUMP_SHA = "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b"
EXPECTED_MOOGER_RUNTIME_SHA = "e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275"
EXPECTED_RUNTIME_IMAGE_SHA = "fdf7ebdf911041de64ebd80c3d807959b29034ef4e2fed35245b2dfe7b032270"
EXPECTED_PACKET_STREAM_SHA = "5454832b5b97cd8773efe23aa0ba343ae14639d7a38584c43fb2f74d4c9e6939"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def run_build(output: Path) -> None:
    subprocess.run([
        sys.executable,
        str(BUILDER),
        "build",
        str(DUMP),
        str(CONFIG),
        str(output),
    ], check=True, cwd=ROOT)


def main() -> int:
    require(digest(DUMP) == EXPECTED_DUMP_SHA, "official v15 clean dump SHA")
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    config = json.loads(CONFIG.read_text(encoding="utf-8"))
    require(catalog["format"] == "smk37-v15-factory-voice-catalog-v1", "catalog format")
    require(catalog["voice_count"] == 128 and len(catalog["voices"]) == 128, "catalog voice count")
    require(config["format"] == "smk37-v15-pad-patch-set-v1", "config format")
    require(len(config["slots"]) == 16, "example slot count")
    require(sorted(slot["note"] for slot in config["slots"]) == list(range(36, 52)),
            "exact note coverage")
    require(all(slot["bank"] == 4 and slot["patch"] == index + 1
                for index, slot in enumerate(sorted(config["slots"], key=lambda item: item["note"]))),
            "1-based Bank D patch 1..16 mapping")

    voices = {(voice["bank"], voice["patch"]): voice for voice in catalog["voices"]}
    require(voices[(4, 1)]["name"] == "BUZZ BASS", "Bank D patch 1 identity")
    require(voices[(4, 12)]["name"] == "HAND DRUM", "Bank D patch 12 identity")
    require(voices[(4, 14)]["name"] == "Mooger #1", "Bank D patch 14 identity")
    require(voices[(4, 14)]["runtime_sha256"] == EXPECTED_MOOGER_RUNTIME_SHA,
            "Mooger #1 runtime SHA")

    with tempfile.TemporaryDirectory(prefix="smk37-v15-patch-set-a-") as first_name, \
         tempfile.TemporaryDirectory(prefix="smk37-v15-patch-set-b-") as second_name:
        first = Path(first_name)
        second = Path(second_name)
        run_build(first)
        run_build(second)
        first_files = sorted(path.relative_to(first) for path in first.iterdir() if path.is_file())
        second_files = sorted(path.relative_to(second) for path in second.iterdir() if path.is_file())
        require(first_files == second_files, "deterministic file list")
        for relative in first_files:
            require((first / relative).read_bytes() == (second / relative).read_bytes(),
                    f"deterministic artifact {relative}")

        manifest = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
        require(len(manifest["slots"]) == 16, "manifest slot count")
        require([slot["slot"] for slot in manifest["slots"]] == list(range(16)), "slot indices")
        require([slot["note"] for slot in manifest["slots"]] == list(range(36, 52)), "slot notes")
        require((first / "runtime-slots.bin").stat().st_size == 0xA00, "runtime image size")
        require((first / "sequential-product-packets.syx").stat().st_size == 16 * 163,
                "packet stream size")
        require(digest(first / "runtime-slots.bin") == EXPECTED_RUNTIME_IMAGE_SHA,
                "runtime image SHA")
        require(digest(first / "sequential-product-packets.syx") == EXPECTED_PACKET_STREAM_SHA,
                "packet stream SHA")
        for slot in manifest["slots"]:
            packet = (first / slot["packet_file"]).read_bytes()
            require(len(packet) == 163, f"slot {slot['slot']} packet length")
            require(packet[:6] == bytes.fromhex("f0430000011b") and packet[-1] == 0xF7,
                    f"slot {slot['slot']} packet framing")

    print("v15 patch-set compiler and catalog: PASS")
    print("offline only; no firmware modification or device access")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
