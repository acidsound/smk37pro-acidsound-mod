#!/usr/bin/env python3
"""Build and validate the official-v15-only H0 memory-boundary diagnostic.

H0 intentionally changes exactly two application bytes, both inside the two
six-byte memory-boundary instructions already identified in R03 analysis:

- BSS_SIZE_INSN  0x0200001e: c2ff48cb0300 -> c2ffeccb0300
- HEAP_BEGIN_INSN 0x0205e9f8: c5ff2065c401 -> c5ffc065c401

It leaves the code cave, Note On/Off hooks, product/SAVE calls, packer, UI, and
all other application bytes stock.  This is an offline diagnostic package
builder only.  It never accesses a device or flash transport.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from build_v15_r01_hand_drum import APP_SHA256, APP_SIZE, RUNTIME_BASE, off, replace_exact, sha256  # noqa: E402
from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_OFFSET,
    FLASH_SIZE,
    protected_hashes,
    Ufw,
    unpack_fwsc,
    AppImage,
    difference_offsets,
    compact_ranges,
)

FORMAT = "smk37-v15-h0-memory-boundary-only-v1"
DEFAULT_INPUT = ROOT / "build" / "SMK-37_Pro_015.fwsc"
DEFAULT_OUTPUT_DIR = ROOT / "build" / "SMK37Pro-v15-H0-memory-boundary-only"
PACKAGE_NAME = "SMK37Pro-v15-H0-memory-boundary-only.fwsc"

BSS_SIZE_INSN = 0x0200001E
BSS_SIZE_STOCK = bytes.fromhex("c2ff48cb0300")
BSS_SIZE_H0 = bytes.fromhex("c2ffeccb0300")
HEAP_BEGIN_INSN = 0x0205E9F8
HEAP_BEGIN_STOCK = bytes.fromhex("c5ff2065c401")
HEAP_BEGIN_H0 = bytes.fromhex("c5ffc065c401")

SECTOR_SIZE = 0x2000
PROTECTED_PREFIX_END = 0x4000


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def sector_base(offset: int) -> int:
    return offset - (offset % SECTOR_SIZE)


def sector_name(base: int) -> str:
    return f"stock-sector-{base:05x}.bin"


def extract_stock(input_fwsc: Path) -> tuple[bytes, bytearray, bytes]:
    raw = input_fwsc.read_bytes()
    payload, _metadata = unpack_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    if len(app) != APP_SIZE or sha256(app) != APP_SHA256:
        raise SystemExit("refusing non-official v15 app")
    return raw, flash, app


def build_app(app: bytes) -> tuple[bytes, dict[str, object]]:
    output = bytearray(app)
    changes: list[dict[str, object]] = []
    changes.append(replace_exact(output, app, BSS_SIZE_INSN, BSS_SIZE_STOCK, BSS_SIZE_H0))
    changes.append(replace_exact(output, app, HEAP_BEGIN_INSN, HEAP_BEGIN_STOCK, HEAP_BEGIN_H0))
    changed_offsets = difference_offsets(app, output)
    if changed_offsets != [off(BSS_SIZE_INSN) + 2, off(HEAP_BEGIN_INSN) + 2]:
        raise SystemExit(f"unexpected changed app offsets: {changed_offsets!r}")
    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline H0 diagnostic only; not a live functional success claim",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(output),
        "app_size": len(output),
        "changed_app_byte_count": len(changed_offsets),
        "changed_app_byte_offsets": [f"0x{item:05x}" for item in changed_offsets],
        "changes": changes,
        "stock_preserved": {
            "code_cave": "unchanged",
            "note_on_off_calls": "unchanged",
            "product_calls": "unchanged",
            "save_calls": "unchanged",
            "packer": "unchanged",
            "ui": "unchanged",
            "all_other_app_bytes": "unchanged",
        },
        "diagnostic_notice": "Only tests the memory-boundary hypothesis H0; it does not claim functional success.",
    }
    return bytes(output), manifest


def repack_with_existing_tool(input_fwsc: Path, app_path: Path, package_path: Path, manifest_path: Path) -> None:
    subprocess.run(
        [
            sys.executable,
            str(TOOLS / "smk37_v15_app_patch.py"),
            "repack-app",
            str(input_fwsc),
            str(app_path),
            str(package_path),
            "--manifest",
            str(manifest_path),
        ],
        check=True,
    )


def validate_and_rollback(
    stock_raw: bytes,
    stock_flash: bytes | bytearray,
    stock_app: bytes,
    h0_app: bytes,
    package_path: Path,
    output_dir: Path,
) -> dict[str, object]:
    h0_raw, h0_flash, extracted_h0_app = extract_stock_like_h0(package_path)
    if extracted_h0_app != h0_app:
        raise SystemExit("repacked package does not contain the requested H0 app")

    app_diffs = difference_offsets(stock_app, h0_app)
    flash_diffs = difference_offsets(stock_flash, h0_flash)
    raw_diffs = difference_offsets(stock_raw, h0_raw)
    expected_flash_offsets = sorted(APP_DATA_OFFSET + item for item in app_diffs)
    missing_app_flash_offsets = sorted(set(expected_flash_offsets) - set(flash_diffs))
    if missing_app_flash_offsets:
        raise SystemExit(f"missing expected app diff offsets in flash: {missing_app_flash_offsets!r}")
    metadata_flash_offsets = sorted(set(flash_diffs) - set(expected_flash_offsets))
    metadata_allowed_ranges = ((0x4000, 0x4100),)
    unexpected_metadata = [
        item for item in metadata_flash_offsets
        if not any(start <= item < end for start, end in metadata_allowed_ranges)
    ]
    if unexpected_metadata:
        raise SystemExit(f"unexpected non-app flash diff offsets: {unexpected_metadata!r}")
    if any(item < PROTECTED_PREFIX_END for item in flash_diffs):
        raise SystemExit("protected prefix gate failed: flash diff before 0x4000")
    sectors = sorted({sector_base(item) for item in flash_diffs})

    rollback_dir = output_dir / "rollback" / "recovery-sectors"
    rollback_dir.mkdir(parents=True, exist_ok=True)
    sector_entries = []
    for base in sectors:
        data = bytes(stock_flash[base : base + SECTOR_SIZE])
        path = rollback_dir / sector_name(base)
        path.write_bytes(data)
        sector_entries.append({
            "sector_base": f"0x{base:05x}",
            "size": len(data),
            "sha256": sha256(data),
            "file": str(path.relative_to(output_dir)),
        })

    reconstructed = bytearray(h0_flash)
    for base in sectors:
        reconstructed[base : base + SECTOR_SIZE] = stock_flash[base : base + SECTOR_SIZE]
    rollback_restores_stock_flash = bytes(reconstructed) == bytes(stock_flash)
    rollback_restores_changed_offsets = all(reconstructed[item] == stock_flash[item] for item in flash_diffs)
    if not rollback_restores_stock_flash:
        raise SystemExit("rollback sector replacement did not restore stock flash")

    manifest = {
        "format": FORMAT + ".rollback-v1",
        "scope": "changed sectors only, stock bytes from official v15 package",
        "sector_size": SECTOR_SIZE,
        "changed_sectors": sector_entries,
        "changed_sector_count": len(sector_entries),
        "rollback_restores_stock_flash": rollback_restores_stock_flash,
        "rollback_restores_changed_offsets": rollback_restores_changed_offsets,
        "stock_flash_sha256": sha256(stock_flash),
        "h0_flash_sha256": sha256(h0_flash),
        "reconstructed_flash_sha256": sha256(reconstructed),
    }
    write_json(rollback_dir / "manifest.json", manifest)

    return {
        "validation_gate": "PASS",
        "package_sha256": sha256(h0_raw),
        "package_size": len(h0_raw),
        "input_package_sha256": sha256(stock_raw),
        "app_sha256": sha256(h0_app),
        "flash_sha256": sha256(h0_flash),
        "changed_app_byte_count": len(app_diffs),
        "changed_app_ranges": compact_ranges(app_diffs),
        "changed_flash_byte_count": len(flash_diffs),
        "changed_flash_offsets": [f"0x{item:05x}" for item in flash_diffs],
        "expected_app_flash_offsets": [f"0x{item:05x}" for item in expected_flash_offsets],
        "repacker_metadata_flash_offsets": [f"0x{item:05x}" for item in metadata_flash_offsets],
        "changed_flash_sectors": [f"0x{item:05x}" for item in sectors],
        "changed_package_byte_count": len(raw_diffs),
        "changed_package_ranges": compact_ranges(raw_diffs),
        "protected_prefix_0x0000_0x3fff_unchanged": not any(item < PROTECTED_PREFIX_END for item in flash_diffs),
        "protected_hashes_stock": protected_hashes(bytearray(stock_flash)),
        "protected_hashes_h0": protected_hashes(bytearray(h0_flash)),
        "rollback_manifest": "rollback/recovery-sectors/manifest.json",
        "rollback_restores_stock_flash": rollback_restores_stock_flash,
        "rollback_restores_changed_offsets": rollback_restores_changed_offsets,
    }


def extract_stock_like_h0(path: Path) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    # The existing repacker only accepts official input, not modified packages, so use its lower-level parser.
    from smk37_v15_app_patch import FWSC_SLOTS, FWSC_BLOCK_SIZE, FWSC_DATA_SIZE  # noqa: E402
    metadata = bytes(raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for index in range(FWSC_SLOTS))
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])
    _ = metadata
    ufw = Ufw.parse(payload)
    flash = ufw.flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def build_once(input_fwsc: Path, output_dir: Path) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stock_raw, stock_flash, stock_app = extract_stock(input_fwsc)
    h0_app, app_manifest = build_app(stock_app)
    app_path = output_dir / "app.bin"
    package_path = output_dir / PACKAGE_NAME
    app_manifest_path = output_dir / "app-manifest.json"
    package_manifest_path = output_dir / "package-manifest.json"
    validation_path = output_dir / "validation.json"
    app_path.write_bytes(h0_app)
    write_json(app_manifest_path, app_manifest)
    repack_with_existing_tool(input_fwsc, app_path, package_path, package_manifest_path)
    validation = validate_and_rollback(stock_raw, stock_flash, stock_app, h0_app, package_path, output_dir)
    write_json(validation_path, validation)
    sums = {
        "app.bin": file_sha256(app_path),
        PACKAGE_NAME: file_sha256(package_path),
        "app-manifest.json": file_sha256(app_manifest_path),
        "package-manifest.json": file_sha256(package_manifest_path),
        "validation.json": file_sha256(validation_path),
        "rollback/recovery-sectors/manifest.json": file_sha256(output_dir / "rollback" / "recovery-sectors" / "manifest.json"),
    }
    for sector_file in sorted((output_dir / "rollback" / "recovery-sectors").glob("stock-sector-*.bin")):
        sums[str(sector_file.relative_to(output_dir))] = file_sha256(sector_file)
    (output_dir / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(sums.items())), encoding="utf-8")
    return validation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--determinism-check", action="store_true", help="build twice and require byte-identical outputs")
    args = parser.parse_args()

    validation = build_once(args.input, args.output_dir)
    if args.determinism_check:
        with tempfile.TemporaryDirectory(prefix="h0-determinism-") as tmp:
            tmp_dir = Path(tmp)
            validation_2 = build_once(args.input, tmp_dir)
            for rel in ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "validation.json", "rollback/recovery-sectors/manifest.json", "SHA256SUMS"]:
                if (args.output_dir / rel).read_bytes() != (tmp_dir / rel).read_bytes():
                    raise SystemExit(f"determinism check failed for {rel}")
            for path in (args.output_dir / "rollback" / "recovery-sectors").glob("stock-sector-*.bin"):
                rel = path.relative_to(args.output_dir)
                if path.read_bytes() != (tmp_dir / rel).read_bytes():
                    raise SystemExit(f"determinism check failed for {rel}")
            if validation != validation_2:
                raise SystemExit("determinism check failed for validation object")
    print(json.dumps(validation, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
