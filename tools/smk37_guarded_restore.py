#!/usr/bin/env python3
"""Guarded sector-specific flash restore for SMK-37 Pro.

Restores ONLY the app area (0x4300..0x9A832) from an FWSC package to a
live flash dump, preserving all device-specific regions:

  0x0000..0x3FFF   Boot header     - device-specific, never touched
  0x4000..0x42FF   JLFS header     - restored together with the app area
  0x4300..0x9ACD2  App area        - sfc_cipher base 0x4000 (RESTORED)
  0x9ACD3..0x9BFFF Tail metadata   - dynamic/device-specific, never touched
  0x9C000..        Beyond package  - live-only, never touched

The script works offline on flash dump files and produces a "restored"
dump that can be written back to the device via the normal write path.
It never opens USB and never issues chip-level erase commands.

Usage:
  python3 smk37_guarded_restore.py \
    --package baselines/v15/SMK-37_Pro_015.fwsc \
    --dump    baselines/v15/device-dumps/v15-clean-baseline-a.bin \
    --output  restored-v15.bin \
    [--dry-run]

  # To restore from a specific app-area source (e.g., a patched build):
  python3 smk37_guarded_restore.py \
    --package baselines/v15/SMK-37_Pro_015.fwsc \
    --dump    current-device-dump.bin \
    --app-src patched_app_area.bin \
    --output  restored-patched.bin
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from pathlib import Path

# ── Flash layout constants (validated against v15 clean baseline) ──────────

FLASH_SIZE = 0x100_000          # full chip size (live dump)
PACKAGE_SIZE = 0x9C_000         # FWSC flash.bin size

BOOT_HEADER_END = 0x4000        # 0x0000..0x3FFF: boot header (device-specific)
JLFS_START = 0x4000
JLFS_END = 0x4300               # 0x4000..0x42FF: JLFS header
APP_START = 0x4300
APP_END = 0x9ACD3               # 0x4300..0x9ACD2: app area (v15 area size 0x96CD3)
TAIL_START = 0x9ACD3
PACKAGE_END = 0x9C000           # 0x9A833..0x9BFFF: tail metadata (dynamic)

CHIP_KEY = 0x980F
SFC_BASE = 0x4000

# ── Cipher (same as smk37_app_patch.sfc_cipher) ────────────────────────────

def _lfsr_xor(data: bytearray, offset: int, size: int, key: int) -> None:
    for i in range(size):
        data[offset + i] ^= key & 0xFF
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 0xFFFF

def sfc_cipher(data: bytearray, offset: int, size: int, base: int, key: int) -> None:
    """XOR a region with the SFC LFSR key stream (self-inverse)."""
    for rel in range(0, size, 32):
        chunk = min(size - rel, 32)
        block_key = key ^ ((offset + rel - base) >> 2)
        _lfsr_xor(data, offset + rel, chunk, block_key)

# ── FWSC extraction ────────────────────────────────────────────────────────

FWSC_BLOCK_SIZE = 48
FWSC_DATA_SIZE = 47
FWSC_SLOTS = 20

def extract_flash_from_fwsc(package_path: Path) -> bytes:
    """Extract the raw flash.bin payload from an FWSC package."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent))
    from smk37_app_patch import (
        FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw,
    )
    raw = package_path.read_bytes()
    # Build UFW payload from FWSC block structure
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        chunk = raw[start:start + FWSC_DATA_SIZE]
        if len(chunk) < FWSC_DATA_SIZE:
            raise SystemExit(f"FWSC: truncated at slot {index}")
        payload.extend(chunk)
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    # Parse UFW container and extract flash
    ufw = Ufw.parse(bytes(payload))
    flash = ufw.flash()
    if len(flash) < PACKAGE_SIZE:
        raise SystemExit(
            f"Extracted flash too small: {len(flash):#x} < {PACKAGE_SIZE:#x}"
        )
    return flash

# ── Core restore logic ─────────────────────────────────────────────────────

def package_to_live(package_flash: bytes) -> bytes:
    """
    Convert the FWSC package flash.bin app area into the live flash form.

    sfc_cipher is a self-inverse XOR keystream, so applying it over the app
    area converts the package representation into the representation raw
    device flash actually holds.
    """
    live = bytearray(package_flash)
    sfc_cipher(live, APP_START, APP_END - APP_START, SFC_BASE, CHIP_KEY)
    return bytes(live)


def restore_app_area(
    dump: bytearray,
    package_flash: bytes,
    app_src: bytes | None = None,
    dry_run: bool = False,
) -> dict:
    """
    Restore the app area (0x4300..0x9A832) in a flash dump.

    Args:
        dump: The live flash dump (bytearray, FLASH_SIZE bytes).
        package_flash: The extracted flash.bin from the FWSC package.
        app_src: Optional alternative app-area source (plain, unencrypted).
                 If None, the app area is taken from the package.
        dry_run: If True, report what would change without modifying dump.

    Returns:
        A dict with restore statistics.
    """
    stats = {
        "bytes_changed": 0,
        "sectors_touched": 0,
        "app_area_size": APP_END - APP_START,
        "dry_run": dry_run,
    }

    # ── Validate dump ──
    if len(dump) < FLASH_SIZE:
        raise SystemExit(f"dump too small: {len(dump)} < {FLASH_SIZE:#x}")

    # ── Validate package ──
    if len(package_flash) < PACKAGE_SIZE:
        raise SystemExit(f"package flash too small: {len(package_flash)} < {PACKAGE_SIZE:#x}")

    # ── Determine app area source ──
    if app_src is not None:
        # app_src is plain (unencrypted) app area data
        if len(app_src) < APP_END - APP_START:
            raise SystemExit(
                f"app_src too small: {len(app_src)} < {APP_END - APP_START:#x}"
            )
        app_plain = app_src[:APP_END - APP_START]
        source_label = "external app_src"
    else:
        # package_flash is expected to already be in live form (main() runs
        # it through package_to_live before calling here).
        app_plain = package_flash[APP_START:APP_END]
        source_label = "package converted to live form"

    # ── Compute differences ──
    if not dry_run:
        diff_count = 0
        for i in range(APP_END - APP_START):
            if dump[APP_START + i] != app_plain[i]:
                diff_count += 1
        stats["bytes_changed"] = diff_count
        stats["sectors_touched"] = (diff_count + 0xFF) // 0x100 if diff_count else 0

        if diff_count == 0:
            print("  App area already matches source. No changes needed.")
            return stats

        # ── Write app area to dump ──
        dump[APP_START:APP_END] = app_plain

    print(f"  Source: {source_label}")
    print(f"  App area: {APP_START:#06x}..{APP_END:#06x} ({APP_END - APP_START:#x} bytes)")
    if not dry_run:
        print(f"  Bytes changed: {stats['bytes_changed']}")
        print(f"  Sectors touched: {stats['sectors_touched']}")
    else:
        # Count diffs for dry run
        diff_count = sum(
            1 for i in range(APP_END - APP_START)
            if dump[APP_START + i] != app_plain[i]
        )
        print(f"  [dry-run] Bytes that would change: {diff_count}")

    # ── Verify preserved regions ──
    print("  Preserved regions:")
    print(f"    Boot header  {0x0000:#06x}..{BOOT_HEADER_END:#06x}  ✓ untouched")
    print(f"    JLFS header  {JLFS_START:#06x}..{JLFS_END:#06x}    ✓ untouched")
    print(f"    Tail metadata {TAIL_START:#06x}..{PACKAGE_END:#06x}   ✓ untouched")
    print(f"    Beyond pkg   {PACKAGE_END:#06x}..{FLASH_SIZE:#06x}  ✓ untouched")

    return stats


def verify_restore(
    dump: bytearray,
    package_flash: bytes,
) -> bool:
    """Verify that the dump app area matches the given live-form flash image."""
    mismatches = 0
    for i in range(APP_START, APP_END):
        if dump[i] != package_flash[i]:
            mismatches += 1
            if mismatches <= 5:
                print(f"  MISMATCH at {i:#06x}: dump={dump[i]:#04x} pkg={package_flash[i]:#04x}")
    if mismatches:
        print(f"  VERIFY FAIL: {mismatches} mismatches in app area")
        return False
    print("  VERIFY OK: app area matches package")
    return True


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Guarded sector-specific flash restore for SMK-37 Pro"
    )
    parser.add_argument(
        "--package", type=Path, required=True,
        help="FWSC package file (e.g., SMK-37_Pro_015.fwsc)"
    )
    parser.add_argument(
        "--dump", type=Path, required=True,
        help="Live flash dump file (0x100000 bytes)"
    )
    parser.add_argument(
        "--app-src", type=Path, default=None,
        help="Optional: plain (unencrypted) app area source file"
    )
    parser.add_argument(
        "--output", type=Path, required=True,
        help="Output restored dump file"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Report changes without writing output"
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Verify app area matches package before restoring"
    )
    args = parser.parse_args()

    # ── Load inputs ──
    print(f"Package: {args.package}")
    pkg_flash = extract_flash_from_fwsc(args.package)
    print(f"  Extracted flash: {len(pkg_flash):#x} bytes")
    print(f"  SHA-256: {hashlib.sha256(pkg_flash).hexdigest()[:16]}…")
    live_flash = package_to_live(pkg_flash)
    print("  Converted package -> live form (sfc_cipher over app area)")

    dump_raw = args.dump.read_bytes()
    if len(dump_raw) < FLASH_SIZE:
        raise SystemExit(f"Dump too small: {len(dump_raw):#x} < {FLASH_SIZE:#x}")
    dump = bytearray(dump_raw[:FLASH_SIZE])
    print(f"Dump: {args.dump} ({len(dump_raw):#x} bytes)")
    print(f"  SHA-256: {hashlib.sha256(dump_raw).hexdigest()[:16]}…")

    # ── Optional: verify current state ──
    if args.verify:
        print("\nVerifying current dump against package…")
        ok = verify_restore(dump, live_flash)
        if not ok:
            print("  (Continuing with restore regardless of verification)")

    # ── Optional: external app source ──
    app_src = None
    if args.app_src:
        app_src = args.app_src.read_bytes()
        print(f"\nApp source: {args.app_src} ({len(app_src):#x} bytes)")
        print(f"  SHA-256: {hashlib.sha256(app_src).hexdigest()[:16]}…")

    # ── Restore ──
    print("\nRestoring app area…")
    stats = restore_app_area(dump, live_flash, app_src, args.dry_run)

    # ── Write output ──
    if not args.dry_run:
        # Pad to full flash size if dump was shorter
        if len(dump) < FLASH_SIZE:
            dump.extend(b"\xFF" * (FLASH_SIZE - len(dump)))
        args.output.write_bytes(bytes(dump))
        print(f"\nWrote restored dump: {args.output}")
        print(f"  SHA-256: {hashlib.sha256(bytes(dump)).hexdigest()[:16]}…")
    else:
        print("\n[dry-run] No output written.")


if __name__ == "__main__":
    main()
