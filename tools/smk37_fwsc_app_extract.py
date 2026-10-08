#!/usr/bin/env python3
"""Extract and decode the application image from an SMK-37 Pro .fwsc package.

Recovers the JLFS app.bin from a vendor FWSC even when the package layout has
changed between firmware revisions:

  * FWSC metadata: 20 x 48-byte slots, 47 data bytes each, remainder appended
  * UFW payload: flash.bin is located by decrypting candidate offsets and
    looking for the plaintext JLFS name "app_area_head" (the offset moved from
    0x400 in v15 to 0x410 in v16)
  * JLFS entries at flash 0x4000 (app_area_head) and 0x4020 (app.bin)
  * the app area is SFC-ciphered: block key = CHIP_KEY ^ ((addr - 0x4000) >> 2),
    keystream = LFSR 0x1021 seeded with the low byte of the block key

Offline only: reads a package file, writes a decoded app image. No device.

Usage:
  python3 tools/smk37_fwsc_app_extract.py <package.fwsc> [--out app.bin] [--json out.json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct

CHIP_KEY = 0x980F
APP_AREA_BASE = 0x4000
FWSC_BLOCK = 48
FWSC_DATA = 47
FWSC_SLOTS = 20
FLASH_BIN_SIZE = 0x9C000
FLASH_SCAN = (0x300, 0xC00)


def keystream(n: int, key: int) -> bytes:
    out = bytearray()
    for _ in range(n):
        out.append(key & 0xFF)
        key = ((key << 1) ^ (0x1021 if key & 0x8000 else 0)) & 0xFFFF
    return bytes(out)


def decrypt(fl: bytes, addr: int, size: int) -> bytes:
    buf = bytearray(fl[addr:addr + size])
    for rel in range(0, len(buf), 32):
        chunk = min(32, len(buf) - rel)
        key = CHIP_KEY ^ ((addr + rel - APP_AREA_BASE) >> 2)
        ks = keystream(chunk, key)
        for i in range(chunk):
            buf[rel + i] ^= ks[i]
    return bytes(buf)


def decrypt_app(data: bytes, app_start: int = 0x4120) -> bytes:
    """Decrypt a raw app slice (the app starts at flash APP_AREA_BASE+0x120)."""
    buf = bytearray(data)
    base = APP_AREA_BASE - app_start
    for rel in range(0, len(buf), 32):
        chunk = min(32, len(buf) - rel)
        ks = keystream(chunk, CHIP_KEY ^ ((rel - base) >> 2))
        for i in range(chunk):
            buf[rel + i] ^= ks[i]
    return bytes(buf)


def unpack_fwsc(raw: bytes) -> bytes:
    payload = bytearray()
    for i in range(FWSC_SLOTS):
        payload += raw[i * FWSC_BLOCK: i * FWSC_BLOCK + FWSC_DATA]
    payload += raw[FWSC_SLOTS * FWSC_BLOCK:]
    return bytes(payload)


def find_flash_bin(payload: bytes):
    for cand in range(FLASH_SCAN[0], FLASH_SCAN[1], 2):
        if cand + FLASH_BIN_SIZE > len(payload):
            break
        fl = payload[cand:cand + FLASH_BIN_SIZE]
        if b"app_area_head" in decrypt(fl, APP_AREA_BASE, 0x100):
            return cand, fl
    return None, None


def read_entry(fl: bytes, addr: int):
    h = decrypt(fl, addr, 0x20)
    _, off, size = struct.unpack_from("<HII", h, 2)
    name = bytes(h[16:32]).split(bytes([0]))[0].decode("latin1")
    return {"name": name, "offset": off, "size": size, "flags": h[12], "crc": struct.unpack_from("<H", h, 14)[0]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("package")
    ap.add_argument("--out")
    ap.add_argument("--json")
    args = ap.parse_args()

    raw = open(args.package, "rb").read()
    payload = unpack_fwsc(raw)
    flash_off, fl = find_flash_bin(payload)
    if fl is None:
        print("flash.bin not located in payload")
        return 1
    area = read_entry(fl, APP_AREA_BASE)
    app = read_entry(fl, APP_AREA_BASE + 0x20)
    start = APP_AREA_BASE + app["offset"]
    raw_app = fl[start:start + app["size"]]
    decoded = decrypt_app(raw_app, start)

    info = {
        "package": args.package,
        "package_sha256": hashlib.sha256(raw).hexdigest(),
        "payload_size": len(payload),
        "flash_bin_payload_offset": hex(flash_off),
        "flash_bin_sha256": hashlib.sha256(fl).hexdigest(),
        "app_area": area,
        "app_entry": app,
        "app_offset": hex(start),
        "app_size": app["size"],
        "app_sha256_decoded": hashlib.sha256(decoded).hexdigest(),
        "app_sha256_raw": hashlib.sha256(raw_app).hexdigest(),
    }
    if args.out:
        open(args.out, "wb").write(decoded)
        info["out"] = args.out
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(info, fh, indent=2)
            fh.write("\n")
    for k, v in info.items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
