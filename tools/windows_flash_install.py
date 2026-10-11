#!/usr/bin/env python3
"""Install an SMK-37 Pro FWSC payload over the WL82 bootloader, no vendor tool.

Reuses the Windows SCSI transport that already proved the loader protocol on
hardware (loader-probe, 2026-10-11): that probe uploaded Jieli's official
31,232-byte loader to volatile RAM and reported WL82/UBOOT1.00/1.00 with flash
id 60256. This adds the two vendor CDBs the read-only tool deliberately omits:

    0xFB01 CMD_ERASE_FLASH_SECTOR   arguments: address(4, big-endian)
    0xFB04 CMD_WRITE_FLASH          arguments: address(4, BE) len(2, BE)
                                            0x00 crc16-xmodem(data)(2, LE)

The block device is not used and does not need to work. Get-Disk reports Size 0
for this target because the flash is reached entirely through vendor CDBs, so a
zero capacity there is expected and is not a fault.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import sys
from pathlib import Path

LOG = logging.getLogger("flash-install")

FLASH_SIZE = 0x100000
SECTOR_SIZE = 0x1000
IO_CHUNK = 256  # proven conservative; the loader advertises 32768

CMD_ERASE_SECTOR = 0xFB01
CMD_WRITE_FLASH = 0xFB04
CMD_READ_FLASH = 0xFD05

EXPECTED_VENDOR = "WL82"
EXPECTED_PRODUCT = "UBOOT1.00"
EXPECTED_FLASH_ID = 60256


def crc16_xmodem(data: bytes, initial: int = 0) -> int:
    crc = initial
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def vendor_cdb(command: int, arguments: bytes) -> bytes:
    cdb = command.to_bytes(2, "big") + arguments
    if len(cdb) > 11:
        raise ValueError("arguments too long for a 16-byte vendor CDB")
    return cdb.ljust(16, b"\xff")


def load_transport(bundle: Path):
    tool = bundle / "tools" / "windows_scsi_transport.py"
    spec = importlib.util.spec_from_file_location("wl82_transport", tool)
    module = importlib.util.module_from_spec(spec)
    sys.modules["wl82_transport"] = module
    spec.loader.exec_module(module)
    return module


class Installer:
    def __init__(self, target, transport):
        self.target = target
        self.transport = transport

    def read(self, address: int, length: int) -> bytes:
        cdb = vendor_cdb(CMD_READ_FLASH, address.to_bytes(4, "big") + length.to_bytes(2, "big"))
        return self.transport.execute(cdb, data_in_length=length)

    def erase(self, address: int) -> None:
        cdb = vendor_cdb(CMD_ERASE_SECTOR, address.to_bytes(4, "big"))
        self.transport.execute(cdb, data_in_length=16)

    def write(self, address: int, data: bytes) -> None:
        arguments = (
            address.to_bytes(4, "big")
            + len(data).to_bytes(2, "big")
            + b"\x00"
            + crc16_xmodem(data).to_bytes(2, "little")
        )
        self.transport.execute(vendor_cdb(CMD_WRITE_FLASH, arguments), data_out=data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--device", default=r"\\.\PhysicalDrive5")
    parser.add_argument("--bundle", type=Path,
                        default=Path("build/SMK37Pro-WL82-v15-H0-rollback-20260802-v1"))
    parser.add_argument("--sha256", default="")
    parser.add_argument("--backup", type=Path, default=None)
    parser.add_argument("--confirm", default="")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    image = args.image.read_bytes()
    if len(image) > FLASH_SIZE:
        raise SystemExit(f"image is {len(image)} bytes, flash holds {FLASH_SIZE}")
    LOG.info("image: %d bytes of %d", len(image), FLASH_SIZE)

    if args.sha256:
        got = hashlib.sha256(image).hexdigest()
        if got.lower() != args.sha256.lower():
            raise SystemExit(f"image sha256 {got} does not match pinned {args.sha256}")
        LOG.info("image sha256 matches pin")

    if args.dry_run:
        LOG.info("dry run: nothing sent")
        return 0

    if args.confirm != "I-UNDERSTAND":
        raise SystemExit(
            "refusing to write without --confirm I-UNDERSTAND.\n"
            "This erases and rewrites the instrument's entire flash."
        )

    module = load_transport(args.bundle)
    loader = (args.bundle / "assets" / "wl82loader.bin").read_bytes()
    module.validate_official_loader(loader)

    with module.WindowsScsiTransport(args.device) as transport:
        target = module.ReadOnlyWl82(transport)
        identity = target.inquiry()
        LOG.info("identity: %s", json.dumps(identity))
        if identity["vendor"] != EXPECTED_VENDOR or identity["product"] != EXPECTED_PRODUCT:
            raise SystemExit("target is not a WL82 UBOOT1.00 device; refusing")

        target.upload_official_loader(loader)
        info = target.loader_info()
        LOG.info("loader info: %s", json.dumps(info))
        if info["flash_id"] != EXPECTED_FLASH_ID:
            raise SystemExit(f"unexpected flash id {info['flash_id']}")

        io = Installer(target, transport)

        if args.backup:
            LOG.info("reading full flash to %s", args.backup)
            blob = bytearray()
            for address in range(0, FLASH_SIZE, IO_CHUNK):
                blob += io.read(address, IO_CHUNK)
            args.backup.write_bytes(bytes(blob))
            LOG.info("backup written: %d bytes", args.backup.stat().st_size)

        sectors = sorted({(a // SECTOR_SIZE) * SECTOR_SIZE
                          for a in range(0, len(image), SECTOR_SIZE)})
        LOG.info("erasing %d sectors, then writing %d bytes", len(sectors), len(image))
        for index, sector in enumerate(sectors, 1):
            io.erase(sector)
            if index % 25 == 0 or index == len(sectors):
                LOG.info("  erased %d/%d", index, len(sectors))

        written = 0
        for address in range(0, len(image), IO_CHUNK):
            io.write(address, image[address:address + IO_CHUNK])
            written += IO_CHUNK
            if written % (IO_CHUNK * 100) == 0 or written >= len(image):
                LOG.info("  written %d/%d", min(written, len(image)), len(image))

        LOG.info("verifying read-back")
        for address in range(0, len(image), IO_CHUNK):
            block = image[address:address + IO_CHUNK]
            if io.read(address, len(block)) != block:
                raise SystemExit(f"read-back mismatch at 0x{address:06x}")
        LOG.info("PASS: %d bytes written and read back identical", len(image))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
