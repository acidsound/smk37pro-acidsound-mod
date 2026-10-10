#!/usr/bin/env python3
"""Strictly read-only WL82 Flash acquisition for SMK-37 Pro recovery.

The only target mutations implemented here are writes to volatile RAM followed
by a RAM jump, which are required to start Jieli's official WL82 loader.
There are no Flash erase, Flash write, chip-key write, format, or reset CDBs.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Protocol


EXPECTED_VENDOR = "WL82"
EXPECTED_PRODUCT = "UBOOT1.00"
FLASH_SIZE = 0x100000
SECTOR_SIZE = 0x1000
LOADER_ADDRESS = 0x1C02000
LOADER_ARGUMENT_SPI_NOR = 1
LOADER_BLOCK_SIZE = 512
OFFICIAL_LOADER_SIZE = 31232
OFFICIAL_LOADER_SHA256 = (
    "9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27"
)
EXPECTED_RECOVERY_SECTORS = {0x04000, 0x20000, 0x21000, 0x27000, 0x5A000, 0x99000}
# The M09 recovery plan above keeps its own report format. The generic
# evidence path deliberately uses a different one so a session can never be
# mistaken for an M09 plan result, and it takes no manifest at all.
EVIDENCE_REPORT_FORMAT = "smk37-wl82-evidence-dump-v1"
# The 0xFC14 response carries the loader USB buffer size in its first 4 bytes
# (big-endian, effectively bytes[2:4]) followed by 10 bytes of flags/state.
# The host conservatively reads Flash in min(buffer_size, 256) chunks, so the
# upper bound only needs to exclude a misread or missing loader. Observed live
# on the M09 target: bytes 2-4 = 0x0080 (big-endian) = 32768. When the loader
# is not yet running, the first four bytes are all zero, which is how the
# sanity check rejects pre-jump or dead-loader responses.
LOADER_BUFFER_SIZE_MIN = 64
LOADER_BUFFER_SIZE_MAX = 0x10000
STANDARD_INQUIRY_CDB = bytes([0x12, 0x00, 0x00, 0x00, 36, 0x00])

CMD_UBOOT_WRITE_MEMORY = 0xFB06  # volatile RAM only
CMD_UBOOT_JUMP_MEMORY = 0xFB08   # execute volatile RAM loader
CMD_LOADER_READ_FLASH = 0xFD05
CMD_LOADER_GET_ONLINE_DEVICE = 0xFC0A
CMD_LOADER_READ_ID = 0xFC0B
CMD_LOADER_GET_USB_BUFFER_SIZE = 0xFC14

ALLOWED_VENDOR_CDBS = {
    CMD_UBOOT_WRITE_MEMORY,
    CMD_UBOOT_JUMP_MEMORY,
    CMD_LOADER_READ_FLASH,
    CMD_LOADER_GET_ONLINE_DEVICE,
    CMD_LOADER_READ_ID,
    CMD_LOADER_GET_USB_BUFFER_SIZE,
}
FORBIDDEN_FLASH_MUTATING_CDBS = {0xFB00, 0xFB01, 0xFB02, 0xFB04, 0xFC12}

LOG = logging.getLogger("smk37-wl82-readonly")


class SafetyError(RuntimeError):
    """A condition that must stop the read-only workflow."""


class ScsiTransport(Protocol):
    observed_vendor_cdbs: list[int]

    def execute(
        self,
        cdb: bytes,
        *,
        data_out: bytes | None = None,
        data_in_length: int = 0,
    ) -> bytes:
        ...

    def close(self) -> None:
        ...


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def crc16_xmodem(data: bytes, initial: int = 0) -> int:
    crc = initial & 0xFFFF
    for value in data:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def validate_official_loader(loader: bytes) -> None:
    if len(loader) != OFFICIAL_LOADER_SIZE:
        raise SafetyError(
            f"official loader size mismatch: got {len(loader)}, expected {OFFICIAL_LOADER_SIZE}"
        )
    actual = sha256_bytes(loader)
    if actual != OFFICIAL_LOADER_SHA256:
        raise SafetyError(
            f"official loader SHA-256 mismatch: got {actual}, expected {OFFICIAL_LOADER_SHA256}"
        )
    if len(loader) % LOADER_BLOCK_SIZE != 0:
        raise SafetyError("official loader is not aligned to 512-byte transfer blocks")


def build_vendor_cdb(command: int, arguments: bytes = b"") -> bytes:
    if command not in ALLOWED_VENDOR_CDBS:
        raise SafetyError(f"CDB 0x{command:04X} is not in the read-only allowlist")
    cdb = command.to_bytes(2, "big") + arguments
    if len(cdb) > 16:
        raise SafetyError(f"CDB 0x{command:04X} exceeds 16 bytes")
    return cdb + b"\xFF" * (16 - len(cdb))


def validate_transfer_contract(
    cdb: bytes,
    data_out: bytes | None,
    data_in_length: int,
) -> int | None:
    """Reject every SCSI shape except the six reviewed read-only/RAM forms."""
    if data_out is not None and data_in_length:
        raise SafetyError("simultaneous SCSI data-in and data-out is prohibited")
    if cdb == STANDARD_INQUIRY_CDB:
        if data_out is not None or data_in_length != 36:
            raise SafetyError("standard INQUIRY must be an exact 36-byte data-in transfer")
        return None
    if len(cdb) != 16:
        raise SafetyError("only exact 6-byte INQUIRY or allowlisted 16-byte CDBs are accepted")

    command = int.from_bytes(cdb[:2], "big")
    if command not in ALLOWED_VENDOR_CDBS:
        raise SafetyError(f"refusing non-allowlisted vendor CDB 0x{command:04X}")

    if command == CMD_UBOOT_WRITE_MEMORY:
        if data_out is None or not 1 <= len(data_out) <= LOADER_BLOCK_SIZE:
            raise SafetyError("RAM-loader write must contain 1..512 output bytes")
        address = int.from_bytes(cdb[2:6], "big")
        length = int.from_bytes(cdb[6:8], "big")
        crc = int.from_bytes(cdb[9:11], "little")
        if (
            length != len(data_out)
            or cdb[8] != 0
            or crc != crc16_xmodem(data_out)
            or not LOADER_ADDRESS <= address
            or address + length > LOADER_ADDRESS + OFFICIAL_LOADER_SIZE
            or cdb[11:] != b"\xFF" * 5
        ):
            raise SafetyError("RAM-loader write contract mismatch")
    elif command == CMD_UBOOT_JUMP_MEMORY:
        if (
            data_out is not None
            or data_in_length != 16
            or int.from_bytes(cdb[2:6], "big") != LOADER_ADDRESS
            or int.from_bytes(cdb[6:8], "big") != LOADER_ARGUMENT_SPI_NOR
            or cdb[8:] != b"\xFF" * 8
        ):
            raise SafetyError("RAM-loader jump contract mismatch")
    elif command in {
        CMD_LOADER_GET_ONLINE_DEVICE,
        CMD_LOADER_READ_ID,
        CMD_LOADER_GET_USB_BUFFER_SIZE,
    }:
        if data_out is not None or data_in_length != 16 or cdb[2:] != b"\xFF" * 14:
            raise SafetyError("loader-information query contract mismatch")
    elif command == CMD_LOADER_READ_FLASH:
        address = int.from_bytes(cdb[2:6], "big")
        length = int.from_bytes(cdb[6:8], "big")
        if (
            data_out is not None
            or length != data_in_length
            or not 1 <= length <= 4096
            or address + length > FLASH_SIZE
            or cdb[8:] != b"\xFF" * 8
        ):
            raise SafetyError("Flash-read contract mismatch")
    else:
        raise AssertionError(f"unhandled allowlisted CDB 0x{command:04X}")
    return command


class WindowsScsiTransport:
    """Windows SCSI_PASS_THROUGH_DIRECT transport for one explicit disk path."""

    IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x4D014
    IOCTL_SCSI_GET_ADDRESS = 0x41018
    SCSI_IOCTL_DATA_OUT = 0
    SCSI_IOCTL_DATA_IN = 1
    SCSI_IOCTL_DATA_UNSPECIFIED = 2
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x00000080
    SENSE_LENGTH = 32

    def __init__(self, path: str):
        if os.name != "nt":
            raise SafetyError("real SCSI access is supported only on Windows")
        if not path.startswith("\\\\.\\"):
            raise SafetyError("device path must start with \\\\.\\")

        class ScsiPassThroughDirect(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.USHORT),
                ("ScsiStatus", wintypes.BYTE),
                ("PathId", wintypes.BYTE),
                ("TargetId", wintypes.BYTE),
                ("Lun", wintypes.BYTE),
                ("CdbLength", wintypes.BYTE),
                ("SenseInfoLength", wintypes.BYTE),
                ("DataIn", wintypes.BYTE),
                ("DataTransferLength", wintypes.ULONG),
                ("TimeOutValue", wintypes.ULONG),
                ("DataBuffer", ctypes.c_void_p),
                ("SenseInfoOffset", wintypes.ULONG),
                ("Cdb", wintypes.BYTE * 16),
            ]

        class Packet(ctypes.Structure):
            _fields_ = [
                ("sptd", ScsiPassThroughDirect),
                ("filler", wintypes.ULONG),
                ("sense", wintypes.BYTE * self.SENSE_LENGTH),
            ]

        class ScsiAddress(ctypes.Structure):
            _fields_ = [
                ("Length", wintypes.ULONG),
                ("PortNumber", wintypes.BYTE),
                ("PathId", wintypes.BYTE),
                ("TargetId", wintypes.BYTE),
                ("Lun", wintypes.BYTE),
            ]

        self._sptd_type = ScsiPassThroughDirect
        self._packet_type = Packet
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._create_file = self._kernel32.CreateFileW
        self._create_file.restype = wintypes.HANDLE
        self._create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = [wintypes.HANDLE]
        self._close_handle.restype = wintypes.BOOL
        self._device_io_control = self._kernel32.DeviceIoControl
        self._device_io_control.restype = wintypes.BOOL
        self._device_io_control.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]

        self._handle = self._create_file(
            path,
            self.GENERIC_READ | self.GENERIC_WRITE,
            self.FILE_SHARE_READ | self.FILE_SHARE_WRITE,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if self._handle == wintypes.HANDLE(-1).value:
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error), path)
        self.path = path
        self.observed_vendor_cdbs: list[int] = []

        address = ScsiAddress()
        address.Length = ctypes.sizeof(ScsiAddress)
        returned = wintypes.DWORD()
        success = self._device_io_control(
            self._handle,
            self.IOCTL_SCSI_GET_ADDRESS,
            None,
            0,
            ctypes.byref(address),
            ctypes.sizeof(address),
            ctypes.byref(returned),
            None,
        )
        if not success:
            error = ctypes.get_last_error()
            self.close()
            raise OSError(error, ctypes.FormatError(error), path)
        self._path_id = address.PathId
        self._target_id = address.TargetId
        self._lun = address.Lun

    def close(self) -> None:
        if getattr(self, "_handle", None) not in (None, wintypes.HANDLE(-1).value):
            self._close_handle(self._handle)
            self._handle = None

    def __enter__(self) -> "WindowsScsiTransport":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def execute(
        self,
        cdb: bytes,
        *,
        data_out: bytes | None = None,
        data_in_length: int = 0,
    ) -> bytes:
        command = validate_transfer_contract(cdb, data_out, data_in_length)
        if command is not None:
            self.observed_vendor_cdbs.append(command)

        packet = self._packet_type()
        packet.sptd.Length = ctypes.sizeof(self._sptd_type)
        packet.sptd.PathId = self._path_id
        packet.sptd.TargetId = self._target_id
        packet.sptd.Lun = self._lun
        packet.sptd.CdbLength = len(cdb)
        packet.sptd.SenseInfoLength = self.SENSE_LENGTH
        packet.sptd.SenseInfoOffset = self._packet_type.sense.offset
        packet.sptd.TimeOutValue = 10
        for index, value in enumerate(cdb):
            packet.sptd.Cdb[index] = value

        data_buffer = None
        if data_out is not None:
            data_buffer = ctypes.create_string_buffer(data_out)
            packet.sptd.DataIn = self.SCSI_IOCTL_DATA_OUT
            packet.sptd.DataTransferLength = len(data_out)
            packet.sptd.DataBuffer = ctypes.addressof(data_buffer)
        elif data_in_length:
            data_buffer = ctypes.create_string_buffer(data_in_length)
            packet.sptd.DataIn = self.SCSI_IOCTL_DATA_IN
            packet.sptd.DataTransferLength = data_in_length
            packet.sptd.DataBuffer = ctypes.addressof(data_buffer)
        else:
            packet.sptd.DataIn = self.SCSI_IOCTL_DATA_UNSPECIFIED
            packet.sptd.DataTransferLength = 0
            packet.sptd.DataBuffer = None

        returned = wintypes.DWORD()
        success = self._device_io_control(
            self._handle,
            self.IOCTL_SCSI_PASS_THROUGH_DIRECT,
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            ctypes.byref(packet),
            ctypes.sizeof(packet),
            ctypes.byref(returned),
            None,
        )
        if not success:
            error = ctypes.get_last_error()
            raise OSError(error, ctypes.FormatError(error), self.path)
        if packet.sptd.ScsiStatus != 0:
            sense = bytes(packet.sense).hex(" ")
            raise SafetyError(
                f"SCSI status 0x{packet.sptd.ScsiStatus:02X}; sense={sense}"
            )
        if data_in_length:
            assert data_buffer is not None
            transferred = packet.sptd.DataTransferLength
            if transferred != data_in_length:
                raise SafetyError(
                    f"short SCSI data-in: got {transferred}, expected {data_in_length}"
                )
            return bytes(data_buffer.raw[:transferred])
        return b""


class ReadOnlyWl82:
    def __init__(self, transport: ScsiTransport):
        self.transport = transport

    def inquiry(self) -> dict[str, str]:
        data = self.transport.execute(
            STANDARD_INQUIRY_CDB, data_in_length=36
        )
        if len(data) != 36:
            raise SafetyError(f"short SCSI INQUIRY response: {len(data)} bytes")

        def field(start: int, length: int) -> str:
            return data[start : start + length].decode("ascii", errors="strict").strip(" \x00")

        identity = {
            "vendor": field(8, 8),
            "product": field(16, 16),
            "revision": field(32, 4),
        }
        if identity["vendor"] != EXPECTED_VENDOR or identity["product"] != EXPECTED_PRODUCT:
            raise SafetyError(
                "unexpected target identity: "
                f"vendor={identity['vendor']!r} product={identity['product']!r}"
            )
        return identity

    def _response(self, command: int, arguments: bytes = b"") -> bytes:
        response = self.transport.execute(
            build_vendor_cdb(command, arguments), data_in_length=16
        )
        if len(response) != 16:
            raise SafetyError(f"short response for 0x{command:04X}")
        returned_command = int.from_bytes(response[:2], "big")
        if returned_command != command:
            raise SafetyError(
                f"response CDB mismatch: sent 0x{command:04X}, got 0x{returned_command:04X}"
            )
        return response[2:]

    def upload_official_loader(
        self,
        loader: bytes,
        *,
        expected_size: int = OFFICIAL_LOADER_SIZE,
        expected_sha256: str = OFFICIAL_LOADER_SHA256,
    ) -> None:
        if len(loader) != expected_size or sha256_bytes(loader) != expected_sha256:
            raise SafetyError("loader does not match the locked expected bytes")
        if len(loader) % LOADER_BLOCK_SIZE:
            raise SafetyError("loader length is not a multiple of 512 bytes")

        LOG.info("uploading %d-byte loader to volatile RAM only", len(loader))
        for offset in range(0, len(loader), LOADER_BLOCK_SIZE):
            block = loader[offset : offset + LOADER_BLOCK_SIZE]
            address = LOADER_ADDRESS + offset
            arguments = (
                address.to_bytes(4, "big")
                + len(block).to_bytes(2, "big")
                + b"\x00"
                + crc16_xmodem(block).to_bytes(2, "little")
            )
            self.transport.execute(
                build_vendor_cdb(CMD_UBOOT_WRITE_MEMORY, arguments), data_out=block
            )

        self._response(
            CMD_UBOOT_JUMP_MEMORY,
            LOADER_ADDRESS.to_bytes(4, "big")
            + LOADER_ARGUMENT_SPI_NOR.to_bytes(2, "big"),
        )
        time.sleep(0.5)

    def loader_info(self) -> dict[str, int]:
        buffer_response = self._response(CMD_LOADER_GET_USB_BUFFER_SIZE)
        buffer_size = int.from_bytes(buffer_response[2:4], "big")
        if not LOADER_BUFFER_SIZE_MIN <= buffer_size <= LOADER_BUFFER_SIZE_MAX:
            LOG.error(
                "0xFC14 raw 14-byte payload (hex): %s; parsed 32-bit big-endian from bytes 2-4: %d",
                buffer_response.hex(" "),
                buffer_size,
            )
            raise SafetyError(f"implausible loader USB buffer size: {buffer_size}")

        online = self._response(CMD_LOADER_GET_ONLINE_DEVICE)
        device_type = online[0]
        device_id = int.from_bytes(online[2:6], "little")
        if device_type not in {0x03, 0x16}:
            raise SafetyError(
                f"loader selected unexpected device type 0x{device_type:02X}; expected SPI NOR"
            )

        flash_id_response = self._response(CMD_LOADER_READ_ID)
        flash_id = int.from_bytes(flash_id_response[:3], "big")
        return {
            "usb_buffer_size": buffer_size,
            "device_type": device_type,
            "device_id": device_id,
            "flash_id": flash_id,
        }

    def read_flash(self, address: int, length: int) -> bytes:
        if address < 0 or length <= 0 or address + length > FLASH_SIZE:
            raise SafetyError(
                f"Flash read outside locked 1 MiB range: 0x{address:X}+0x{length:X}"
            )
        arguments = address.to_bytes(4, "big") + length.to_bytes(2, "big")
        return self.transport.execute(
            build_vendor_cdb(CMD_LOADER_READ_FLASH, arguments),
            data_in_length=length,
        )


def load_recovery_manifest(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("format") != "smk37-m09-forced-recovery-plan-v1":
        raise SafetyError("unexpected recovery manifest format")
    if value.get("hash_representation") != (
        "FWSC-unpacked flash.bin bytes; not directly comparable to "
        "a forced-loader dump until its returned representation is validated"
    ):
        raise SafetyError("recovery manifest does not declare its hash representation")
    sectors = value.get("sectors")
    if not isinstance(sectors, list):
        raise SafetyError("recovery manifest has no sector list")
    addresses = {int(item["address"], 0) for item in sectors}
    if addresses != EXPECTED_RECOVERY_SECTORS:
        raise SafetyError(f"unexpected recovery sector set: {sorted(addresses)}")
    for item in sectors:
        if item.get("length") != SECTOR_SIZE:
            raise SafetyError(f"sector {item.get('address')} is not 4 KiB")
        expected = item.get("expected_m09_sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            raise SafetyError(f"sector {item.get('address')} has no valid M09 hash")
    return value


def configure_logging(log_path: Path | None = None) -> None:
    LOG.handlers.clear()
    LOG.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    LOG.addHandler(console)
    if log_path is not None:
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        LOG.addHandler(file_handler)


def dump_once(device: ReadOnlyWl82, output: Path, chunk_size: int) -> str:
    partial = output.with_suffix(output.suffix + ".partial")
    digest = hashlib.sha256()
    with partial.open("wb") as handle:
        for address in range(0, FLASH_SIZE, chunk_size):
            block = device.read_flash(address, min(chunk_size, FLASH_SIZE - address))
            if len(block) != min(chunk_size, FLASH_SIZE - address):
                raise SafetyError(f"short Flash read at 0x{address:06X}")
            handle.write(block)
            digest.update(block)
            if address % 0x10000 == 0:
                LOG.info("read progress: 0x%06X / 0x%06X", address, FLASH_SIZE)
        handle.flush()
        os.fsync(handle.fileno())
    partial.replace(output)
    return digest.hexdigest()


def compare_recovery_sectors(dump_path: Path, manifest: dict[str, object]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    with dump_path.open("rb") as handle:
        for item in manifest["sectors"]:  # type: ignore[index]
            address = int(item["address"], 0)
            handle.seek(address)
            data = handle.read(SECTOR_SIZE)
            actual = sha256_bytes(data)
            expected = item["expected_m09_sha256"]
            results.append(
                {
                    "address": item["address"],
                    "length": SECTOR_SIZE,
                    "forced_loader_dump_sha256": actual,
                    "fwsc_flash_bin_expected_m09_sha256": expected,
                    "representations_directly_comparable": False,
                }
            )
    return results


def compare_flash_images(
    left: Path, right: Path, left_label: str, right_label: str
) -> dict[str, object]:
    """Sector-by-sector comparison of two 1 MiB Flash images.

    This reports only what was observed. It draws no conclusion about which
    representation is correct, and it never implies that either image may be
    written: deciding that is an open recovery gate, not something a byte
    comparison can settle.
    """
    left_bytes = left.read_bytes()
    right_bytes = right.read_bytes()
    if len(left_bytes) != FLASH_SIZE or len(right_bytes) != FLASH_SIZE:
        raise SafetyError("both Flash images must be exactly 1 MiB")
    sectors: list[dict[str, object]] = []
    for address in range(0, FLASH_SIZE, SECTOR_SIZE):
        before = left_bytes[address : address + SECTOR_SIZE]
        after = right_bytes[address : address + SECTOR_SIZE]
        if before == after:
            continue
        sectors.append(
            {
                "address": f"0x{address:05X}",
                "length": SECTOR_SIZE,
                "changed_byte_count": sum(a != b for a, b in zip(before, after)),
                f"{left_label}_sha256": sha256_bytes(before),
                f"{right_label}_sha256": sha256_bytes(after),
            }
        )
    return {
        "left": {"label": left_label, "sha256": sha256_bytes(left_bytes)},
        "right": {"label": right_label, "sha256": sha256_bytes(right_bytes)},
        "sector_size": SECTOR_SIZE,
        "total_sectors": FLASH_SIZE // SECTOR_SIZE,
        "identical_sector_count": (FLASH_SIZE // SECTOR_SIZE) - len(sectors),
        "differing_sector_count": len(sectors),
        "differing_sectors": sectors,
        "interpretation": (
            "observation only; equal bytes do not prove equal semantics and "
            "this comparison does not authorize any write"
        ),
    }


def make_session_directory(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    candidate = root / f"wl82-readonly-{stamp}"
    suffix = 1
    while candidate.exists():
        candidate = root / f"wl82-readonly-{stamp}-{suffix}"
        suffix += 1
    candidate.mkdir()
    return candidate


def run_probe(device_path: str) -> int:
    configure_logging()
    with WindowsScsiTransport(device_path) as transport:
        identity = ReadOnlyWl82(transport).inquiry()
    print(json.dumps(identity, indent=2))
    print("PASS: exact WL82 UBOOT1.00 identity; no vendor command was sent")
    return 0


def run_loader_probe(device_path: str, loader_path: Path) -> int:
    configure_logging()
    loader = loader_path.read_bytes()
    validate_official_loader(loader)
    with WindowsScsiTransport(device_path) as transport:
        target = ReadOnlyWl82(transport)
        identity = target.inquiry()
        target.upload_official_loader(loader)
        info = target.loader_info()
        observed = sorted(set(transport.observed_vendor_cdbs))
    result = {"identity": identity, "loader": info, "observed_cdbs": observed}
    print(json.dumps(result, indent=2))
    print("PASS: official loader ran from volatile RAM; Flash was not read or modified")
    return 0


def acquire_evidence(
    transport,
    loader: bytes,
    session: Path,
    *,
    expected_size: int = OFFICIAL_LOADER_SIZE,
    expected_sha256: str = OFFICIAL_LOADER_SHA256,
) -> dict[str, object]:
    """Identity, RAM loader, then two full 1 MiB reads. Read-only.

    Shared by run_evidence_dump and the self-test so the tested path is the
    production path. No manifest is consulted here by design. The expected_*
    arguments default to the locked official loader; only the self-test
    overrides them, exactly as ReadOnlyWl82.upload_official_loader allows.
    """
    target = ReadOnlyWl82(transport)
    identity = target.inquiry()
    target.upload_official_loader(
        loader, expected_size=expected_size, expected_sha256=expected_sha256
    )
    loader_info = target.loader_info()
    chunk_size = min(loader_info["usb_buffer_size"], 256)
    LOG.info("using conservative Flash read size: %d", chunk_size)
    dump_a = session / "flash-dump-a.bin"
    dump_b = session / "flash-dump-b.bin"
    digest_a = dump_once(target, dump_a, chunk_size)
    digest_b = dump_once(target, dump_b, chunk_size)
    observed = sorted(set(transport.observed_vendor_cdbs))
    if dump_a.stat().st_size != FLASH_SIZE or dump_b.stat().st_size != FLASH_SIZE:
        raise SafetyError("one or both Flash dumps are not exactly 1 MiB")
    if digest_a != digest_b or dump_a.read_bytes() != dump_b.read_bytes():
        raise SafetyError("the two Flash dumps differ; preserve output and stop")
    return {
        "identity": identity,
        "loader_info": loader_info,
        "chunk_size": chunk_size,
        "dump_a": dump_a,
        "dump_b": dump_b,
        "digest_a": digest_a,
        "digest_b": digest_b,
        "observed": observed,
    }


def run_evidence_dump(
    device_path: str,
    loader_path: Path,
    output_root: Path,
    compare_path: Path | None,
) -> int:
    """Generic read-only double dump with no M09 manifest gate.

    This exists so a healthy, known-version target can be captured in the
    forced-loader representation before any version change, which is the only
    way to compare that representation against a package. It is evidence
    acquisition. It is not a recovery plan and produces no write list.
    """
    loader = loader_path.read_bytes()
    validate_official_loader(loader)
    session = make_session_directory(output_root)
    configure_logging(session / "session.log")
    LOG.info("read-only evidence session directory: %s", session)
    with WindowsScsiTransport(device_path) as transport:
        acquired = acquire_evidence(transport, loader, session)

    dump_a: Path = acquired["dump_a"]  # type: ignore[assignment]
    dump_b: Path = acquired["dump_b"]  # type: ignore[assignment]
    report: dict[str, object] = {
        "format": EVIDENCE_REPORT_FORMAT,
        "command": "evidence-dump",
        "device_path": device_path,
        "identity": acquired["identity"],
        "official_loader": {
            "size": len(loader),
            "sha256": sha256_bytes(loader),
            "ram_address": f"0x{LOADER_ADDRESS:08X}",
        },
        "loader_info": acquired["loader_info"],
        "flash_size": FLASH_SIZE,
        "dump_a": {"file": dump_a.name, "sha256": acquired["digest_a"]},
        "dump_b": {"file": dump_b.name, "sha256": acquired["digest_b"]},
        "dumps_byte_identical": True,
        "observed_vendor_cdbs": [f"0x{c:04X}" for c in acquired["observed"]],
        "read_only_acquisition_pass": True,
        "physical_write_supported": False,
        "restore_authorized": False,
        "restore_blocker": (
            "evidence acquisition only. Package flash.bin sector hashes are "
            "still not established as comparable to a forced-loader dump, no "
            "v16 target manifest exists, and this report carries no write list."
        ),
    }
    if compare_path is not None:
        report["comparison"] = compare_flash_images(
            dump_a, compare_path, "forced_loader_dump", "supplied_reference"
        )
    (session / "evidence-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (session / "SHA256SUMS.txt").write_text(
        f"{acquired['digest_a']}  {dump_a.name}\n"
        f"{acquired['digest_b']}  {dump_b.name}\n",
        encoding="ascii",
    )
    print(json.dumps({"session": str(session), "read_only_acquisition_pass": True,
                      "restore_authorized": False}, indent=2))
    print("PASS: two byte-identical 1 MiB forced-loader dumps were acquired")
    print("EVIDENCE ONLY: no restore authorized, no write list produced")
    return 0


def run_double_dump(
    device_path: str,
    loader_path: Path,
    manifest_path: Path,
    output_root: Path,
) -> int:
    loader = loader_path.read_bytes()
    validate_official_loader(loader)
    manifest = load_recovery_manifest(manifest_path)
    session = make_session_directory(output_root)
    configure_logging(session / "session.log")
    LOG.info("read-only session directory: %s", session)

    with WindowsScsiTransport(device_path) as transport:
        target = ReadOnlyWl82(transport)
        identity = target.inquiry()
        target.upload_official_loader(loader)
        loader_info = target.loader_info()
        chunk_size = min(loader_info["usb_buffer_size"], 256)
        LOG.info("using conservative Flash read size: %d", chunk_size)
        dump_a = session / "flash-dump-a.bin"
        dump_b = session / "flash-dump-b.bin"
        digest_a = dump_once(target, dump_a, chunk_size)
        digest_b = dump_once(target, dump_b, chunk_size)
        observed = sorted(set(transport.observed_vendor_cdbs))

    if dump_a.stat().st_size != FLASH_SIZE or dump_b.stat().st_size != FLASH_SIZE:
        raise SafetyError("one or both Flash dumps are not exactly 1 MiB")
    dumps_match = digest_a == digest_b and dump_a.read_bytes() == dump_b.read_bytes()
    sector_results = compare_recovery_sectors(dump_a, manifest)
    report = {
        "format": "smk37-wl82-readonly-dump-v1",
        "device_path": device_path,
        "identity": identity,
        "official_loader": {
            "size": len(loader),
            "sha256": sha256_bytes(loader),
            "ram_address": f"0x{LOADER_ADDRESS:08X}",
        },
        "loader_info": loader_info,
        "flash_size": FLASH_SIZE,
        "dump_a": {"file": dump_a.name, "sha256": digest_a},
        "dump_b": {"file": dump_b.name, "sha256": digest_b},
        "dumps_byte_identical": dumps_match,
        "sectors": sector_results,
        "read_only_acquisition_pass": dumps_match,
        "restore_authorized": False,
        "restore_blocker": (
            "FWSC flash.bin sector hashes are not directly comparable to "
            "a forced-loader dump until its returned representation is validated"
        ),
        "observed_vendor_cdbs": [f"0x{command:04X}" for command in observed],
    }
    (session / "readonly-report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (session / "SHA256SUMS.txt").write_text(
        f"{digest_a}  {dump_a.name}\n{digest_b}  {dump_b.name}\n", encoding="ascii"
    )
    LOG.info("dump A SHA-256: %s", digest_a)
    LOG.info("dump B SHA-256: %s", digest_b)
    print(
        json.dumps(
            {
                "session": str(session),
                "read_only_acquisition_pass": dumps_match,
                "restore_authorized": False,
            },
            indent=2,
        )
    )
    if not dumps_match:
        raise SafetyError("the two Flash dumps differ; preserve output and stop")
    print("PASS: two byte-identical 1 MiB forced-loader dumps were acquired")
    print("RESTORE BLOCKED: dump/package representation is not yet validated")
    return 0


class FakeTransport:
    def __init__(self, flash: bytes):
        self.flash = flash
        self.loader_running = False
        self.next_loader_address = LOADER_ADDRESS
        self.observed_vendor_cdbs: list[int] = []

    def close(self) -> None:
        pass

    def execute(
        self,
        cdb: bytes,
        *,
        data_out: bytes | None = None,
        data_in_length: int = 0,
    ) -> bytes:
        command = validate_transfer_contract(cdb, data_out, data_in_length)
        if command is None:
            response = bytearray(36)
            response[8:16] = b"WL82    "
            response[16:32] = b"UBOOT1.00       "
            response[32:36] = b"1.00"
            return bytes(response)

        self.observed_vendor_cdbs.append(command)
        if command == CMD_UBOOT_WRITE_MEMORY:
            assert data_out is not None
            assert int.from_bytes(cdb[2:6], "big") == self.next_loader_address
            assert len(data_out) == int.from_bytes(cdb[6:8], "big")
            assert cdb[8] == 0
            assert int.from_bytes(cdb[9:11], "little") == crc16_xmodem(data_out)
            self.next_loader_address += len(data_out)
            return b""
        if command == CMD_UBOOT_JUMP_MEMORY:
            assert int.from_bytes(cdb[2:6], "big") == LOADER_ADDRESS
            assert int.from_bytes(cdb[6:8], "big") == LOADER_ARGUMENT_SPI_NOR
            self.loader_running = True
            return command.to_bytes(2, "big") + b"\x00" * 14
        if not self.loader_running:
            raise AssertionError("loader command sent before RAM jump")
        if command == CMD_LOADER_GET_USB_BUFFER_SIZE:
            body = b"\x00" * 2 + (256).to_bytes(2, "big") + b"\x00" * 10
            return command.to_bytes(2, "big") + body
        if command == CMD_LOADER_GET_ONLINE_DEVICE:
            body = bytes([0x03, 0x00]) + (0x123456).to_bytes(4, "little") + b"\x00" * 8
            return command.to_bytes(2, "big") + body
        if command == CMD_LOADER_READ_ID:
            return command.to_bytes(2, "big") + b"\x85\x60\x14" + b"\x00" * 11
        if command == CMD_LOADER_READ_FLASH:
            address = int.from_bytes(cdb[2:6], "big")
            length = int.from_bytes(cdb[6:8], "big")
            assert length == data_in_length
            return self.flash[address : address + length]
        raise AssertionError(f"unhandled fake CDB 0x{command:04X}")


def self_test(optional_loader: Path | None) -> int:
    configure_logging()
    if crc16_xmodem(b"123456789") != 0x31C3:
        raise AssertionError("CRC16-XMODEM test vector failed")
    if ALLOWED_VENDOR_CDBS & FORBIDDEN_FLASH_MUTATING_CDBS:
        raise AssertionError("read-only allowlist overlaps a Flash-mutating CDB")
    try:
        build_vendor_cdb(0xFB01)
    except SafetyError:
        pass
    else:
        raise AssertionError("Flash-write CDB was not rejected")
    expected_cdb = b"\xFD\x05\x00\x01\x20\x00\x01\x00" + b"\xFF" * 8
    if build_vendor_cdb(CMD_LOADER_READ_FLASH, b"\x00\x01\x20\x00\x01\x00") != expected_cdb:
        raise AssertionError("vendor CDB encoding test failed")

    fake_loader = bytes(index & 0xFF for index in range(LOADER_BLOCK_SIZE * 2))
    fake_loader_hash = sha256_bytes(fake_loader)
    flash = bytes(((index * 17) ^ (index >> 8)) & 0xFF for index in range(FLASH_SIZE))
    fake = FakeTransport(flash)
    target = ReadOnlyWl82(fake)
    identity = target.inquiry()
    target.upload_official_loader(
        fake_loader,
        expected_size=len(fake_loader),
        expected_sha256=fake_loader_hash,
    )
    loader_info = target.loader_info()
    if identity["vendor"] != EXPECTED_VENDOR or loader_info["device_type"] != 0x03:
        raise AssertionError("fake identity/loader probe failed")

    manifest = {
        "format": "smk37-m09-forced-recovery-plan-v1",
        "sectors": [
            {
                "address": f"0x{address:05x}",
                "length": SECTOR_SIZE,
                "expected_m09_sha256": sha256_bytes(flash[address : address + SECTOR_SIZE]),
            }
            for address in sorted(EXPECTED_RECOVERY_SECTORS)
        ],
    }
    with tempfile.TemporaryDirectory(prefix="smk37-readonly-selftest-") as directory:
        root = Path(directory)
        dump_a = root / "a.bin"
        dump_b = root / "b.bin"
        digest_a = dump_once(target, dump_a, 256)
        digest_b = dump_once(target, dump_b, 256)
        if digest_a != digest_b or dump_a.read_bytes() != dump_b.read_bytes():
            raise AssertionError("double-dump equality test failed")
        sector_results = compare_recovery_sectors(dump_a, manifest)
        expected_dump = {
            item["address"]: sha256_bytes(
                flash[int(item["address"], 0) : int(item["address"], 0) + SECTOR_SIZE]
            )
            for item in manifest["sectors"]
        }
        if any(
            item["forced_loader_dump_sha256"] != expected_dump[item["address"]]
            for item in sector_results
        ):
            raise AssertionError("forced-loader sector evidence test failed")
        if any(item["representations_directly_comparable"] for item in sector_results):
            raise AssertionError("package/dump sector hashes were incorrectly marked comparable")

    with tempfile.TemporaryDirectory(prefix="smk37-evidence-selftest-") as directory:
        session = Path(directory) / "session"
        session.mkdir()
        evidence_fake = FakeTransport(flash)
        acquired = acquire_evidence(
            evidence_fake,
            fake_loader,
            session,
            expected_size=len(fake_loader),
            expected_sha256=fake_loader_hash,
        )
        if acquired["digest_a"] != acquired["digest_b"]:
            raise AssertionError("evidence double-dump digests differ")
        evidence_dump: Path = acquired["dump_a"]  # type: ignore[assignment]
        if evidence_dump.stat().st_size != FLASH_SIZE:
            raise AssertionError("evidence dump is not 1 MiB")
        if acquired["identity"]["vendor"] != EXPECTED_VENDOR:
            raise AssertionError("evidence path did not record identity")
        if set(evidence_fake.observed_vendor_cdbs) - ALLOWED_VENDOR_CDBS:
            raise AssertionError("evidence path observed a non-allowlisted CDB")
        if set(evidence_fake.observed_vendor_cdbs) & FORBIDDEN_FLASH_MUTATING_CDBS:
            raise AssertionError("evidence path observed a Flash-mutating CDB")
        # A comparison must be able to detect a difference and must not
        # claim anything about what may be written.
        altered = bytearray(flash)
        altered[0x4000] ^= 0xFF
        altered[0x9000 + 7] ^= 0x5A
        altered_path = Path(directory) / "altered.bin"
        altered_path.write_bytes(bytes(altered))
        comparison = compare_flash_images(
            evidence_dump, altered_path, "forced_loader_dump", "supplied_reference"
        )
        if comparison["differing_sector_count"] != 2:
            raise AssertionError("comparison did not detect both altered sectors")
        if comparison["identical_sector_count"] != FLASH_SIZE // SECTOR_SIZE - 2:
            raise AssertionError("comparison miscounted identical sectors")
        if "does not authorize" not in str(comparison["interpretation"]):
            raise AssertionError("comparison lost its no-authorization wording")
        if "write_list" in json.dumps(comparison):
            raise AssertionError("comparison unexpectedly carried a write list")
    if EVIDENCE_REPORT_FORMAT == "smk37-m09-forced-recovery-plan-v1":
        raise AssertionError("evidence report format collides with the M09 plan")
    # The M09 path must keep its manifest gate: dump without --manifest still
    # has to be rejected, so the new path cannot have weakened it.
    try:
        parse_args(
            [
                "dump",
                "--device",
                r"\\.\PHYSICALDRIVE5",
                "--loader",
                "loader.bin",
                "--output-root",
                "out",
            ]
        )
    except SystemExit:
        pass
    else:
        raise AssertionError("dump accepted a run without --manifest")
    if set(fake.observed_vendor_cdbs) - ALLOWED_VENDOR_CDBS:
        raise AssertionError("self-test observed a non-allowlisted CDB")
    if set(fake.observed_vendor_cdbs) & FORBIDDEN_FLASH_MUTATING_CDBS:
        raise AssertionError("self-test observed a Flash-mutating CDB")
    if optional_loader is not None:
        validate_official_loader(optional_loader.read_bytes())
        print(f"official loader validation PASS: {optional_loader}")
    print("self-test PASS: identity, RAM loader, double dump, manifest, CDB allowlist")
    print("evidence path PASS: manifest-free double dump, sector comparison, M09 gate intact")
    print("Flash-mutating CDB count: 0")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    self_parser = subparsers.add_parser("self-test", help="run without a USB device")
    self_parser.add_argument("--loader", type=Path)

    probe_parser = subparsers.add_parser("probe", help="send standard SCSI INQUIRY only")
    probe_parser.add_argument("--device", required=True)

    loader_parser = subparsers.add_parser(
        "loader-probe", help="run official loader from volatile RAM and query identity"
    )
    loader_parser.add_argument("--device", required=True)
    loader_parser.add_argument("--loader", required=True, type=Path)

    dump_parser = subparsers.add_parser(
        "dump", help="read the complete Flash twice; never erase or write Flash"
    )
    dump_parser.add_argument("--device", required=True)
    dump_parser.add_argument("--loader", required=True, type=Path)
    dump_parser.add_argument("--manifest", required=True, type=Path)
    dump_parser.add_argument("--output-root", required=True, type=Path)

    evidence_parser = subparsers.add_parser(
        "evidence-dump",
        help="read the complete Flash twice with no M09 manifest; evidence only",
    )
    evidence_parser.add_argument("--device", required=True)
    evidence_parser.add_argument("--loader", required=True, type=Path)
    evidence_parser.add_argument("--output-root", required=True, type=Path)
    evidence_parser.add_argument(
        "--compare",
        type=Path,
        default=None,
        help="optional 1 MiB image to diff against, e.g. a normal-mode dump",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.command == "self-test":
            return self_test(args.loader)
        if args.command == "probe":
            return run_probe(args.device)
        if args.command == "loader-probe":
            return run_loader_probe(args.device, args.loader)
        if args.command == "dump":
            return run_double_dump(
                args.device, args.loader, args.manifest, args.output_root
            )
        if args.command == "evidence-dump":
            return run_evidence_dump(
                args.device, args.loader, args.output_root, args.compare
            )
        raise AssertionError(f"unhandled command: {args.command}")
    except (SafetyError, OSError, json.JSONDecodeError) as error:
        print(f"SAFE STOP: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
