#!/usr/bin/env python3
"""Pack, unpack, and validate Yamaha DX7 32-voice VMEM data."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


VMEM_VOICE_SIZE = 128
VCED_VOICE_SIZE = 155
RUNTIME_VOICE_SIZE = 156
SYSEX_HEADER = bytes.fromhex("f04300092000")


@dataclass(frozen=True)
class SysexBank:
    voices: tuple[bytes, ...]
    checksum: int


def yamaha_checksum(data: bytes) -> int:
    return (-sum(data)) & 0x7F


def parse_sysex_bank(data: bytes) -> SysexBank:
    if len(data) != 4104:
        raise ValueError("DX7 32-voice SysEx must be exactly 4104 bytes")
    if data[:6] != SYSEX_HEADER or data[-1] != 0xF7:
        raise ValueError("not a Yamaha DX7 32-voice VMEM message")
    body = data[6:-2]
    if yamaha_checksum(body) != data[-2]:
        raise ValueError("DX7 VMEM checksum mismatch")
    voices = tuple(
        body[offset:offset + VMEM_VOICE_SIZE]
        for offset in range(0, len(body), VMEM_VOICE_SIZE)
    )
    return SysexBank(voices=voices, checksum=data[-2])


def voice_name(packed: bytes) -> str:
    if len(packed) != VMEM_VOICE_SIZE:
        raise ValueError("packed DX7 voice must be 128 bytes")
    return packed[118:128].decode("ascii", "replace").rstrip()


def unpack_voice(packed: bytes, operator_mask: int = 0x3F) -> bytes:
    """Expand one 128-byte VMEM voice to the SMK/DX7 156-byte runtime form."""
    if len(packed) != VMEM_VOICE_SIZE:
        raise ValueError("packed DX7 voice must be 128 bytes")
    if not 0 <= operator_mask <= 0x3F:
        raise ValueError("operator mask must fit six bits")

    output = bytearray(RUNTIME_VOICE_SIZE)
    for operator in range(6):
        packed_offset = operator * 17
        unpacked_offset = operator * 21
        output[unpacked_offset:unpacked_offset + 11] = \
            packed[packed_offset:packed_offset + 11]
        curves = packed[packed_offset + 11]
        output[unpacked_offset + 11] = curves & 0x03
        output[unpacked_offset + 12] = (curves >> 2) & 0x03
        detune_rate = packed[packed_offset + 12]
        output[unpacked_offset + 13] = detune_rate & 0x07
        velocity_amp = packed[packed_offset + 13]
        output[unpacked_offset + 14] = velocity_amp & 0x03
        output[unpacked_offset + 15] = (velocity_amp >> 2) & 0x07
        output[unpacked_offset + 16] = packed[packed_offset + 14]
        coarse_mode = packed[packed_offset + 15]
        output[unpacked_offset + 17] = coarse_mode & 0x01
        output[unpacked_offset + 18] = (coarse_mode >> 1) & 0x1F
        output[unpacked_offset + 19] = packed[packed_offset + 16]
        output[unpacked_offset + 20] = (detune_rate >> 3) & 0x0F

    output[126:135] = packed[102:111]
    feedback_sync = packed[111]
    output[135] = feedback_sync & 0x07
    output[136] = (feedback_sync >> 3) & 0x01
    output[137:141] = packed[112:116]
    lfo = packed[116]
    output[141] = lfo & 0x01
    output[142] = (lfo >> 1) & 0x07
    output[143] = (lfo >> 4) & 0x07
    output[144] = packed[117]
    output[145:155] = packed[118:128]
    output[155] = operator_mask
    return bytes(output)


def pack_voice(unpacked: bytes) -> bytes:
    """Pack the first 155 bytes of a runtime/VCED voice back to VMEM."""
    if len(unpacked) not in (VCED_VOICE_SIZE, RUNTIME_VOICE_SIZE):
        raise ValueError("unpacked DX7 voice must be 155 or 156 bytes")
    output = bytearray(VMEM_VOICE_SIZE)
    for operator in range(6):
        packed_offset = operator * 17
        unpacked_offset = operator * 21
        output[packed_offset:packed_offset + 11] = \
            unpacked[unpacked_offset:unpacked_offset + 11]
        output[packed_offset + 11] = (
            (unpacked[unpacked_offset + 11] & 0x03)
            | ((unpacked[unpacked_offset + 12] & 0x03) << 2)
        )
        output[packed_offset + 12] = (
            (unpacked[unpacked_offset + 13] & 0x07)
            | ((unpacked[unpacked_offset + 20] & 0x0F) << 3)
        )
        output[packed_offset + 13] = (
            (unpacked[unpacked_offset + 14] & 0x03)
            | ((unpacked[unpacked_offset + 15] & 0x07) << 2)
        )
        output[packed_offset + 14] = unpacked[unpacked_offset + 16]
        output[packed_offset + 15] = (
            (unpacked[unpacked_offset + 17] & 0x01)
            | ((unpacked[unpacked_offset + 18] & 0x1F) << 1)
        )
        output[packed_offset + 16] = unpacked[unpacked_offset + 19]

    output[102:111] = unpacked[126:135]
    output[111] = (unpacked[135] & 0x07) | ((unpacked[136] & 0x01) << 3)
    output[112:116] = unpacked[137:141]
    output[116] = (
        (unpacked[141] & 0x01)
        | ((unpacked[142] & 0x07) << 1)
        | ((unpacked[143] & 0x07) << 4)
    )
    output[117] = unpacked[144]
    output[118:128] = unpacked[145:155]
    return bytes(output)


def self_test() -> None:
    fixture = bytes((index * 17 + 3) & 0x7F for index in range(128))
    # Constrain packed bit fields to the values VMEM actually stores.
    mutable = bytearray(fixture)
    for operator in range(6):
        offset = operator * 17
        mutable[offset + 11] &= 0x0F
        mutable[offset + 12] &= 0x7F
        mutable[offset + 13] &= 0x1F
        mutable[offset + 15] &= 0x3F
    mutable[110] &= 0x1F
    mutable[111] &= 0x0F
    mutable[116] &= 0x7F
    packed = bytes(mutable)
    if pack_voice(unpack_voice(packed)) != packed:
        raise AssertionError("DX7 VMEM pack/unpack round trip failed")


if __name__ == "__main__":
    self_test()
    for argument in __import__("sys").argv[1:]:
        path = Path(argument)
        bank = parse_sysex_bank(path.read_bytes())
        print(path)
        for index, voice in enumerate(bank.voices):
            print(f"{index:02d} {voice_name(voice)}")
