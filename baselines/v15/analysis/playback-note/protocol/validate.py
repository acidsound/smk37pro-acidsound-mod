#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
HERE = Path(__file__).resolve().parent
DESIGN = HERE / 'protocol-design.json'

def fail(msg: str) -> None:
    raise SystemExit(f'FAIL\t{msg}')

def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xffff
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xffff
            else:
                crc = (crc << 1) & 0xffff
    return crc

def dec3(chunks: list[int]) -> int:
    if len(chunks) != 3:
        fail('expected three 7-bit chunks')
    if any((x < 0 or x >= 0x80) for x in chunks[:2]) or chunks[2] >= 4:
        fail(f'invalid 3x7 chunks {chunks!r}')
    return chunks[0] | (chunks[1] << 7) | (chunks[2] << 14)

def check(cond: bool, msg: str) -> None:
    if not cond:
        fail(msg)
    print(f'PASS\t{msg}')

def main() -> None:
    d = json.loads(DESIGN.read_text())
    check(d['scope']['offline_only'] is True, 'offline-only scope')
    for k in ['device_accessed','flash_performed','ota_performed','reset_performed','midi_transport_opened','firmware_package_built']:
        check(d['scope'][k] is False, f'{k}=false')

    for name, rec in d['basis']['artifacts'].items():
        p = ROOT / rec['path']
        check(p.exists(), f'artifact exists {name}')
        check(sha256_path(p) == rec['sha256'], f'artifact sha256 {name}')

    ram = d['current_ram_layout']
    base = int(ram['owned_reservation']['range'].split('..')[0], 16)
    end = int(ram['owned_reservation']['range'].split('..')[1], 16)
    check(end - base == 0x0a90, 'owned reservation is 0x0a90')
    h0, h1 = [int(x,16) for x in ram['header_map_area']['range'].split('..')]
    check(h1 - h0 == 0x90, 'header/map area is 0x90')
    check(base <= h0 < h1 <= end, 'header/map area inside owned reservation')
    check(ram['ram_boundary_expansion_required_for_protocol'] is False, 'no RAM boundary expansion required')

    ex = d['current_executable_placement']
    check(ex['producer']['reported_spare_bytes'] == 4, 'producer reported spare bytes is 4')
    check(ex['selector']['padding_bytes'] == 24, 'selector padding bytes is 24')
    check(ex['byte_budget_decision'].startswith('BLOCK'), 'byte budget blocks implementation candidate')
    check(d['ownership_abi_gate_summary']['firmware_candidate_constructed'] is False, 'no firmware candidate constructed')

    frame = bytes.fromhex(d['proposed_protocol']['original_semantics']['all_original_frame_hex'])
    check(len(frame) == 0xa3, 'all-Original frame length 0xa3')
    check(frame[:6] == bytes([0xf0,0x43,0,0,1,0x1b]), 'outer direct-product header')
    check(frame[-1] == 0xf7, 'terminal F7')
    payload = frame[6:-1]
    check(len(payload) == 0x9c, 'payload length 0x9c')
    check(all(b < 0x80 for b in payload), 'all payload bytes are seven-bit')
    check(payload[:6] == b'SMKPN1', 'SMKPN1 magic')
    check(payload[6] == 1 and payload[7] == 0x10 and payload[8] == 0 and payload[9] == 16, 'version/cmd/flags/count')
    original_mask = dec3(list(payload[10:13]))
    check(original_mask == 0xffff, 'all-original mask decodes to 0xffff')
    check(payload[13:29] == bytes(16), 'all-original note bytes are zero')
    crc_expect = crc16_ccitt_false(payload[:29])
    crc_actual = dec3(list(payload[29:32]))
    check(crc_actual == crc_expect, 'CRC-16/CCITT-FALSE matches')
    check(payload[32:] == bytes(124), 'padding zero')
    check(hashlib.sha256(frame).hexdigest() == d['proposed_protocol']['original_semantics']['all_original_frame_sha256'], 'frame sha256 recorded')

    effective = [36+i if (original_mask >> i) & 1 else payload[13+i] for i in range(16)]
    check(effective == list(range(36,52)), 'all-original effective notes are 36..51')
    check(len(set(effective)) == 16, 'all-original effective notes distinct')
    print('PLAYBACK_NOTE_PROTOCOL_VALIDATION_PASS')

if __name__ == '__main__':
    main()
