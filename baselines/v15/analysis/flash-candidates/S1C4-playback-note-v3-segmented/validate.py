#!/usr/bin/env python3
"""Offline validator for S1-C4 Playback Note v3 segmented-safe.

No device, USB, MIDI, OTA upload, flash, reset, or live send is opened.
"""
from __future__ import annotations
import hashlib, json, subprocess, sys, tempfile
from pathlib import Path
import build_s1c4_playback_note_v3 as b

HERE = Path(__file__).resolve().parent
PKG = b.PACKAGE_NAME

def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for c in iter(lambda: f.read(1024 * 1024), b''):
            h.update(c)
    return h.hexdigest()

def req(ok: bool, msg: str):
    if not ok:
        raise SystemExit('FAIL: ' + msg)

def run(args, expect=0):
    r = subprocess.run(args, cwd=HERE, text=True, capture_output=True, check=False)
    if r.returncode != expect:
        raise SystemExit('FAIL: command returned %d expected %d: %s\nstdout:\n%s\nstderr:\n%s' % (r.returncode, expect, ' '.join(map(str, args)), r.stdout, r.stderr))
    return r

def main() -> None:
    ev = b.build(check=True)
    appm = json.loads((HERE / 'app-manifest.json').read_text())
    pkgm = json.loads((HERE / 'package-manifest.json').read_text())
    code = json.loads((b.CODEDIR / 'evidence.json').read_text())
    req(ev['decision'] == 'PASS' and ev['candidate_built'] is True, 'release evidence PASS')
    req(ev['scope']['offline_only'] is True and ev['scope']['device_accessed'] is False and ev['scope']['midi_transport_opened'] is False, 'offline scope')
    req(shaf(HERE / 'app.bin') == ev['app']['output_app_sha256'], 'app hash matches evidence')
    req(shaf(HERE / PKG) == ev['package']['package_sha256'], 'package hash matches evidence')
    req(pkgm['output']['sha256'] == ev['package']['package_sha256'], 'package manifest output hash')
    req(ev['basis']['official_fwsc_sha256'] == b.EXPECTED['official_fwsc'], 'official FWSC hash pinned')
    req(ev['basis']['official_app_sha256'] == b.EXPECTED['official_app'], 'official app hash pinned')
    req(ev['basis']['parent_s1c3_app_sha256'] == b.EXPECTED['parent_app'], 'parent app hash pinned')
    req(ev['basis']['parent_s1c3_package_sha256'] == b.EXPECTED['parent_fwsc'], 'parent package hash pinned')

    app = (HERE / 'app.bin').read_bytes()
    req(app[b.off(b.NOFF_HOOK):b.off(b.NOFF_HOOK)+6].hex() == b.EXPECTED['noff_hook'], 'Note Off hook unchanged')
    req(app[b.off(b.NON_HOOK):b.off(b.NON_HOOK)+6].hex() == b.EXPECTED['non_hook'], 'Note On hook unchanged')
    req(app[b.off(b.NOFF_NEUT):b.off(b.NOFF_NEUT)+6].hex() == '001600160016', 'Note Off neutralization exact mov r0,r0 x3')
    req(app[b.off(b.NON_NEUT):b.off(b.NON_NEUT)+6].hex() == '001600160016', 'Note On neutralization exact mov r0,r0 x3')
    req(app[b.off(0x0201C68C):b.off(0x0201C68C)+2].hex() == '8d42', 'Note On velocity store preserved')
    req(app[b.off(b.DIRECT_RELOAD):b.off(b.DIRECT_RELOAD)+4].hex() == b.EXPECTED['direct_reload'], 'direct reload preserved')
    req(app[b.off(b.SEG_RELOAD):b.off(b.SEG_RELOAD)+4].hex() == b.EXPECTED['seg_reload'], 'segmented reload preserved')
    req(b.short_target(b.DIRECT_CALL, app[b.off(b.DIRECT_CALL):b.off(b.DIRECT_CALL)+4]) == int(code['producer']['reset_entry'], 16), 'direct product call target')
    req(b.short_target(b.SEG_CALL, app[b.off(b.SEG_CALL):b.off(b.SEG_CALL)+4]) == int(code['producer']['reset_entry'], 16), 'segmented final product call target')

    combined = app[b.off(b.SEL_START):b.off(b.OWNED_END)]
    req(hashlib.sha256(combined).hexdigest() == code['combined']['sha256'] == ev['code']['combined_sha256'], 'combined code slice hash')
    req(code['selector']['source_invariant'] == 'source slot = trigger_note - 36 only; Playback Note is metadata only', 'trigger source invariant')
    req(code['selector']['fail_closed_fallback'] is True, 'fallback keeps Trigger Note')
    req(code['selector']['playback_map_read_after_armed_and_valid'] is True, 'map read occurs only after ARMED and selected-slot valid')
    rows = [line.split('\t') for line in (b.CODEDIR / 'decode.tsv').read_text().splitlines()[1:] if line.strip()]
    order = {row[3]: index for index, row in enumerate(rows)}
    req(order['selector.default_note'] < order['selector.gate_state'] < order['selector.gate_valid'] < order['selector.load_playback_note'] < order['selector.select_source'], 'exact fail-closed selector ordering')
    req(order['selector.slot_index'] < order['selector.slot_offset_seed'] < order['selector.slot_offset'] < order['selector.valid_load'], 'trigger slot retained through selected-slot valid check')
    req(code['producer']['r9_length_gate_removed'] is True, 'r9 length gate removed')
    req(code['producer']['staging_restore_before_memcpy'] is True and code['producer']['slot_restore_before_valid'] is True, '0x9b restore proofs')
    req(code['producer']['armed_last_publishes_map'] is True, 'ARMED last publishes map')

    rb = json.loads((HERE / 'rollback/official-v15-recovery-sectors/manifest.json').read_text())
    req(rb['rollback_restores_official_flash'] is True, 'rollback manifest PASS')
    for item in rb['changed_sectors']:
        p = HERE / item['file']
        req(p.exists() and shaf(p) == item['sha256'], 'rollback sector ' + item['sector_base'])

    dry = json.loads(run([sys.executable, 'dry_run_validate.py', '--json']).stdout)
    req(dry['status'] == 'DRY_RUN_PASS' and dry['device_accessed'] is False and dry['midi_transport_opened'] is False, 'dry run PASS')
    man = json.loads((HERE / 'inputs/packets/packet-manifest.json').read_text())
    req(man['wire_playback_note_offset'] == 161 and man['payload_playback_note_offset'] == 0x9b, 'transport offsets')
    for i, item in enumerate(man['packets']):
        pkt = (HERE / 'inputs/packets' / item['file']).read_bytes()
        req(len(pkt) == 163 and pkt.startswith(b.HEADER) and pkt.endswith(b.TERM), f'packet {i} framing')
        req(pkt[161] == item['playback_note'] == item['trigger_note'], f'packet {i} default Original playback byte')
        req(item['template_byte_at_wire_offset'] == 0x3f and item['only_changed_wire_offsets_vs_template'] == [161], f'packet {i} template restore proof')

    with tempfile.TemporaryDirectory(prefix='s1c4-playback-validate-') as tmp:
        tmp = Path(tmp)
        pkg = subprocess.run(['pkg-config', '--cflags', '--libs', 'libusb-1.0'], text=True, capture_output=True, check=False)
        req(pkg.returncode == 0, 'pkg-config libusb-1.0 available')
        out = tmp / 'exact_ota'
        run(['cc','-O2','-g','-std=c11','-Wall','-Wextra','-Wpedantic','exact_ota.c','../../../../../src/device_info.c','../../../../../src/fwsc.c','../../../../../src/protocol.c','../../../../../src/sha256.c','../../../../../src/usb_probe.c','-o',str(out),*pkg.stdout.split()])
        run([str(out), 'check', PKG])
        reject = run([str(out), 'check', str(b.PARENT_FWSC)], expect=1)
        req('offline check rejected' in reject.stderr, 'exact OTA rejects parent')

    for line in (HERE / 'SHA256SUMS').read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith('*') else rel
        req((HERE / rel).exists(), 'SHA path exists ' + rel)
        req(shaf(HERE / rel) == digest, 'SHA inventory ' + rel)

    print('S1-C4 Playback Note v3 segmented-safe validation PASS: app_sha256=%s; package_sha256=%s; ota_confirmation_token=%s; sender_confirmation_token=%s; offline only' % (ev['app']['output_app_sha256'], ev['package']['package_sha256'], ev['flash']['confirmation_token'], ev['sender']['confirmation_token']))

if __name__ == '__main__':
    main()
