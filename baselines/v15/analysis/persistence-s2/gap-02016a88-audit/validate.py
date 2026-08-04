#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit('FAIL: ' + msg)

ev = json.loads((HERE / 'evidence.json').read_text())
req(ev['format'] == 'smk37-v15-s1c5-gap-02016a88-audit-v1', 'format')
req(ev['scope'] == {'device_accessed': False, 'flash_performed': False, 'fwsc_emitted': False, 'midi_transport_opened': False, 'offline_only': True, 'ota_performed': False}, 'offline-only scope')
req(ev['target_gap_bytes']['range'] == '0x02016a88..0x02016ce2', 'exact range')
req(ev['target_gap_bytes']['bytes'] == 602, 'exact byte count')
req(ev['target_gap_bytes']['sha256'] == '6553ba46b3a949db3774ccc60795500983313f5fa38b66e7bab173aee8b958c7', 'gap sha256')
req(ev['exact_s1c5_identity']['combined_selector_producer_tail']['preserved'] is True, 'S1C5 selector/producer preserved')
req(ev['ownership_and_executability']['decision'] == 'REFUTED_FOR_PROMOTION', 'ownership refuted')
req(ev['ownership_and_executability']['pre_gap_callsite']['address'] == '0x02016a84', 'pre-gap callsite')
req(ev['ownership_and_executability']['pre_gap_callsite']['text'] == 'call 0x0200ad74', 'pre-gap call target')
req(len(ev['ownership_and_executability']['callee_0x0200ad74_return_rows']) >= 3, 'callee normal returns')
req(ev['decision']['promoted'] is False and ev['decision']['minimal_manifest_restore_body_assembled'] is False, 'no body assembled')
req(len([g for g in ev['next_gaps_ge_300_bytes'] if g['bytes'] >= 300]) == 4, 'all gaps >=300 ranked')
req(ev['next_gaps_ge_300_bytes'][0]['range'] == '0x02016a88..0x02016ce2', 'target is largest listing gap')
print('PASS gap 0x02016a88 audit validation')
