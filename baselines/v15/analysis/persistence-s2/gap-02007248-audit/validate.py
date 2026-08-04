#!/usr/bin/env python3
from __future__ import annotations
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit('FAIL: ' + msg)

ev = json.loads((HERE / 'evidence.json').read_text())
req(ev['format'] == 'smk37-v15-s1c5-gap-02007248-audit-v1', 'format')
req(ev['scope'] == {'device_accessed': False, 'flash_performed': False, 'fwsc_emitted': False, 'midi_transport_opened': False, 'offline_only': True, 'ota_performed': False}, 'offline-only scope')
req(ev['target_gap_bytes']['range'] == '0x02007248..0x02007390', 'exact range')
req(ev['target_gap_bytes']['bytes'] == 328, 'exact byte count')
req(ev['target_gap_bytes']['sha256'] == '0f91e6223173e3fb01f63f0de60f58fe5cfe251dfedaebb81769c0b3bc580b66', 'gap sha256')
req(ev['exact_s1c5_identity']['combined_selector_producer_tail']['preserved'] is True, 'S1C5 selector/producer preserved')
req(ev['ownership_and_executability']['decision'] == 'REFUTED_FOR_PROMOTION', 'ownership refuted')
req(ev['ownership_and_executability']['quarkslab_gap_rows_inside'] == 0, 'quark exhaustive hole')
req(ev['ownership_and_executability']['quarkslab_recursive_gap_rows_inside'] == 133, 'recursive decode rows')
req(ev['ownership_and_executability']['kagaimiq_patched_gap_rows_inside'] == 122, 'kagaimiq decode rows')
req(ev['function_data_boundary_evidence']['pre_gap_quarkslab_exhaustive_callsite']['address'] == '0x02007242', 'pre-gap callsite')
req(ev['function_data_boundary_evidence']['pre_gap_quarkslab_exhaustive_callsite']['text'] == 'call 0x02063260', 'pre-gap call target')
req(len(ev['ownership_and_executability']['direct_text_xrefs_into_gap']['quarkslab_recursive_all']) == 26, 'recursive internal branch reach')
req(len(ev['ownership_and_executability']['direct_text_xrefs_into_gap']['kagaimiq_patched_exhaustive_all']) == 19, 'kagaimiq internal branch reach')
req(ev['ownership_and_executability']['raw_pointer_xrefs_into_gap']['count'] == 1, 'raw pointer hit count')
req(ev['decision']['promoted'] is False and ev['decision']['minimal_manifest_restore_body_assembled'] is False, 'no body assembled')
req(any(g['requested_target'] and g['bytes'] == 328 for g in ev['related_exhaustive_listing_gaps_ge_300_bytes']), 'target gap ranked')
print('PASS gap 0x02007248 audit validation')
