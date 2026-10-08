#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent

def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit('FAIL: ' + msg)


ev = json.loads((HERE / 'evidence.json').read_text())
req(ev['scope'] == {'offline_only': True, 'device_accessed': False, 'midi_transport_opened': False, 'flash_performed': False, 'ota_performed': False, 'fwsc_emitted': False}, 'offline/no-device scope')
req(ev['target_gap_bytes']['range'] == '0x02039be6..0x02039e2a', 'exact range')
req(ev['target_gap_bytes']['bytes'] == 580, 'exact length')
req(ev['target_gap_bytes']['sha256'] == 'a1825cf3261b2ce8fd20f820bcd4a843b36e2f290b97be1e0e078b652efe5bfe', 'gap sha')
req(hashlib.sha256((HERE / 'gap-02039be6.bin').read_bytes()).hexdigest() == ev['target_gap_bytes']['sha256'], 'gap bin sha')
own = ev['ownership_and_executability']
req(ev['decision']['result'] == 'REFUTE_PROMOTION' and not ev['decision']['promoted'], 'refute decision')
req(own['quarkslab_gap_rows_inside'] == 0, 'exhaustive gap source')
req(own['quarkslab_recursive_gap_rows_inside'] >= 180, 'recursive rows')
req(own['kagaimiq_patched_gap_rows_inside'] >= 130, 'kagaimiq rows')
req(any(e['target'] == '0x02039be6' for e in own['branch_table_reach']['entries']), 'TBH reaches gap start')
req(len(own['direct_text_xrefs_into_gap']['quarkslab_recursive']) >= 20, 'recursive xrefs')
req(own['raw_pointer_xrefs_into_gap']['count'] == 0, 'raw pointer count')
req(ev['exact_s1c5_identity']['combined_selector_producer_tail']['preserved'] is True, 'exact S1C5 preserved')
print('PASS validate gap-02039be6 audit refutation artifacts')
