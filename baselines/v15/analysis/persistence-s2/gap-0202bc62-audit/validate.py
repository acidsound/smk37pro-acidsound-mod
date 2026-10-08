#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = json.loads((HERE / "evidence.json").read_text())

assert EVIDENCE["format"] == "smk37-v15-s1c5-gap-0202bc62-audit-v1"
assert EVIDENCE["scope"] == {
    "offline_only": True,
    "device_accessed": False,
    "midi_transport_opened": False,
    "flash_performed": False,
    "ota_performed": False,
    "fwsc_emitted": False,
}
assert EVIDENCE["target_gap_bytes"]["range"] == "0x0202bc62..0x0202be5a"
assert EVIDENCE["target_gap_bytes"]["bytes"] == 504
assert EVIDENCE["target_gap_bytes"]["sha256"] == "0c5ce1e1b9c0bb13cec4e5b076a70d73ae3fdf0de5d73833d8cb29015338aa2e"
assert EVIDENCE["exact_s1c5_identity"]["combined_selector_producer_tail"]["sha256"] == "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1"
assert EVIDENCE["ownership_and_executability"]["quarkslab_gap_rows_inside"] == 0
assert EVIDENCE["ownership_and_executability"]["quarkslab_recursive_gap_rows_inside"] == 164
assert EVIDENCE["ownership_and_executability"]["kagaimiq_patched_gap_rows_inside"] == 126
assert EVIDENCE["ownership_and_executability"]["raw_pointer_xrefs_into_gap"]["count"] == 0
assert len(EVIDENCE["branch_reach_and_boundaries"]["entry_xrefs"]["quarkslab_exhaustive"]) >= 3
assert EVIDENCE["decision"] == {
    "result": "REFUTE_PROMOTION",
    "promoted": False,
    "minimal_manifest_restore_body_assembled": False,
    "reason": "No manifest-gated restore body is assembled because the requested 504-byte interval is reachable executable body inside FUN_0202bc22. Overwriting it would corrupt live code while exact S1C5 selector/producer must remain preserved.",
}
print("PASS gap 0x0202bc62 audit evidence validation")
