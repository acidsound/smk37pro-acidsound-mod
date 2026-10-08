#!/usr/bin/env python3
import json, pathlib, hashlib, re
root=pathlib.Path(__file__).resolve().parent
repo=root.parents[3]
obj=json.loads((root/'memory-map.json').read_text())
req={'id','section','start','end_exclusive','size','type_owner','evidence_confidence','mutability_patch_policy','source_artifacts'}
sections={'live_validated','static_proven','inferred','refuted','unknown'}
conf={'PROVEN','OBSERVED','INFERRED','BLOCKED'}
ids=set()
for row in obj['rows']:
    missing=req-set(row)
    assert not missing, (row.get('id'), missing)
    assert row['id'] not in ids; ids.add(row['id'])
    assert row['section'] in sections, row
    assert row['evidence_confidence'] in conf, row
    if isinstance(row['start'],str) and row['start'].startswith('0x') and isinstance(row['end_exclusive'],str) and row['end_exclusive'].startswith('0x'):
        assert row['size']==int(row['end_exclusive'],16)-int(row['start'],16), row
        assert row['size']>=0, row
    assert row['source_artifacts'], row
    for s in row['source_artifacts']:
        assert (repo/s).exists(), f'missing source {s}'
text=(root/'README.md').read_text()
for phrase in ['No v12 evidence','Live Validated','Static Proven','Refuted','Unknown','physical Flash/package/JLFS/user tail','global RAM 0x01c33260 object offsets','owned S1C5 16-slot RAM']:
    assert phrase in text, phrase
print(f'PASS rows={len(obj["rows"])} sha256={hashlib.sha256((root/"memory-map.json").read_bytes()).hexdigest()}')
