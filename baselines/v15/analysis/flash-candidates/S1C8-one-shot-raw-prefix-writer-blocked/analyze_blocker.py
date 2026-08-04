#!/usr/bin/env python3
import hashlib, json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[5]
S1C7 = ROOT/'baselines/v15/analysis/flash-candidates/S1C7-current-set-helper-checkpoint'
S1C6 = ROOT/'baselines/v15/analysis/flash-candidates/S1C6-raw17-persistence-block/evidence.json'
STORAGE = ROOT/'baselines/v15/analysis/persistence-s2/storage/evidence.json'

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    prefixes = sorted((S1C7/'host-seeded-records').glob('record-*-slot-*.prefix'))
    assert len(prefixes) == 16
    sizes = [p.stat().st_size for p in prefixes]
    assert sizes == [0x9c]*16, sizes
    prefix_hashes = {p.name: sha(p) for p in prefixes}
    s1c6 = json.loads(S1C6.read_text())
    storage = json.loads(STORAGE.read_text())
    out = {
        'decision': 'BLOCK',
        'candidate_built': False,
        'reason': 'No defensible flashable normal-firmware or one-shot writer can be emitted from current exact v15/S1C5/S1C7 evidence without adding unproven executable/data placement or dropping mandatory checks.',
        'current_exact_inputs': {
            's1c7_app_sha256': sha(S1C7/'app.bin'),
            's1c7_fwsc_sha256': sha(S1C7/'SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc'),
            's1c7_package_manifest_sha256': sha(S1C7/'package-manifest.json'),
            'prefix_record_indices': list(range(96,112)),
            'prefix_size_each': 0x9c,
            'prefix_total_payload_bytes': sum(sizes),
            'prefix_hashes': prefix_hashes,
        },
        'required_abi': {
            'write_wrapper': {'address':'0x02004b02','success':'return == requested length','short_or_failed':'0'},
            'read_wrapper': {'address':'0x02004870','success':'return == requested length','short_or_failed':'0'},
            'write_records': [{'record':96+i,'storage_offset':hex(0x7d20+i*0xa3),'length':0x9c} for i in range(16)],
        },
        'blocker_evidence': {
            's1c5_owned_window': s1c6['fit_evidence']['available_windows']['s1c5_owned_window'],
            'save_no_write_dead_slice': s1c6['fit_evidence']['available_windows']['save_no_write_dead_slice'],
            'mandatory_extras': s1c6['fit_evidence']['defensible_writer_required_extras'],
            'direct_only_fit_is_insufficient': s1c6['fit_evidence']['compact_successor_fit_after_boar_dm'],
            'one_shot_embedded_prefix_data_bytes_needed': sum(sizes),
            'minimum_loop_body_not_counting_embedded_data': 'At least one checked 0x02004b02 write plus one 0x02004870 readback/compare path per record, and a success/failure state. Current exact evidence has no reviewed cave for 2496 bytes of constants plus code.',
        },
        'preservation_statement': 'No S1C5/S1C7 app, WebMIDI producer, playback, FWSC, exact OTA, or rollback artifact is modified by this blocker package.',
        'allowed_successor_conditions': [
            'A reviewed executable/data cave or relocation plan large enough for 2496 exact prefix bytes plus checked writer/readback code.',
            'Full-length equality checks for all 16 calls to 0x02004b02.',
            '0x02004870 readback of every written 0x9c prefix and byte equality validation against the exact source bytes.',
            'Commit-last or equivalent failure state semantics that avoid forced recovery and do not misreport partial writes as success.',
            'Deterministic app/FWSC/exact OTA/rollback validators built from only exact v15/S1C5/S1C7 evidence.'
        ]
    }
    Path('evidence.json').write_text(json.dumps(out, indent=2, sort_keys=True)+'\n')
    Path('validation.txt').write_text('PASS analyze_blocker.py: current exact evidence blocks a flashable checked one-shot writer; no firmware artifacts emitted.\n')
    with open('SHA256SUMS','w') as f:
        for name in ['analyze_blocker.py','evidence.json','report.md','validation.txt']:
            p=Path(name)
            if p.exists(): f.write(f'{sha(p)}  {name}\n')

if __name__ == '__main__': main()
