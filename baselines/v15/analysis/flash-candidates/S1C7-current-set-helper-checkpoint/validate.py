#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, subprocess, sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG='SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc'

def sha(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()
def req(ok: bool, msg: str) -> None:
    if not ok: raise SystemExit('FAIL: '+msg)

def main() -> None:
    ev=json.loads((HERE/'evidence.json').read_text())
    req(ev['decision']=='PASS_CURRENT_SET_CHECKPOINT','release decision')
    req(ev['scope']['device_accessed'] is False and ev['scope']['ota_performed'] is False,'offline scope')
    req(sha(HERE/'app.bin')==ev['app']['output_app_sha256'],'app hash')
    req(sha(HERE/PKG)==ev['package']['package_sha256'],'package hash')
    code=json.loads((HERE/'code-evidence'/'evidence.json').read_text())['code']
    req(code['helper']['start']=='0x02026d80' and code['helper']['end_exclusive']=='0x02026dd4','helper region exact')
    req(code['helper']['uses_read_wrapper']=='0x02004870','read wrapper used')
    req(code['save_ui_skip']['bytes']=='04ac00160016','SAVE UI skip exact')
    req(code['producer']['status'].startswith('preserved byte-for-byte'),'producer preserved')
    seed=json.loads((HERE/'host-seeded-records'/'prefix-manifest.json').read_text())
    req(seed['requires_exact_host_seeded_records'] is True and seed['payload_record_count']==16,'seed manifest')
    for r in seed['records']:
        p=HERE/'host-seeded-records'/r['prefix_file']
        b=p.read_bytes()
        req(len(b)==0x9c, f"prefix size {p.name}")
        req(hashlib.sha256(b).hexdigest()==r['prefix_sha256'], f"prefix hash {p.name}")
        req(r['tail_policy'].startswith('preserve live raw bytes'), f"tail policy {p.name}")
    rb=json.loads((HERE/'rollback'/'official-v15-recovery-sectors'/'manifest.json').read_text())
    req(rb['rollback_restores_official_flash'] is True and rb['changed_sectors'],'rollback manifest')
    subprocess.run([sys.executable, str(HERE/'build_s1c7_current_set_helper_checkpoint.py'), '--check'], check=True)
    print('S1-C7 offline validator PASS: app/FWSC/helper/seed/rollback artifacts are deterministic and device-free')
if __name__=='__main__': main()
