#!/usr/bin/env python3
"""Official-v15-only R03 owned-RAM copy-path gate.

Read-only: consumes the official v15 app/package and existing official-v15
Quarkslab/Kagaimiq listings. It emits a design/evidence report and never
patches, flashes, or accesses a device.
"""
from __future__ import annotations
import csv, gzip, hashlib, json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
APP = ROOT / 'build/v15-official-app.bin'
FWSC = ROOT / 'build/SMK-37_Pro_015.fwsc'
MANIFEST = ROOT / 'baselines/v15/official/package-manifest.json'
Q = ROOT / 'baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz'
K = ROOT / 'baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz'
EXPECTED = {
    'app':'36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055',
    'fwsc':'f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff',
    'quark':'f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347',
    'kaga':'814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013',
}
STAGE_BASE, STAGE_OFF = 0x01c37030, 0x0fa0
STAGE = STAGE_BASE + STAGE_OFF
OBJ, CURRENT = 0x01c33260, 0x01c33260 + 0x1a14
VOICE_LEN = 0x9c
ADDR = {'memcpy':0x02048cce,'packer':0x0201e13e,'loader':0x02005660,'dispatcher':0x0201c5ec}
REQ = {
    0x0201e3ee:'lb.z r0,[r7 + 0x206]', 0x0201e3f2:'je r0,#0x0,0x0201e648',
    0x0201e3f8:'lb.z r0,[r7 + 0x104]', 0x0201e3fc:'mov r6,#0x1c37030',
    0x0201e402:'je r0,0x2,0x0201e472', 0x0201e406:'je r0,0x1,0x0201e4a6',
    0x0201e40a:'jne r0,#0x0,0x0201e606', 0x0201e410:'jne r0,#0xf0',
    0x0201e416:'jne r0,#0x43,0x0201e606', 0x0201e432:'jne r0,#0x0,0x0201e606',
    0x0201e438:'jne r0,#0x0,0x0201e606', 0x0201e43e:'jne r0,#0x1,0x0201e606',
    0x0201e444:'jne r0,#0x1b,0x0201e606', 0x0201e448:'add r8,r6,#0xfa0',
    0x0201e44c:'add r1,r4,#0x6', 0x0201e44e:'add r6,r9,#-0x6',
    0x0201e452:'mov r0,r8', 0x0201e454:'mov r2,r6', 0x0201e456:'call 0x02048cce',
    0x0201e45c:'add r0,r4,r9', 0x0201e462:'jne r0,#0xf7', 0x0201e466:'mov r0,r8',
    0x0201e468:'call 0x0201e13e', 0x0201e46c:'call 0x02005660', 0x0201e470:'pop {pc,r9,r8,r7,r6,r5,r4}',
    0x0201e472:'lh.z r0,[r7 + 0x9c]', 0x0201e480:'jne r1,#0xf7', 0x0201e484:'jne r5,#0x9e',
    0x0201e488:'add r6,r6,#0xfa0', 0x0201e48c:'add r0,r6', 0x0201e48e:'add r2,r9,#-0x2',
    0x0201e492:'mov r1,r4', 0x0201e494:'call 0x02048cce', 0x0201e49a:'mov r0,r6',
    0x0201e49c:'call 0x0201e13e', 0x0201e4a0:'call 0x02005660', 0x0201e4a4:'goto 0x0201e538',
    0x0201e4ce:'call 0x02048cce', 0x0201e52c:'call 0x02048cce', 0x0201e580:'add r0,r6,#0xfa0',
    0x0201e58c:'call 0x02048cce', 0x0201e592:'sh r4,[r7 + 0x9c]',
    0x0201e13e:'push {rets,r6,r5,r4}', 0x0201e140:'add sp,#-0x80', 0x0201e216:'mov r4,#0x1c33260',
    0x0201e232:'mov r2,#0x80', 0x0201e234:'mov r0,r3', 0x0201e236:'call 0x02004b02',
    0x0201e250:'add sp,#0x80', 0x0201e252:'pop {pc,r6,r5,r4}',
    0x02026d9e:'add r4,r8,0x1a14', 0x02026da2:'mov r2,#0xa3', 0x02026da4:'mov r0,r4',
    0x02026da6:'call 0x02004b02', 0x02026daa:'mov r0,r4', 0x02026dac:'call 0x0201e13e',
    0x0201c5ec:'push {rets,r10,r9,r8,r7,r6,r5,r4}', 0x0201c5ee:'lb.z r3,[r1 + 0x0]',
    0x0201c5f0:'lsr r4,r3,0x4', 0x0201c5fe:'and r9,r3,#0xffffff0f', 0x0201c602:'mov r8,#0x1c34c74',
    0x0201c616:'jl r2,#0x3,0x0201c710', 0x0201c62a:'and r2,r4,#0xffffff0f',
    0x0201c630:'mul r1,r2,#0xa0', 0x0201c636:'add r0,r6,#0xa2', 0x0201c63a:'mov r2,#0x9c',
    0x0201c63c:'mov r1,r8', 0x0201c63e:'call 0x02048cce', 0x0201c644:'add r0,r6,#0x13e',
    0x0201c652:'jl r2,#0x3,0x0201c710', 0x0201c666:'and r2,r4,#0xffffff0f',
    0x0201c66c:'mul r1,r2,#0xa0', 0x0201c674:'add r0,r7,#0xa2', 0x0201c678:'mov r2,#0x9c',
    0x0201c67a:'mov r1,r8', 0x0201c67c:'call 0x02048cce', 0x0201c682:'add r0,r7,#0x13e',
    0x0201c698:'pop {pc,r10,r9,r8,r7,r6,r5,r4}',
}
PATHS = {
 'direct_complete_accept':[0x0201e3ee,0x0201e3f2,0x0201e3f8,0x0201e3fc,0x0201e402,0x0201e406,0x0201e40a,0x0201e410,0x0201e416,0x0201e432,0x0201e438,0x0201e43e,0x0201e444,0x0201e448,0x0201e44c,0x0201e44e,0x0201e452,0x0201e454,0x0201e456,0x0201e45c,0x0201e462,0x0201e466,0x0201e468,0x0201e46c,0x0201e470],
 'segmented_final_accept':[0x0201e472,0x0201e480,0x0201e484,0x0201e488,0x0201e48c,0x0201e48e,0x0201e492,0x0201e494,0x0201e49a,0x0201e49c,0x0201e4a0,0x0201e4a4],
 'other_stage_overwrites':[0x0201e4ce,0x0201e52c,0x0201e580,0x0201e58c,0x0201e592],
 'packer_sink':[0x0201e13e,0x0201e140,0x0201e216,0x0201e232,0x0201e234,0x0201e236,0x0201e250,0x0201e252],
 'save_packer_caller':[0x02026d9e,0x02026da2,0x02026da4,0x02026da6,0x02026daa,0x02026dac],
 'note_off_copy':[0x0201c5ec,0x0201c5ee,0x0201c5f0,0x0201c5fe,0x0201c602,0x0201c616,0x0201c62a,0x0201c630,0x0201c636,0x0201c63a,0x0201c63c,0x0201c63e,0x0201c644],
 'note_on_copy':[0x0201c5ec,0x0201c5ee,0x0201c5f0,0x0201c5fe,0x0201c602,0x0201c652,0x0201c666,0x0201c66c,0x0201c674,0x0201c678,0x0201c67a,0x0201c67c,0x0201c682,0x0201c698],
}

def sha(p:Path)->str:
    h=hashlib.sha256();
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1<<20), b''): h.update(b)
    return h.hexdigest()
def hx(x:int)->str: return f'0x{x:08x}'
def rows(path:Path):
    with gzip.open(path,'rt',errors='replace',newline='') as f: return list(csv.DictReader(f,delimiter='\t'))
def addr(r): return int(r['address'],16)
def out(r): return {k:r[k] for k in ['address','bytes','mnemonic','text','flow_type','function']}
def line(r): return '\t'.join(r[k] for k in ['address','bytes','mnemonic','text','flow_type','function'])
def calls(rs,target):
    n=hx(target); return [out(r) for r in rs if r['mnemonic']=='call' and n in r['text'].lower()]
def blen(r): return len(r['bytes'])//2

def build():
    rs=rows(Q); by={addr(r):r for r in rs}
    ev:dict[str,Any]={
      'scope':{'inputs':[str(APP.relative_to(ROOT)),str(FWSC.relative_to(ROOT)),str(Q.relative_to(ROOT)),str(K.relative_to(ROOT))], 'constraints':['official v15 only','read-only','no patch','no flash','no device access','no boot hooks','no guessed cave/address']},
      'sha256':{'app':sha(APP),'fwsc':sha(FWSC),'quark':sha(Q),'kaga':sha(K)},
      'constants':{'stage_base':hx(STAGE_BASE),'stage_offset':hex(STAGE_OFF),'stage':hx(STAGE),'voice_len':hex(VOICE_LEN),'obj_base':hx(OBJ),'stock_current':hx(CURRENT)},
      'paths':{n:[out(by[a]) for a in aa] for n,aa in PATHS.items()},
      'call_xrefs':{hx(v):calls(rs,v) for v in ADDR.values()},
      'budgets':{hx(a):{'bytes':by[a]['bytes'],'size':blen(by[a]),'text':by[a]['text']} for a in [0x0201e468,0x0201e49c,0x0201c63e,0x0201c67c]},
      'decision':{'status':'BLOCK','summary':'Post-accept producer shape is identifiable, but owned RAM and executable placement are not proven.'},
    }
    checks=[]
    def ck(n,c,d): checks.append({'status':'PASS' if c else 'FAIL','name':n,'detail':d})
    man=json.loads(MANIFEST.read_text())
    for key,path in [('app',APP),('fwsc',FWSC),('quark',Q),('kaga',K)]: ck(f'sha256-{key}',ev['sha256'][key]==EXPECTED[key],ev['sha256'][key])
    ck('manifest-app',man.get('app_sha256')==EXPECTED['app'],str(man.get('app_sha256')))
    ck('manifest-package',man.get('package_sha256')==EXPECTED['fwsc'],str(man.get('package_sha256')))
    ck('official-v15-only',all('v12' not in p.lower() and 'r02' not in p.lower() for p in ev['scope']['inputs']),json.dumps(ev['scope']['inputs']))
    ck('stage-arithmetic',STAGE==0x01c37fd0,f'{hx(STAGE_BASE)}+0x{STAGE_OFF:x}={hx(STAGE)}')
    ck('current-arithmetic',CURRENT==0x01c34c74,f'{hx(OBJ)}+0x1a14={hx(CURRENT)}')
    for a,t in REQ.items(): ck(f'row-{hx(a)}',a in by and t in by[a]['text'],by[a]['text'] if a in by else 'missing')
    pack={int(r['address'],16) for r in ev['call_xrefs'][hx(ADDR['packer'])]}
    load={int(r['address'],16) for r in ev['call_xrefs'][hx(ADDR['loader'])]}
    disp={int(r['address'],16) for r in ev['call_xrefs'][hx(ADDR['dispatcher'])]}
    mem={int(r['address'],16) for r in ev['call_xrefs'][hx(ADDR['memcpy'])]}
    ck('packer-callers-exact',pack=={0x0201e468,0x0201e49c,0x02026dac},','.join(hx(x) for x in sorted(pack)))
    ck('loader-post-packer-calls',{0x0201e46c,0x0201e4a0}<=load,','.join(hx(x) for x in sorted(load)))
    ck('dispatcher-callers-exact',disp=={0x0201c736,0x0201e644},','.join(hx(x) for x in sorted(disp)))
    ck('note-copy-memcpy-sites',{0x0201c63e,0x0201c67c}<=mem,','.join(hx(x) for x in sorted(mem) if 0x0201c600<=x<=0x0201c690))
    ck('sysex-callsite-budgets',ev['budgets'][hx(0x0201e468)]['size']==4 and ev['budgets'][hx(0x0201e49c)]['size']==4,json.dumps(ev['budgets'],sort_keys=True))
    ck('note-callsite-budgets',ev['budgets'][hx(0x0201c63e)]['size']==6 and ev['budgets'][hx(0x0201c67c)]['size']==6,json.dumps(ev['budgets'],sort_keys=True))
    ck('stock-packer-not-cave',0x02026dac in pack,'SAVE path calls stock packer')
    ck('block-owned-ram-recorded',ev['decision']['status']=='BLOCK','No owned RAM destination proven')
    ev['validation']=checks
    bad=[c for c in checks if c['status']!='PASS']
    if bad: raise SystemExit('validation failed: '+json.dumps(bad,ensure_ascii=False))
    return ev

def report(ev):
    L=[]; s=ev['sha256']; b=ev['budgets']
    L += ['# R03 owned-RAM copy-path design gate','', 'Decision: **BLOCK**.', '', 'Official-v15-only read-only analysis. No patch, flash, device access, boot hook, R01d address, v12 address, guessed RAM, or guessed executable cave is used.', '']
    L += ['## SHA gates','',f"- app: `{s['app']}`",f"- FWSC: `{s['fwsc']}`",f"- Quarkslab listing: `{s['quark']}`",f"- Kagaimiq listing: `{s['kaga']}`",'']
    L += ['## Minimal semantic path, not patch-ready','', 'The only stock-preserving producer shape is a wrapper at the two accepted product packer callsites, `0x0201e468` and `0x0201e49c`. Both are reached only after the official handler has accepted a complete product payload into `0x01c37fd0`. A valid wrapper would preserve the stage pointer, call stock `0x0201e13e(stage)`, copy exactly `0x9c` bytes from stage into a separately proven owned destination, then publish `generation++` and `valid=1` only after the copy completes. The stock reload calls at `0x0201e46c` and `0x0201e4a0` stay in place.', '', 'This remains blocked because the listings prove neither the owned destination nor the executable body placement required by that wrapper.', '']
    L += ['## Exact accepted SysEx callsites','', 'Direct complete message: `F0 43 00 00 01 1B + 0x9c payload/checksum + F7`, total `0xa3` bytes. The direct path computes `0x01c37030 + 0x0fa0 = 0x01c37fd0`, copies `message+6`, checks final `F7`, then calls packer and loader. The segmented-final path is also accepted only after final `F7` and accumulated length `0x9e`.', '']
    for name in ['direct_complete_accept','segmented_final_accept']:
        L += [f'### {name}','']; L += [f'- `{line(r)}`' for r in ev['paths'][name]]; L.append('')
    L += ['## Register, stack ABI, and SAVE behavior','', '- At `0x0201e468`, `r0 = r8 = 0x01c37fd0`. At `0x0201e49c`, `r0 = r6 = 0x01c37fd0`.', '- Packer `0x0201e13e` pushes `{rets,r6,r5,r4}`, allocates `0x80` stack bytes, packs from input `r0`, calls `0x02004b02` with `r0=packed80`, selected persistent destination in `r1`, and `r2=0x80`, then restores stack and pops `{pc,r6,r5,r4}`.', '- SAVE also calls `0x0201e13e` at `0x02026dac` after staging `r0 = 0x01c33260+0x1a14`. Therefore `0x0201e13e` is stock pack/SAVE code, not a cave.', '']
    for name in ['packer_sink','save_packer_caller','other_stage_overwrites']:
        L += [f'### {name}','']; L += [f'- `{line(r)}`' for r in ev['paths'][name]]; L.append('')
    L += ['## Instruction budgets and caller effects','', f"- `0x0201e468`: `{b[hx(0x0201e468)]['bytes']}`, inline budget `{b[hx(0x0201e468)]['size']}` bytes.", f"- `0x0201e49c`: `{b[hx(0x0201e49c)]['bytes']}`, inline budget `{b[hx(0x0201e49c)]['size']}` bytes.", f"- `0x0201c63e`: `{b[hx(0x0201c63e)]['bytes']}`, inline budget `{b[hx(0x0201c63e)]['size']}` bytes.", f"- `0x0201c67c`: `{b[hx(0x0201c67c)]['bytes']}`, inline budget `{b[hx(0x0201c67c)]['size']}` bytes.", '- Producer logic necessarily exceeds the 4-byte SysEx callsite budget because it must preserve stage, preserve/call stock packer, perform a second `0x9c` copy, and publish metadata. No executable body is proven.', '- Direct packer callers are exactly `0x0201e468`, `0x0201e49c`, and `0x02026dac`. Hooking the first two only is the stock-SAVE-preserving strategy, but it still needs unproven placement.', '']
    L += ['## Note On/Off valid and generation behavior','', 'Stock `0x0201c5ec` has no Ch10-owned valid flag, no generation counter, and no valid-source branch. It only checks message/voice bounds, then both Note Off and Note On set `r1 = r8 = 0x01c34c74`, `r2 = 0x9c`, and copy to `engine + voice*0xa0 + 0xa2`. Event metadata follows the `0x9c` copied block. A safe R03 consumer must add metadata: `valid=0` at reset; set `valid=1` only after the producer copy completes; reject or defer generation changes while any Ch10 note is active, or otherwise prove per-active-note generation identity. No storage or code budget for that state is proven here.', '']
    for name in ['note_off_copy','note_on_copy']:
        L += [f'### {name}','']; L += [f'- `{line(r)}`' for r in ev['paths'][name]]; L.append('')
    L += ['## PASS/BLOCK matrix','', '| Gate | Result | Reason |','|---|---|---|','| Exact accepted product callsites | PASS | `0x0201e468` and `0x0201e49c` are post-F7 acceptance packer calls |','| Producer source/length | PASS | stage is `0x01c37fd0`; required copy is first `0x9c` bytes |','| Stock packer/SAVE preservation | BLOCK | semantic strategy exists, but needs unproven wrapper body; overwriting packer affects SAVE |','| Owned RAM destination | BLOCK | no exact start/end, owner, lifetime, initialization, alias, DMA/stack/heap exclusion proof |','| Valid/generation | BLOCK | required semantics defined, but no owned metadata storage or consumer budget proven |','| Avoid boot hooks | PASS semantically | producer would run only from already-live SysEx accept path |','| No guessed cave/address | PASS by refusal | no cave or RAM address is proposed |','']
    L += ['## Reproduce','','```sh','python3 baselines/v15/analysis/r03-owned-ram/copy-path/analyze_copy_path.py','cd baselines/v15/analysis/r03-owned-ram/copy-path','shasum -a 256 -c SHA256SUMS','```','']
    return '\n'.join(L)

def main():
    ev=build(); OUT.mkdir(parents=True,exist_ok=True)
    (OUT/'evidence.json').write_text(json.dumps(ev,indent=2,sort_keys=True)+'\n')
    (OUT/'report.md').write_text(report(ev))
    (OUT/'validation.txt').write_text('\n'.join(f"{c['status']}\t{c['name']}\t{c['detail']}" for c in ev['validation'])+f"\nPASS\tcheck-count\t{len(ev['validation'])}\n")
    names=['analyze_copy_path.py','evidence.json','report.md','validation.txt']
    (OUT/'SHA256SUMS').write_text('\n'.join(f"{sha(OUT/n)}  {n}" for n in names)+'\n')
if __name__=='__main__': main()
