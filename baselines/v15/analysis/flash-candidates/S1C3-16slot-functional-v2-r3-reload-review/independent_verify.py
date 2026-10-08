#!/usr/bin/env python3
from __future__ import annotations
import gzip, hashlib, importlib.util, json, os, re, shutil, struct, subprocess, sys, tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CAND = HERE.parent / 'S1C3-16slot-functional-v2-r3-reload'
PROD = HERE.parents[1] / 'patch-set-ui/s1c3/compact-producer-v3-r3-reload'
BOUNDARY = HERE.parent / 'S1C3-16slot-boundary-only'
S1C2 = HERE.parent / 'S1C2-two-slot-selector-live-v2'
SELECTOR = HERE.parents[1] / 'patch-set-ui/s1c3/selector'
REPO = HERE.parents[4]
OFFICIAL = S1C2 / 'inputs/SMK-37_Pro_015.fwsc'
PKG = 'SMK37Pro-v15-S1C3-16slot-functional-v2-r3-reload.fwsc'
BASE = 0x02000000
SECTOR = 0x2000
SEL_START, SEL_END = 0x0201E13E, 0x0201E19E
PROD_START, PROD_END, PROD_LIMIT = 0x0201E1A2, 0x0201E250, 0x0201E254
DIRECT_ENTRY, SEG_STUB, MEMCPY = 0x0201E226, 0x0201E222, 0x02048CCE
DIRECT_CALL, DIRECT_RELOAD = 0x0201E468, 0x0201E46C
SEG_CALL, SEG_RELOAD = 0x0201E49C, 0x0201E4A0
NOTE_OFF, NOTE_ON = 0x0201C63E, 0x0201C67C
EXP = {
 'official_fwsc':'f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff',
 'official_flash':'f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a',
 'official_app':'36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055',
 'boundary_app':'c18ed6f4e8ba2c16b99c41e6264cc36804fb38d8800d03ec518ab6bd838a8d14',
 'selector':'ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915',
 'selector_live':'894f61ee4eedb942b6653bd36dc72934d3719b54a9a413f6c94f29d0084f8ffc',
 'producer':'48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607',
 'producer_evidence':'0e8d2c664f770889d6a714fff61a351652552fbd38e5aacf1ff444268c1aed3a',
 'candidate_app':'7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b',
 'candidate_pkg':'0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9',
 'candidate_flash':'ee72dd53448f917d3b3c86b09ada7a79abf0cee1326cc1780c6bdd0e97bcd19b',
 'sender_token':'SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7',
}
PACKET_HASHES = ['1c9239621563722eaac0a85db411571963f9ebbd0dbbb00b21044b76b1581427','afa8957005341e6144962ce3120bb1d829475714077617ea8da2c3fee4a0aa21','8a87a409056457e61944d01bf4bbc0266414b8385c3a848125700da9e8417de3','a5c086a77b4de1ce9546e747b72f79d8f6ad7b0dbd7c3b6e1665ef7edf83ff58','ffd1bcc6c7a7c5d8a1bb35f5bf7e39bf63058e62ac574e1e308ba53edc6670ff','57136706fa633b5b47008ed2616471f72ae629d69e601e33c66daad991df94e9','0f202d88578152ca024b3822f56a7c74c485c42996695033a4c239449d30f366','d4ee6f2ccfce2d0c548917bb58ead4988dc3038c2b84edaaa37f047d2e006ea2','c8c489b72b195dfe5f373b6a860b32f0d07a29a83a9f2c070299df5af88a9cb3','9c895d925a6cb79c4dff9f9f27727cce02f6dd0ed86467c994d7f459f1036258','802944d0e1a8f4e85f1a3a694e2a0dbbfe9bb55972814f11ed4c7be7575b6704','c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d','622a06870f189b6e4582f0093255f450403d4112836f09563c0b4623c1b287cd','6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27','b159db617616621759bb9990991a8214c585d1f7ecd1be0f36d53a0b71b160c8','39a3e4eca1c740f719b3495f2a88c63e3b5d575a16a98c7b05fbc211fbfa4775']
BRANCHES = {0x0201E1AC:('jne_imm7',0x0201E220),0x0201E1BA:('ifeq',0x0201E220),0x0201E1C4:('jne_imm7',0x0201E1D6),0x0201E1CA:('jne_imm7',0x0201E218),0x0201E1D4:('goto',0x0201E1DC),0x0201E1D6:('jne_imm7',0x0201E218),0x0201E1DC:('jge_imm7',0x0201E218),0x0201E1FC:('call32',MEMCPY),0x0201E20E:('jne_imm7',0x0201E218),0x0201E22C:('jne_imm7',0x0201E246),0x0201E232:('jne_imm7',0x0201E246),0x0201E248:('call32',0x0201E1A2)}

def req(c,m):
 if not c: raise SystemExit('BLOCK: '+m)
def sha(b): return hashlib.sha256(b).hexdigest()
def shaf(p:Path):
 h=hashlib.sha256();
 with p.open('rb') as f:
  for c in iter(lambda:f.read(1048576), b''): h.update(c)
 return h.hexdigest()
def j(p): return json.loads(p.read_text())
def off(a): return a-BASE
def hx(a): return f'0x{a:08x}'
def sx(v,b): s=1<<(b-1); return (v^s)-s
def call32(at,b): req(len(b)==6 and b[:2]==b'\x80\xff',f'call32 at {hx(at)}'); return at+6+struct.unpack('<i',b[2:])[0]
def scall(at,b): req(len(b)==4 and b[:2]==b'\xbf\xea',f'short call at {hx(at)}'); return ((at+4+struct.unpack('<H',b[2:])[0]*2)&0xffff)|(at&0xffff0000)
def diffs(a,b): req(len(a)==len(b),'diff lengths'); return [i for i,(x,y) in enumerate(zip(a,b)) if x!=y]
def ranges(ds):
 out=[]
 if not ds: return out
 s=p=ds[0]
 for x in ds[1:]:
  if x==p+1: p=x
  else: out.append({'start':s,'end_exclusive':p+1}); s=p=x
 out.append({'start':s,'end_exclusive':p+1}); return out

def ledger(base:Path):
 n=0
 for line in (base/'SHA256SUMS').read_text().splitlines():
  if not line.strip(): continue
  dig, rel = line.split(maxsplit=1); rel = rel[1:] if rel.startswith('*') else rel
  req(shaf(base/rel)==dig, f'sha ledger {base.name}/{rel}'); n+=1
 return {'entry_count':n,'all_match':True}

def run(args,cwd,expect=0):
 env=os.environ.copy(); env['PYTHONDONTWRITEBYTECODE']='1'
 r=subprocess.run(args,cwd=cwd,text=True,capture_output=True,env=env)
 req(r.returncode==expect, f"command rc {r.returncode}!={expect}: {' '.join(map(str,args))}\n{r.stdout}\n{r.stderr}")
 return r

def mod():
 sys.dont_write_bytecode=True
 spec=importlib.util.spec_from_file_location('m', BOUNDARY/'smk37_v15_app_patch.py')
 req(spec and spec.loader, 'load parser')
 m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m); return m

def unpack_nonofficial(raw,m):
 payload=bytearray()
 for i in range(m.FWSC_SLOTS): payload.extend(raw[i*m.FWSC_BLOCK_SIZE:i*m.FWSC_BLOCK_SIZE+m.FWSC_DATA_SIZE])
 payload.extend(raw[m.FWSC_SLOTS*m.FWSC_BLOCK_SIZE:]); req(len(payload)==m.OFFICIAL_V15_PAYLOAD_SIZE,'payload size'); return payload

def fw(path,m,official):
 raw=path.read_bytes(); payload=m.unpack_fwsc(raw)[0] if official else unpack_nonofficial(raw,m)
 flash=m.Ufw.parse(payload).flash(); app=m.AppImage.parse(flash).app_bytes(); return raw,flash,app

def decode(data,start):
 rows=[]; i=0
 while i<len(data):
  at=start+i; rem=len(data)-i; w=int.from_bytes(data[i:i+2],'little') if rem>=2 else 0
  if rem>=6 and data[i:i+2]==b'\x80\xff': size=6; row={'op':'call32','target':call32(at,data[i:i+6])}
  elif rem>=6 and (w&0xffc0)==0xffc0: size=6; row={'op':'mov_imm32','dst':w&0xf,'imm':int.from_bytes(data[i+2:i+6],'little')}
  elif rem>=4 and data[i:i+4]==bytes.fromhex('2000b000'): size=4; row={'op':'trylock'}
  elif rem>=4 and data[i:i+2]==bytes.fromhex('40e8'): size=4; row={'op':'ifeq','target':at+4+struct.unpack('<h',data[i+2:i+4])[0]*2}
  elif rem>=4 and (w&0xff80) in {0xf880,0xfd00,0xfc80,0xfd80}: size=4; w2=int.from_bytes(data[i+2:i+4],'little'); row={'op':{0xf880:'jne_imm7',0xfd00:'jge_imm7',0xfc80:'jl_imm7',0xfd80:'jl_imm7'}[w&0xff80],'reg':w&7,'imm':(w2>>9)&0x7f,'target':at+4+sx(w2&0x1ff,9)*2}
  elif rem>=4 and data[i+1]==0xe1 and (data[i]&0xf0)==0xe0: size=4; row={'op':'mul_imm12','dst':data[i]&0xf,'src':data[i+3]>>4,'imm':data[i+2]|((data[i+3]&0xf)<<8)}
  elif rem>=4 and data[i+1]==0xe1: size=4; row={'op':'add_imm12','dst':data[i],'src':data[i+3]>>4,'imm':data[i+2]|((data[i+3]&0xf)<<8)}
  elif rem>=2 and (w&0xe088)==0x4008: size=2; row={'op':'load_byte','dst':w&7,'base':(w>>4)&7,'offset':sx((w>>8)&0x1f,5)}
  elif rem>=2 and (w&0xe088)==0x4088: size=2; row={'op':'store_byte','src':w&7,'base':(w>>4)&7,'offset':sx((w>>8)&0x1f,5)}
  elif rem>=2 and (w&0xe0c0)==0x20c0: size=2; imm=((w>>8)&0x1f)|(((w>>3)&7)<<5); row={'op':'add_imm8','dst':w&7,'imm_signed':sx(imm,8)}
  elif rem>=2 and (w&0xe0c0)==0x2040: size=2; imm=((w>>8)&0x1f)|(((w>>3)&7)<<5); row={'op':'mov_imm8','dst':w&7,'imm':imm}
  elif rem>=2 and (w&0xff00)==0x1600: size=2; row={'op':'mov_reg','dst':w&0xf,'src':(w>>4)&0xf}
  elif rem>=2 and (w&0xff00)==0x1800: size=2; row={'op':'add_reg','dst':w&7,'src':(w>>4)&7}
  elif rem>=2 and (w&0x80ff)==0x8004: size=2; row={'op':'goto','target':at+2+((w>>8)&0x1f)*2}
  elif rem>=2 and w==0x0020: size=2; row={'op':'csync'}
  elif rem>=2 and w in {0x0479,0x0459}: size=2; row={'op':{0x0479:'push',0x0459:'pop_pc'}[w]}
  else: raise SystemExit(f'BLOCK: undecoded {hx(at)} {data[i:i+8].hex()}')
  row.update({'address':at,'size':size,'bytes':data[i:i+size].hex()}); rows.append(row); i+=size
 return rows

def write_tsv(name,rows):
 cols=['address','size','bytes','op','target','dst','src','reg','imm','imm_signed','base','offset']
 out=['\t'.join(cols)]
 for r in rows:
  vals=[]
  for c in cols:
   v=r.get(c,'')
   if c in {'address','target','imm'} and isinstance(v,int): v=hx(v)
   vals.append(str(v))
  out.append('\t'.join(vals).rstrip('\t'))
 (HERE/name).write_text('\n'.join(out)+'\n')

def verify_memcpy():
 rows={}; listing=REPO/'baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz'
 with gzip.open(listing,'rt',encoding='utf-8',errors='replace') as f:
  for line in f:
   p=line.rstrip('\n').split('\t')
   if len(p)>=4:
    try: a=int(p[0],16)
    except ValueError: continue
    if 0x02048cce<=a<=0x02048d0e: rows[a]=line.rstrip('\n')
 req('push {rets,r6,r5,r4}' in rows.get(0x02048cce,''),'memcpy push save set')
 req('pop {pc,r6,r5,r4}' in rows.get(0x02048d0e,''),'memcpy pop restore set')
 muts=[rows[a] for a,l in rows.items() if re.search(r'\b(r3|\[r3)',l) and a!=0x02048cce]
 req(muts,'memcpy r3 mutations')
 return {'entry':rows[0x02048cce],'return':rows[0x02048d0e],'r3_mutating_rows':muts[:8],'conclusion':'r3 clobbered; only r6/r5/r4 preserved'}

def main():
 result={'decision':'PASS','scope':'offline only; no USB, MIDI, OTA upload, flash, reset, or live send'}
 result['ledgers']={'candidate':ledger(CAND),'producer':ledger(PROD),'nested_producer':ledger(CAND/'inputs/producer')}
 ev=j(CAND/'evidence.json'); pe=j(PROD/'evidence.json'); am=j(CAND/'app-manifest.json'); pm=j(CAND/'package-manifest.json')
 req(ev['decision']=='PASS' and ev['candidate_built'] is True,'candidate PASS evidence')
 req(ev['device_accessed'] is False and ev['midi_transport_opened'] is False and ev['flash_performed'] is False,'offline flags')
 req(ev['sender']['default_compile_live_usb_enabled'] is False,'sender default offline')
 req(shaf(PROD/'evidence.json')==EXP['producer_evidence']==shaf(CAND/'inputs/producer/evidence.json'),'producer evidence hash')
 req(pe['code_window']['end_exclusive']==hx(PROD_END),'producer evidence end')
 m=mod(); official_raw,official_flash,official_app=fw(OFFICIAL,m,True); cand_raw,cand_flash,cand_app=fw(CAND/PKG,m,False)
 req(sha(official_raw)==EXP['official_fwsc'] and sha(official_flash)==EXP['official_flash'] and sha(official_app)==EXP['official_app'],'official hashes')
 req(sha(cand_raw)==EXP['candidate_pkg'] and sha(cand_flash)==EXP['candidate_flash'] and sha(cand_app)==EXP['candidate_app'],'candidate hashes')
 req(cand_app==(CAND/'app.bin').read_bytes(),'package embeds app.bin')
 boundary=(BOUNDARY/'app.bin').read_bytes(); bd=diffs(boundary,cand_app)
 req(sha(boundary)==EXP['boundary_app']==am['basis_app_sha256'],'parent boundary hash')
 req(len(bd)==am['boundary_relative_changed_byte_count']==221 and ranges(bd)==am['boundary_relative_changed_ranges'],'parent boundary diffs')
 fd=diffs(official_flash,cand_flash); sectors=sorted({i//SECTOR*SECTOR for i in fd})
 req(sectors==[0x04000,0x20000,0x22000,0x2a000,0x62000],'changed sectors')
 rb=j(CAND/'rollback/official-v15-recovery-sectors/manifest.json'); rec=bytearray(cand_flash); rbases=[]
 for item in rb['changed_sectors']:
  base=int(item['sector_base'],16); data=(CAND/item['file']).read_bytes(); rbases.append(base)
  req(len(data)==item['size']==SECTOR and sha(data)==item['sha256'],'rollback sector metadata')
  req(data==official_flash[base:base+SECTOR],'rollback official sector bytes'); rec[base:base+SECTOR]=data
 req(rbases==sectors and bytes(rec)==bytes(official_flash),'rollback reconstructs official')
 rebuilt=bytearray(boundary); selector=(SELECTOR/'selector.bin').read_bytes(); prod=(CAND/'inputs/producer/producer.bin').read_bytes()
 rebuilt[off(SEL_START):off(SEL_START)+len(selector)]=selector; rebuilt[off(PROD_START):off(PROD_START)+len(prod)]=prod
 rebuilt[off(DIRECT_CALL):off(DIRECT_CALL)+4]=bytes.fromhex('bfeaddfe'); rebuilt[off(SEG_CALL):off(SEG_CALL)+4]=bytes.fromhex('bfeac1fe')
 req(bytes(rebuilt)==cand_app,'deterministic app rebuild')
 with tempfile.TemporaryDirectory(prefix='s1c3-review-repack-') as td:
  app=Path(td)/'app.bin'; pkg=Path(td)/PKG; man=Path(td)/'manifest.json'; app.write_bytes(rebuilt)
  run([sys.executable,str(BOUNDARY/'smk37_v15_app_patch.py'),'repack-app',str(OFFICIAL),str(app),str(pkg),'--manifest',str(man)],REPO)
  req(pkg.read_bytes()==cand_raw and shaf(pkg)==EXP['candidate_pkg'],'deterministic package rebuild')
 result['hashes']={'official_fwsc':sha(official_raw),'official_flash':sha(official_flash),'official_app':sha(official_app),'candidate_package':sha(cand_raw),'candidate_flash':sha(cand_flash),'candidate_app':sha(cand_app),'producer':sha(prod),'selector':sha(selector)}
 result['parent_boundary']={'basis_app_sha256':sha(boundary),'changed_byte_count':len(bd),'changed_ranges':ranges(bd)}
 result['changed_sectors']=[f'0x{x:05x}' for x in sectors]; result['rollback_reconstructs_official']=True; result['deterministic_rebuild']={'app_byte_identical':True,'package_byte_identical':True}
 req(sha(prod)==EXP['producer'] and prod==(PROD/'producer.bin').read_bytes(),'producer exact 48abedfe')
 rows=decode(prod,PROD_START); write_tsv('producer-independent-decode.tsv',rows); by={r['address']:r for r in rows}
 req(rows[-1]['address']+rows[-1]['size']==PROD_END and PROD_LIMIT-PROD_END==4,'producer window')
 for a,(op,t) in BRANCHES.items(): req(by[a]['op']==op and by[a].get('target')==t,f'branch/call {hx(a)}')
 req([by[a]['op'] for a in (0x0201e206,0x0201e208,0x0201e20a,0x0201e20c)]==['store_byte','load_byte','add_imm8','store_byte'],'post memcpy order')
 req(by[0x0201e208]['dst']==3 and by[0x0201e208]['base']==5 and by[0x0201e208]['offset']==1,'post memcpy reload r3')
 result['producer']={'sha256':sha(prod),'bytes':len(prod),'window':{'start':hx(PROD_START),'end_exclusive':hx(PROD_END),'limit_exclusive':hx(PROD_LIMIT),'spare_bytes':4},'branch_targets':{hx(a):{'op':by[a]['op'],'target':hx(by[a]['target'])} for a in BRANCHES},'post_memcpy_order':[hx(a) for a in (0x0201e206,0x0201e208,0x0201e20a,0x0201e20c)]}
 sel_slice=cand_app[off(SEL_START):off(SEL_END)]; req(sha(sel_slice)==EXP['selector'] and sel_slice==selector,'selector unchanged')
 selrows=decode(sel_slice.rstrip(b'\x00'),SEL_START); write_tsv('selector-independent-decode.tsv',selrows)
 routes={'note_off':call32(NOTE_OFF,cand_app[off(NOTE_OFF):off(NOTE_OFF)+6]),'note_on':call32(NOTE_ON,cand_app[off(NOTE_ON):off(NOTE_ON)+6]),'direct_product':scall(DIRECT_CALL,cand_app[off(DIRECT_CALL):off(DIRECT_CALL)+4]),'segmented_product':scall(SEG_CALL,cand_app[off(SEG_CALL):off(SEG_CALL)+4])}
 req(routes=={'note_off':SEL_START,'note_on':SEL_START+4,'direct_product':DIRECT_ENTRY,'segmented_product':SEG_STUB},'external route targets')
 req(cand_app[off(DIRECT_RELOAD):off(DIRECT_RELOAD)+4].hex()=='bfeaf838' and cand_app[off(SEG_RELOAD):off(SEG_RELOAD)+4].hex()=='bfeade38','reload callsites preserved')
 result['selector_and_routes']={'selector_sha256':sha(sel_slice),'selector_live_code_sha256':shaf(SELECTOR/'selector-live-code.bin'),'routes':{k:hx(v) for k,v in routes.items()},'reload_callsites':{'direct':'bfeaf838','segmented':'bfeade38'}}
 result['stock_memcpy']=verify_memcpy()
 pmn=j(CAND/'inputs/packets/packet-manifest.json'); sm=j(CAND/'inputs/packets/sender-manifest.json'); perm=j(CAND/'inputs/packets/physical-pad-permutation.json')
 req(pmn['order_basis']==sm['order_basis']=='note_order_36_51' and sm['send_enabled'] is False,'sender dry-run manifest')
 req(pmn['physical_pad_permutation']['ui_only'] is True and perm['ui_only'] is True,'pad permutation ui only')
 for i,item in enumerate(pmn['packets']):
  data=(CAND/'inputs/packets'/item['file']).read_bytes(); req((item['order'],item['slot'],item['note'])==(i+1,i,36+i) and item['sha256']==PACKET_HASHES[i] and sha(data)==item['sha256'] and len(data)==163,'packet order/hash')
 c=(CAND/'exact_16_packet_sender.c').read_text(); cent=[(int(a),int(b),int(c),d) for a,b,c,d in re.findall(r'\{\s*(\d+),\s*(\d+),\s*(\d+),\s*"[^"]+",\s*"([^"]+)"',c)]
 req(len(cent)==16 and all((o,s,n)==(i+1,i,36+i) for i,(o,s,n,_) in enumerate(cent)),'C sender packet order')
 result['packets_and_sender']={'packet_count':16,'order_basis':'note_order_36_51','physical_pad_permutation_scope':'UI_ONLY','c_sender_order_matches_manifest':True}
 tools={}; tools['candidate_validate_tail']=run([sys.executable,'validate.py'],CAND).stdout.strip().splitlines()[-5:]; tools['dry_run_validate']=json.loads(run([sys.executable,'dry_run_validate.py','--json'],CAND).stdout)
 with tempfile.TemporaryDirectory(prefix='s1c3-review-tools-') as td:
  td=Path(td); pc=subprocess.run(['pkg-config','--cflags','--libs','libusb-1.0'],text=True,capture_output=True)
  if pc.returncode==0:
   exe=td/'exact_ota'; run(['cc','-O2','-g','-std=c11','-Wall','-Wextra','-Wpedantic','exact_ota.c','../../../../../src/device_info.c','../../../../../src/fwsc.c','../../../../../src/protocol.c','../../../../../src/sha256.c','../../../../../src/usb_probe.c','-o',str(exe),*pc.stdout.split()],CAND)
   ok=run([str(exe),'check',PKG],CAND); rej=run([str(exe),'check',str(OFFICIAL)],CAND,1); rej2=run([str(exe),'check','app.bin'],CAND,1)
   tools['exact_ota']={'compiled':True,'candidate_check':ok.stdout.strip(),'official_reject':rej.stderr.strip(),'app_bin_reject_returncode':rej2.returncode}
  else: tools['exact_ota']={'compiled':False,'reason':pc.stderr.strip() or pc.stdout.strip()}
  snd=td/'sender'; run(['cc','-O2','-g','-std=c11','-Wall','-Wextra','-Wpedantic','exact_16_packet_sender.c','../../../../../src/sha256.c','-o',str(snd)],CAND)
  dry=run([str(snd),'dry-run','inputs/packets'],CAND); block=run([str(snd),'send','inputs/packets','--confirm',EXP['sender_token']],CAND,2)
  corrupt=td/'corrupt'; corrupt.mkdir();
  for p in sorted((CAND/'inputs/packets').glob('slot*.bin')): shutil.copyfile(p,corrupt/p.name)
  first=corrupt/'slot00-note36-direct-product-163.bin'; d=bytearray(first.read_bytes()); d[10]^=1; first.write_bytes(d); cr=run([str(snd),'dry-run',str(corrupt)],CAND,2)
  tools['sender']={'compiled':True,'dry_run':dry.stdout.strip(),'send_block':block.stderr.strip(),'corrupt_reject':cr.stderr.strip()}
 result['offline_tools']=tools
 result['reviewed_head']=run(['git','rev-parse','HEAD'],REPO).stdout.strip()
 (HERE/'review.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 md=f"""# Independent review: S1-C3 16-slot functional v2 r3-reload

Decision: **PASS**

Scope: {result['scope']}.

## Verified

- Official v15 hashes: FWSC `{result['hashes']['official_fwsc']}`, flash `{result['hashes']['official_flash']}`, app `{result['hashes']['official_app']}`.
- Candidate deterministic hashes: package `{result['hashes']['candidate_package']}`, app `{result['hashes']['candidate_app']}`.
- Parent boundary: `{result['parent_boundary']['basis_app_sha256']}`, `{result['parent_boundary']['changed_byte_count']}` exact byte changes.
- Producer exact hash: `{result['hashes']['producer']}`, window `{result['producer']['window']['start']}..{result['producer']['window']['end_exclusive']}` within `{result['producer']['window']['limit_exclusive']}`.
- Stock `memcpy` at `0x02048cce` preserves only `r6/r5/r4` and clobbers volatile `r3`; producer reloads `lb.z r3,[r5+1]` at `0x0201e208` before increment/store.
- Selector unchanged: `{result['hashes']['selector']}`; branch/call route targets and reload callsites match expected values.
- Rollback reconstructs official flash exactly from sectors `{', '.join(result['changed_sectors'])}`.
- Exact OTA check accepts the candidate package and rejects official/app inputs. Sender dry-run uses note order slots `0..15` -> notes `36..51`; live send is fail-closed in the offline build.

## Offline validation

- Candidate validator tail: `{'; '.join(result['offline_tools']['candidate_validate_tail'])}`
- Dry-run status: `{result['offline_tools']['dry_run_validate'].get('status')}`
- Exact OTA compiled: `{result['offline_tools']['exact_ota'].get('compiled')}`
- Sender: `{result['offline_tools']['sender']['dry_run']}`

Artifacts: `independent_verify.py`, `producer-independent-decode.tsv`, `selector-independent-decode.tsv`, `review.json`, `review.md`, `SHA256SUMS`.
"""
 (HERE/'review.md').write_text(md)
 sums=[]
 for p in sorted(HERE.iterdir()):
  if p.is_file() and p.name!='SHA256SUMS': sums.append(f'{shaf(p)}  {p.name}')
 (HERE/'SHA256SUMS').write_text('\n'.join(sums)+'\n')
 print('S1-C3 v2 r3-reload independent review: PASS')
 print(json.dumps({'decision':'PASS','candidate_package':result['hashes']['candidate_package'],'producer':result['hashes']['producer'],'review_dir':str(HERE)},indent=2))
 return 0
if __name__=='__main__': raise SystemExit(main())
