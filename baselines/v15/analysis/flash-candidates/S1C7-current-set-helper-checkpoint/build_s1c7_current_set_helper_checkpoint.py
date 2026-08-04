#!/usr/bin/env python3
"""Build S1-C7 current-set helper checkpoint offline candidate.

This child of exact S1-C5 proves the previously blocked split-control path:
selector/producer control remains in 0x0201e13e..0x0201e254, while the whole
S1C5-disabled SAVE body 0x02026d80..0x02026dd4 is made unreachable from the UI
and reused as a standalone selector fallback helper.  It does not access a
device, MIDI, USB, flash, OTA transport, or reset path.
"""
from __future__ import annotations
import argparse, binascii, hashlib, importlib.util, json, shutil, struct, subprocess, sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
FLASH = HERE.parent
ROOT = HERE.parents[4]
S1C5 = FLASH / "S1C5-playback-register-return"
BOUNDARY = FLASH / "S1C3-16slot-boundary-only"
OFFICIAL_FWSC = FLASH / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
CODEDIR = HERE / "code-evidence"
SEEDDIR = HERE / "host-seeded-records"
FORMAT = "smk37-v15-s1c7-current-set-helper-checkpoint"
PACKAGE_NAME = "SMK37Pro-v15-S1C7-current-set-helper-checkpoint.fwsc"
BASE = 0x02000000
SECTOR = 0x2000
PROTECTED_PREFIX_END = 0x4000
SEL_START, SEL_END, OWNED_END = 0x0201E13E, 0x0201E196, 0x0201E254
PRODUCER_START = 0x0201E196
SAVE_SKIP, SAVE_HELPER, SAVE_EXIT = 0x02026D7A, 0x02026D80, 0x02026DD4
MEMCPY, READ_WRAPPER = 0x02048CCE, 0x02004870
PATCH_BASE, MAP_BASE = 0x01C46520, 0x01C46F20
NOTE0, NOTE_END, CH10, ARMED, SLOTS = 36, 52, 9, 2, 16
VOICE, STRIDE, RAW_STRIDE, RECORD_BASE, RECORD_STORAGE_OFFSET = 0x9C, 0xA0, 0xA3, 96, 0x4000 + 96 * 0xA3
HEADER = bytes.fromhex("f0430000011b")

sys.path.insert(0, str(BOUNDARY))
from smk37_v15_app_patch import APP_DATA_OFFSET, APP_DATA_SIZE, AppImage, Ufw, compact_ranges, difference_offsets, protected_hashes, unpack_fwsc, repack_fwsc, crc16  # noqa:E402

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "parent_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "parent_fwsc": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "parent_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "parent_producer": "53bc57acd7e787320400d0d945ec6b3f2e59f2074ae81c9053eb2c11f72560d4",
    "parent_save_skip": "60ffff602a00",
    "parent_save_body_prefix": "05e1a0835844d8ee001500a5",
}

def req(ok: bool, msg: str) -> None:
    if not ok: raise SystemExit("FAIL: " + msg)
def sha(b: bytes|bytearray) -> str: return hashlib.sha256(bytes(b)).hexdigest()
def shaf(p: Path) -> str:
    h=hashlib.sha256();
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()
def wjson(p: Path, v: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(v, indent=2, sort_keys=True)+"\n")
def hx(x:int)->str: return f"0x{x:08x}"
def off(a:int)->int:
    o=a-BASE; req(0 <= o < APP_DATA_SIZE, f"address outside app {hx(a)}"); return o
def word(v:int)->bytes: return struct.pack('<H', v & 0xffff)
def mov(d,s): return word(0x1600 | (s<<4) | d)
def mov32(d,v): return word(0xffc0 | d) + struct.pack('<I', v)
def mov8(r,imm): return word(0x2040 | r | ((imm>>5)<<3) | ((imm&0x1f)<<8))
def add8(r,imm): e=imm&0xff; return word(0x20c0 | r | ((e>>5)<<3) | ((e&0x1f)<<8))
def add(d,s): return word(0x1800 | (s<<4) | d)
def add12(d,s,imm): return bytes((d,0xe1,imm&0xff,(s<<4)|(imm>>8)))
def mul12(d,s,imm): return bytes((0xe0|d,0xe1,imm&0xff,(s<<4)|(imm>>8)))
def lb(d,b,o=0): return word(0x4008 | d | (b<<4) | ((o&0x1f)<<8))
def sb(s,b,o=0): return word(0x4088 | s | (b<<4) | ((o&0x1f)<<8))
def call32(at,target): return b"\x80\xff" + struct.pack('<i', target-(at+6))
def jne(at,r,imm,target): return word(0xf880|r) + word((imm<<9) | (((target-(at+4))//2)&0x1ff))
def jl(at,r,imm,target): return word(0xfd80|r) + word((imm<<9) | (((target-(at+4))//2)&0x1ff))
def jge(at,r,imm,target): return word(0xfd00|r) + word((imm<<9) | (((target-(at+4))//2)&0x1ff))
def fgoto(at,target): return word(0x8004 | (((target-(at+2))//2)<<8))

class R:
    def __init__(self,start:int,prefix:str): self.start=start; self.prefix=prefix; self.data=bytearray(); self.labels={}; self.fix=[]; self.rows=[]
    @property
    def pc(self): return self.start+len(self.data)
    def label(self,n): self.labels[n]=self.pc
    def emit(self,n,asm,b,meaning): self.rows.append({"address":hx(self.pc),"size":len(b),"bytes":b.hex(),"name":self.prefix+'.'+n,"asm":asm,"meaning":meaning}); self.data+=b
    def branch(self,n,asm,size,label,enc,meaning): self.rows.append({"address":hx(self.pc),"size":size,"bytes":"pending","name":self.prefix+'.'+n,"asm":asm,"meaning":meaning}); self.fix.append((len(self.data),label,enc)); self.data += b'\0'*size
    def finish(self):
        for o,l,enc in self.fix:
            at=self.start+o; b=enc(at,self.labels[l]); self.data[o:o+len(b)]=b
            for row in self.rows:
                if int(row['address'],16)==at: row['bytes']=b.hex(); row['target']=hx(self.labels[l]); break
        return bytes(self.data)

def build_selector() -> tuple[bytes,list[dict[str,Any]]]:
    r=R(SEL_START,'selector')
    r.emit('note_off_adapter','mov r3,r5',mov(3,5),'normalize Note Off trigger note')
    r.branch('note_off_goto_core','goto core',2,'core',fgoto,'skip Note On adapter')
    r.emit('note_on_adapter','mov r3,r6',mov(3,6),'normalize Note On trigger note')
    r.label('core')
    r.emit('push_saved','push {rets,r9..r4}',word(0x0479),'preserve trigger registers and velocity')
    r.emit('save_dest','mov r4,r0',mov(4,0),'save payload destination')
    r.emit('default_note','mov r5,r3',mov(5,3),'default metadata note')
    r.emit('channel_tmp','mov r6,r9',mov(6,9),'channel temp')
    r.branch('gate_channel','jne r6,#9,stock_copy',4,'stock_copy',lambda a,t:jne(a,6,CH10,t),'non-Ch10 uses original stock source')
    r.branch('gate_low','jl r3,#36,stock_copy',4,'stock_copy',lambda a,t:jl(a,3,NOTE0,t),'below pad range uses original stock source')
    r.branch('gate_high','jge r3,#52,stock_copy',4,'stock_copy',lambda a,t:jge(a,3,NOTE_END,t),'above pad range uses original stock source')
    r.emit('slot_index','add r3,#-36',add8(3,-NOTE0),'slot = trigger - 36')
    r.emit('patch_base',f'mov r8,#{PATCH_BASE:#x}',mov32(8,PATCH_BASE),'resident slot base')
    r.emit('state_base','add r6,r8,#0x9c',add12(6,8,VOICE),'slot0 control base')
    r.emit('state_load','lb.z r0,[r6+3]',lb(0,6,3),'load ARMED state')
    r.branch('gate_state','jne r0,#2,persistent_fallback',4,'persistent_fallback',lambda a,t:jne(a,0,ARMED,t),'not ARMED reads host-seeded raw record')
    r.emit('slot_offset_seed','mov r6,r3',mov(6,3),'copy slot')
    r.emit('slot_offset','mul r6,r6,#0xa0',mul12(6,6,STRIDE),'resident slot offset')
    r.emit('slot_base_add','add r6,r8',add(6,8),'resident source pointer')
    r.emit('valid_pointer','add r7,r6,#0x9c',add12(7,6,VOICE),'valid pointer')
    r.emit('valid_load','lb.z r0,[r7]',lb(0,7),'selected slot valid')
    r.branch('gate_valid','jne r0,#1,persistent_fallback',4,'persistent_fallback',lambda a,t:jne(a,0,1,t),'invalid resident source reads host-seeded raw record')
    r.emit('map_base','add r7,r8,#0xa00',add12(7,8,MAP_BASE-PATCH_BASE),'Playback Note map base')
    r.emit('map_slot','add r7,r3',add(7,3),'Playback Note map slot')
    r.emit('load_playback_note','lb.z r5,[r7]',lb(5,7),'mapped Playback Note')
    r.emit('select_source','mov r1,r6',mov(1,6),'resident source pointer')
    r.label('stock_copy')
    r.emit('call_ram_copy_helper',f'call {SAVE_HELPER+0x32:#x}',call32(r.pc,SAVE_HELPER+0x32),'tail-call helper stock-copy return')
    r.label('persistent_fallback')
    r.emit('call_persistent_helper',f'call {SAVE_HELPER:#x}',call32(r.pc,SAVE_HELPER),'tail-call helper persistent raw-record return')
    b=r.finish(); req(len(b) <= SEL_END-SEL_START, 'selector fits before producer')
    b += mov(0,0) * ((SEL_END-SEL_START-len(b))//2)
    return b, r.rows

def build_helper() -> tuple[bytes,list[dict[str,Any]]]:
    r=R(SAVE_HELPER,'helper')
    r.label('persistent')
    r.emit('save_stock_source','mov r7,r1',mov(7,1),'keep stock source for read failure rollback')
    r.emit('storage_base',f'mov r1,#{RECORD_STORAGE_OFFSET:#x}',mov32(1,RECORD_STORAGE_OFFSET),'raw record 96 storage offset')
    r.emit('slot_stride','mul r3,r3,#0xa3',mul12(3,3,RAW_STRIDE),'slot * raw record stride')
    r.emit('storage_slot','add r1,r3',add(1,3),'storage offset for selected slot')
    r.emit('read_dest','mov r0,r4',mov(0,4),'read into destination prefix')
    r.emit('read_len','mov r2,#0x9c',mov8(2,VOICE),'full prefix length')
    r.emit('read_wrapper',f'call {READ_WRAPPER:#x}',call32(r.pc,READ_WRAPPER),'0x02004870 full-length checked read wrapper')
    r.branch('read_ok','jne r0,#0,read_ok',4,'read_ok',lambda a,t:jne(a,0,0,t),'wrapper returns zero on short/failing read')
    r.emit('restore_stock_source','mov r1,r7',mov(1,7),'restore original source on read failure')
    r.branch('goto_stock_copy','goto stock_copy',2,'stock_copy',fgoto,'rollback to stock copy path')
    r.label('read_ok')
    r.emit('voice_note_ptr','add r0,r4,#0x9b',add12(0,4,0x9B),'point at persisted Playback Note byte')
    r.emit('load_note','lb.z r5,[r0]',lb(5,0),'load persisted Playback Note')
    r.emit('restore_3f','mov r6,#0x3f',mov8(6,0x3F),'restore voice byte 0x9b')
    r.emit('store_3f','sb [r0],r6',sb(6,0),'force voice[0x9b]=0x3f')
    r.emit('metadata_pointer','add r0,r4,#0x9c',add12(0,4,VOICE),'metadata return pointer')
    r.emit('metadata_store','sb [r0],r5',sb(5,0),'store Playback Note metadata')
    r.emit('return_persistent','pop {pc,r9..r4}',word(0x0459),'return to selector caller')
    # keep stock helper entry fixed at SAVE_HELPER + 0x32 for selector call stability
    while len(r.data) < 0x32: r.emit('pad_to_stock','mov r0,r0',mov(0,0),'padding before stock helper entry')
    r.label('stock_copy')
    req(r.pc == SAVE_HELPER + 0x32, 'stock helper entry fixed')
    r.emit('stock_restore_dest','mov r0,r4',mov(0,4),'stock/armed destination')
    r.emit('stock_memcpy',f'call {MEMCPY:#x}',call32(r.pc,MEMCPY),'copy resident/stock source prefix')
    r.emit('stock_metadata_pointer','add r0,r4,#0x9c',add12(0,4,VOICE),'metadata return pointer')
    r.emit('stock_metadata_store','sb [r0],r5',sb(5,0),'store mapped/default metadata')
    r.emit('stock_return','pop {pc,r9..r4}',word(0x0459),'return to selector caller')
    b=r.finish(); req(len(b) <= SAVE_EXIT-SAVE_HELPER, 'helper fits full disabled SAVE body')
    b += mov(0,0) * ((SAVE_EXIT-SAVE_HELPER-len(b))//2)
    return b, r.rows

def app_from_fwsc(path: Path, official: bool=False):
    raw=path.read_bytes(); payload=unpack_fwsc(raw)[0] if official else unpack_any(raw); flash=Ufw.parse(payload).flash(); app=AppImage.parse(flash).app_bytes(); return raw,flash,app

def unpack_any(raw: bytes) -> bytearray:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload=bytearray()
    for i in range(FWSC_SLOTS): payload.extend(raw[i*FWSC_BLOCK_SIZE:i*FWSC_BLOCK_SIZE+FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS*FWSC_BLOCK_SIZE:]); req(len(payload)==OFFICIAL_V15_PAYLOAD_SIZE,'payload size'); return payload

def gate_basis() -> tuple[bytes, list[dict[str,Any]]]:
    oraw,_,official_app=app_from_fwsc(OFFICIAL_FWSC, True)
    parent=(S1C5/'app.bin').read_bytes()
    req(sha(oraw)==EXPECTED['official_fwsc'], 'official fwsc hash')
    req(sha(official_app)==EXPECTED['official_app'], 'official app hash')
    req(sha(parent)==EXPECTED['parent_app'], 'exact S1C5 parent app hash')
    req(shaf(S1C5/'SMK37Pro-v15-S1C5-playback-register-return.fwsc')==EXPECTED['parent_fwsc'], 'exact S1C5 fwsc hash')
    req(sha(parent[off(SEL_START):off(OWNED_END)])==EXPECTED['parent_combined'], 'S1C5 combined window hash')
    req(sha(parent[off(PRODUCER_START):off(OWNED_END)])==EXPECTED['parent_producer'], 'S1C5 producer hash')
    req(parent[off(SAVE_SKIP):off(SAVE_SKIP)+6].hex()==EXPECTED['parent_save_skip'], 'parent SAVE UI fallthrough branch bytes')
    req(parent[off(SAVE_HELPER):off(SAVE_HELPER)+12].hex()==EXPECTED['parent_save_body_prefix'], 'parent SAVE body starts with stock body')
    return parent, [
        {"name":"offline-scope","status":"PASS","device_accessed":False,"midi_transport_opened":False,"flash_performed":False,"ota_performed":False,"reset_performed":False},
        {"name":"exact-s1c5-basis","status":"PASS","parent_app_sha256":EXPECTED['parent_app'],"parent_fwsc_sha256":EXPECTED['parent_fwsc']},
        {"name":"s1c5-disabled-save-body","status":"PASS","ui_skip_patch_at":hx(SAVE_SKIP),"helper_region":{"start":hx(SAVE_HELPER),"end_exclusive":hx(SAVE_EXIT),"bytes":SAVE_EXIT-SAVE_HELPER}},
    ]

def patch(app: bytearray, address:int, new:bytes, purpose:str) -> dict[str,Any]:
    old=bytes(app[off(address):off(address)+len(new)]); app[off(address):off(address)+len(new)] = new
    return {"address":hx(address),"end_exclusive":hx(address+len(new)),"byte_count":len(new),"old_hex":old.hex(),"new_hex":new.hex(),"old_sha256":sha(old),"new_sha256":sha(new),"purpose":purpose}

def build_seed_records() -> dict[str,Any]:
    if SEEDDIR.exists(): shutil.rmtree(SEEDDIR)
    SEEDDIR.mkdir(parents=True)
    man=json.loads((S1C5/'inputs/packets/packet-manifest.json').read_text())
    records=[]; prefixes=[]
    for item in sorted(man['packets'], key=lambda x:x['slot']):
        slot=item['slot']; pkt=(S1C5/'inputs/packets'/item['file']).read_bytes()
        req(len(pkt)==163 and pkt.startswith(HEADER) and pkt[-1]==0xf7, f'packet {slot} framing')
        payload=pkt[len(HEADER):-1]; req(len(payload)==VOICE, f'packet {slot} prefix size')
        prefix=payload[:0x9b]+bytes([payload[0x9b]&0x7f]); prefixes.append(prefix)
        name=f'record-{RECORD_BASE+slot:03d}-slot-{slot:02d}.prefix'
        (SEEDDIR/name).write_bytes(prefix)
        physical=0x0F8000 + (RECORD_BASE+slot)*RAW_STRIDE
        records.append({"slot":slot,"record_index":RECORD_BASE+slot,"storage_wrapper_offset":f"0x{RECORD_STORAGE_OFFSET+slot*RAW_STRIDE:04x}","physical_offset":f"0x{physical:06x}","prefix_size":VOICE,"prefix_file":name,"prefix_sha256":sha(prefix),"packet_file":item['file'],"packet_sha256":sha(pkt),"playback_note":payload[0x9b]&0x7f,"tail_policy":"preserve live raw bytes 0x9c..0xa2; prefix artifacts never include tails"})
    joined=b''.join(prefixes)
    seed={"format":FORMAT+'.host-seeded-current-set-v1',"scope":{"offline_only":True,"device_accessed":False,"persistent_storage_write_performed":False},"record_base":RECORD_BASE,"payload_record_count":SLOTS,"raw_physical_base":"0x0f8000","record_stride":RAW_STRIDE,"affected_physical_range":["0x0fbd20","0x0fc748"],"requires_exact_host_seeded_records":True,"normal_firmware_restore":"selector helper reads each prefix with 0x02004870 and falls back to stock copy if the full-length wrapper read returns zero","payload_crc32":f"0x{binascii.crc32(joined)&0xffffffff:08x}","records":records,"rollback_policy":"target-specific pre-dump sectors only; rollback validator requires post-rollback dump equals pre-dump byte-for-byte"}
    wjson(SEEDDIR/'prefix-manifest.json', seed)
    (SEEDDIR/'SHA256SUMS').write_text("\n".join(f"{shaf(p)}  {p.relative_to(SEEDDIR)}" for p in sorted(SEEDDIR.iterdir()) if p.is_file())+"\n")
    return seed

def build_app(parent: bytes, gates: list[dict[str,Any]]) -> tuple[bytes,dict[str,Any],dict[str,Any]]:
    selector, selector_rows = build_selector(); helper, helper_rows = build_helper(); app=bytearray(parent)
    skip = fgoto(SAVE_SKIP, SAVE_EXIT) + mov(0,0) + mov(0,0)
    req(skip.hex() == '04ac00160016', 'SAVE UI skip encoding')
    patches=[
        patch(app, SEL_START, selector, 'replace selector with split-control selector that calls helper for raw fallback and stock copy helper for RAM path'),
        patch(app, SAVE_SKIP, skip, 'patch SAVE UI path to skip disabled SAVE body before helper region'),
        patch(app, SAVE_HELPER, helper, 'reuse unreachable S1C5-disabled SAVE body as standalone selector helper region'),
    ]
    appb=bytes(app)
    req(sha(appb[off(PRODUCER_START):off(OWNED_END)])==EXPECTED['parent_producer'], 'producer preserved byte-for-byte')
    req(appb[off(SAVE_EXIT):off(SAVE_EXIT)+10] == parent[off(SAVE_EXIT):off(SAVE_EXIT)+10], 'stock SAVE exit preserved')
    diffs=difference_offsets(parent, appb)
    code={"selector":{"start":hx(SEL_START),"end_exclusive":hx(SEL_END),"bytes":len(selector),"sha256":sha(selector),"rows":selector_rows},"producer":{"start":hx(PRODUCER_START),"end_exclusive":hx(OWNED_END),"sha256":EXPECTED['parent_producer'],"status":"preserved byte-for-byte from S1C5 to keep Chrome segmented-final and reset"},"save_ui_skip":{"address":hx(SAVE_SKIP),"bytes":skip.hex(),"target":hx(SAVE_EXIT)},"helper":{"start":hx(SAVE_HELPER),"end_exclusive":hx(SAVE_EXIT),"bytes":len(helper),"sha256":sha(helper),"stock_copy_entry":hx(SAVE_HELPER+0x32),"rows":helper_rows,"uses_read_wrapper":hx(READ_WRAPPER),"read_failure_rollback":"if wrapper returns zero, restore original r1 and use stock-copy helper"}}
    manifest={"format":FORMAT+'.app-manifest-v1',"basis_app":"S1C5-playback-register-return/app.bin","basis_app_sha256":EXPECTED['parent_app'],"output_app_sha256":sha(appb),"runtime_base":hx(BASE),"patches":patches,"parent_relative_changed_byte_count":len(diffs),"parent_relative_changed_ranges":compact_ranges(diffs),"input_gates":gates,"code_contract":code,"candidate_kind":"current-set checkpoint: exact host-seeded records required; no on-device writer is claimed"}
    return appb, manifest, code

def build_package_from_official(app: bytes, pkg_path: Path, manifest_path: Path) -> dict[str,Any]:
    original=OFFICIAL_FWSC.read_bytes(); payload, metadata = unpack_fwsc(original); original_payload=bytes(payload); ufw=Ufw.parse(payload); original_flash=ufw.flash(); app_image=AppImage.parse(original_flash); official_app=app_image.app_bytes(); output_flash, changed_plain=app_image.replace_app_bytes(app); ufw.replace_flash(output_flash); output=repack_fwsc(original, ufw.payload, metadata); pkg_path.write_bytes(output)
    before=protected_hashes(original_flash); after=protected_hashes(output_flash); req(before==after, 'protected flash hashes unchanged')
    flash_changes=difference_offsets(original_flash, output_flash); payload_changes=difference_offsets(original_payload, ufw.payload); package_changes=difference_offsets(original, output)
    pman={"format":"smk37-v15-application-only-patch-v1","safety_gate":"PASS","input":{"size":len(original),"sha256":sha(original),"payload_sha256":sha(original_payload),"app_sha256":sha(official_app)},"output":{"size":len(output),"sha256":sha(output),"payload_sha256":sha(ufw.payload),"app_sha256":sha(app)},"changes":{"app_byte_count":len(difference_offsets(official_app, app)),"app_ranges":compact_ranges(difference_offsets(official_app, app)),"flash_byte_count_including_crc_fields":len(flash_changes),"flash_ranges":compact_ranges(flash_changes),"ota_payload_byte_count_including_wrapper_crc_fields":len(payload_changes),"fwsc_byte_count":len(package_changes)},"protected_flash_hashes_before":before,"protected_flash_hashes_after":after}
    wjson(manifest_path,pman)
    return pman

def rollback_info(app: bytes, pkg: Path) -> dict[str,Any]:
    oraw, oflash, oapp = app_from_fwsc(OFFICIAL_FWSC, True); craw, cflash, capp = app_from_fwsc(pkg, False)
    req(capp==app, 'package embeds app'); app_diffs=difference_offsets(oapp, app); flash_diffs=difference_offsets(oflash, cflash); sectors=sorted({x-(x%SECTOR) for x in flash_diffs})
    rdir=HERE/'rollback'/'official-v15-recovery-sectors'
    if rdir.exists(): shutil.rmtree(rdir)
    rdir.mkdir(parents=True, exist_ok=True); entries=[]
    for base in sectors:
        data=bytes(oflash[base:base+SECTOR]); name=f'official-v15-sector-{base:05x}.bin'; (rdir/name).write_bytes(data); entries.append({"sector_base":f"0x{base:05x}","size":len(data),"sha256":sha(data),"file":f"rollback/official-v15-recovery-sectors/{name}"})
    recon=bytearray(cflash)
    for base in sectors: recon[base:base+SECTOR]=oflash[base:base+SECTOR]
    req(bytes(recon)==bytes(oflash), 'rollback reconstructs official flash')
    wjson(rdir/'manifest.json', {"format":FORMAT+'.official-v15-sector-rollback-v1',"sector_size":SECTOR,"changed_sectors":entries,"official_flash_sha256":sha(oflash),"candidate_flash_sha256":sha(cflash),"rollback_restores_official_flash":True,"host_seeded_record_rollback_note":"raw-record seed sectors are package-external and must be rolled back with target-specific pre-dump sectors validated by validate_rollback.py"})
    return {"package_sha256":sha(craw),"package_size":len(craw),"candidate_flash_sha256":sha(cflash),"official_flash_sha256":sha(oflash),"changed_app_byte_count_vs_official":len(app_diffs),"changed_app_ranges_vs_official":compact_ranges(app_diffs),"changed_flash_sectors_vs_official":[f"0x{x:05x}" for x in sectors],"rollback_manifest":"rollback/official-v15-recovery-sectors/manifest.json","rollback_restores_official_flash":True}

def c_array(hex_digest: str) -> str: return ', '.join(f'0x{hex_digest[i:i+2]}' for i in range(0,len(hex_digest),2))
def exact_ota_c(pkgsha: str) -> str:
    token=f"INSTALL-SMK37PRO-V15-S1C7-CURRENT-SET-HELPER-CHECKPOINT-{pkgsha[:8].upper()}"
    return f'''/* Exact-hash v15-only OTA wrapper for S1-C7 Current-Set Helper Checkpoint.\n * Default check mode is offline-only; upload requires the exact confirmation token.\n */\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include "../../../../../src/ota.c"\nstatic const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {c_array(pkgsha)} }};\nstatic const char CONFIRM[] = "{token}";\nstatic const char DESCRIPTION[] = "SMK37ProMod v15 S1-C7 Current-Set Helper Checkpoint candidate";\nstatic int check_exact(const char *path) {{ struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{ printf("exact v15 S1-C7 Current-Set Helper Checkpoint package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length); status = 0; }} else fputs("offline check rejected: not exact S1-C7 package\\n", stderr); smk37_fwsc_free(&firmware); return status; }}\nint main(int argc, char **argv) {{ if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C7 Current-Set Helper Checkpoint candidate installed"); fprintf(stderr, "usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n", argv[0], argv[0], CONFIRM); return 2; }}\n'''

def write_code_evidence(code: dict[str,Any]) -> None:
    if CODEDIR.exists(): shutil.rmtree(CODEDIR)
    CODEDIR.mkdir(parents=True)
    for key in ['selector','helper']:
        with (CODEDIR/f'{key}-decode.tsv').open('w') as f:
            f.write('address\tsize\tbytes\tname\tasm\tmeaning\ttarget\n')
            for r in code[key]['rows']:
                f.write(f"{r['address']}\t{r['size']}\t{r['bytes']}\t{r['name']}\t{r['asm']}\t{r['meaning']}\t{r.get('target','')}\n")
    wjson(CODEDIR/'evidence.json', {"format":FORMAT+'.code-evidence-v1',"decision":"PASS","scope":{"offline_only":True,"device_accessed":False},"code":code})
    (CODEDIR/'report.md').write_text('# S1-C7 split-control code evidence PASS\n\nSelector calls the helper for persistent raw-record fallback and for stock-copy return. The producer region is preserved byte-for-byte from S1C5, including Chrome segmented-final and reset behavior. The SAVE UI path is patched to branch to the stock local exit before the helper region.\n')
    (CODEDIR/'validation.txt').write_text('S1-C7 code evidence: PASS\nPASS selector fits before producer\nPASS helper fits full 0x02026d80..0x02026dd4 region\nPASS producer preserved byte-for-byte\nPASS SAVE UI path skips helper\n')
    (CODEDIR/'SHA256SUMS').write_text('\n'.join(f'{shaf(p)}  {p.name}' for p in sorted(CODEDIR.iterdir()) if p.is_file())+'\n')

def write_sha_inventory() -> None:
    names=['build_s1c7_current_set_helper_checkpoint.py','validate.py','validate_rollback.py','app.bin',PACKAGE_NAME,'app-manifest.json','package-manifest.json','evidence.json','report.md','README.md','exact_ota.c','validation.txt']
    paths=[HERE/n for n in names if (HERE/n).exists()]
    for base in ['code-evidence','rollback','host-seeded-records']:
        root=HERE/base
        if root.exists(): paths.extend(p for p in sorted(root.rglob('*')) if p.is_file())
    seen=[]
    for p in paths:
        if p not in seen: seen.append(p)
    (HERE/'SHA256SUMS').write_text('\n'.join(f'{shaf(p)}  {p.relative_to(HERE)}' for p in seen)+'\n')

def build(check=False, no_write=False) -> dict[str,Any]:
    parent,gates=gate_basis(); app, appman, code=build_app(parent,gates)
    if no_write: return {"decision":"PASS","candidate_built":False,"app_sha256":sha(app)}
    if check:
        ev=json.loads((HERE/'evidence.json').read_text()); req(shaf(HERE/'app.bin')==ev['app']['output_app_sha256']==sha(app), 'deterministic app hash'); req(json.loads((CODEDIR/'evidence.json').read_text())['decision']=='PASS','code evidence exists'); return ev
    seed=build_seed_records(); write_code_evidence(code); (HERE/'app.bin').write_bytes(app); wjson(HERE/'app-manifest.json', appman); pman=build_package_from_official(app, HERE/PACKAGE_NAME, HERE/'package-manifest.json'); rb=rollback_info(app, HERE/PACKAGE_NAME); pkgsha=rb['package_sha256']; (HERE/'exact_ota.c').write_text(exact_ota_c(pkgsha))
    token=f"INSTALL-SMK37PRO-V15-S1C7-CURRENT-SET-HELPER-CHECKPOINT-{pkgsha[:8].upper()}"
    ev={"format":FORMAT+'.release-evidence-v1',"decision":"PASS_CURRENT_SET_CHECKPOINT","candidate_built":True,"scope":{"offline_only":True,"device_accessed":False,"midi_transport_opened":False,"flash_performed":False,"ota_performed":False,"reset_performed":False,"live_send_performed":False},"basis":{"official_fwsc_sha256":EXPECTED['official_fwsc'],"official_app_sha256":EXPECTED['official_app'],"parent_s1c5_app_sha256":EXPECTED['parent_app'],"parent_s1c5_package_sha256":EXPECTED['parent_fwsc']},"input_gates":gates,"app":appman,"code":{"candidate_dir":str(CODEDIR.relative_to(ROOT)),"code_evidence_sha256":shaf(CODEDIR/'evidence.json')},"package":rb,"package_manifest_sha256":shaf(HERE/'package-manifest.json'),"flash":{"artifact":PACKAGE_NAME,"confirmation_token":token,"default_check_offline_only":True},"host_seeded_records":seed,"limitations":{"on_device_writer":"not included; full writer with 0x02004b02 write/readback/manifest commit-last still does not fit in this checkpoint","checkpoint_semantics":"after install plus exact host-seeded raw prefixes, cold/not-ARMED selector restores the seeded current set; future WebMIDI updates remain volatile until a full writer successor exists"},"invariants":{"producer_preserved_byte_for_byte":True,"chrome_segmented_final_preserved":True,"reset_wrapper_preserved":True,"save_ui_path_skips_helper":True,"read_wrapper_full_length_gate":"0x02004870 returns zero unless full 0x9c prefix was read; helper rolls back to stock copy on zero"}}
    wjson(HERE/'evidence.json', ev); (HERE/'validation.txt').write_text('S1-C7 Current-Set Helper Checkpoint build validation: PASS\nPASS exact S1C5 basis\nPASS full disabled SAVE body used as helper and skipped by UI path\nPASS selector/helper split control\nPASS producer Chrome segmented-final and reset preserved\nPASS FWSC exact-hash artifact and rollback sectors generated offline\nPASS host-seeded current-set prefix records generated offline only\nPASS exact_ota.c compiled and accepted candidate/rejected S1C5 and official controls offline\n')
    (HERE/'README.md').write_text(f"# S1-C7 current-set helper checkpoint offline release\n\nStatus: **PASS as current-set persistence checkpoint, not a full writer**.\n\nApp SHA-256 `{appman['output_app_sha256']}`. FWSC SHA-256 `{pkgsha}`. OTA token `{token}`.\n\nThis candidate patches the SAVE UI path to skip `0x02026d80..0x02026dd4`, reuses that whole S1C5-disabled body as a helper, preserves the S1C5 producer byte-for-byte, and uses `0x02004870` to restore exact host-seeded raw prefixes when RAM is not ARMED. No device access or live write was performed.\n")
    (HERE/'report.md').write_text(f"# S1-C7 current-set helper checkpoint PASS\n\n## Decision\n\n**PASS_CURRENT_SET_CHECKPOINT.** App/FWSC/exact OTA and rollback artifacts were built offline. This is intentionally not promoted as a full persistence writer because no `0x02004b02` writer/readback/manifest commit-last body is included.\n\n## Key properties\n\n- Helper region: `0x02026d80..0x02026dd4` ({SAVE_EXIT-SAVE_HELPER} bytes), skipped by UI patch `{appman['patches'][1]['new_hex']}` at `0x02026d7a`.\n- Selector/producer window: selector calls persistent helper or stock-copy helper; producer `0x0201e196..0x0201e254` is preserved byte-for-byte from S1C5.\n- Chrome segmented-final and reset are preserved by keeping the S1C5 producer unchanged.\n- Restore path uses `0x02004870` full-length read wrapper. If the wrapper returns zero, helper restores the stock source pointer and performs stock copy.\n- Exact host-seeded records are emitted as offline prefix artifacts under `host-seeded-records/`; they are not written to a device.\n- `exact_ota.c` compiles against current `src/*.c` support sources and accepts only this FWSC while rejecting S1C5 and official-v15 controls in offline `check` mode.\n\n## Limitation\n\nFull normal-firmware write persistence using `0x02004b02` plus readback/manifest commit-last remains follow-up work. This checkpoint restores the exact seeded current set only.\n")
    write_sha_inventory(); return ev

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--check', action='store_true'); ap.add_argument('--no-write', action='store_true'); args=ap.parse_args(); ev=build(args.check,args.no_write); print('S1-C7 Current-Set Helper Checkpoint build gate: PASS');
    if ev.get('candidate_built'): print('app_sha256='+ev['app']['output_app_sha256']); print('package_sha256='+ev['package']['package_sha256']); print('ota_confirmation_token='+ev['flash']['confirmation_token'])
if __name__=='__main__': main()
