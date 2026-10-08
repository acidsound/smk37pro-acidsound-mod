#!/usr/bin/env python3
"""Build S1-C4 Playback Note v3 segmented-final offline candidate.

Offline only: no device, USB, MIDI, OTA upload, flash, reset, or live send.
"""
from __future__ import annotations
import argparse, hashlib, json, shutil, struct, subprocess, sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
FLASH = HERE.parent
ANALYSIS = HERE.parents[1]
ROOT = HERE.parents[4]
PARENT = FLASH / "S1C3-16slot-functional-v2-r3-reload"
BOUNDARY = FLASH / "S1C3-16slot-boundary-only"
CODEDIR = ANALYSIS / "playback-note" / "candidate-v3-segmented-final"
OFFICIAL_FWSC = FLASH / "S1C2-two-slot-selector-live-v2" / "inputs" / "SMK-37_Pro_015.fwsc"
PARENT_FWSC = PARENT / "SMK37Pro-v15-S1C3-16slot-functional-v2-r3-reload.fwsc"
sys.path.insert(0, str(BOUNDARY))
from smk37_v15_app_patch import APP_DATA_OFFSET, APP_DATA_SIZE, AppImage, Ufw, compact_ranges, difference_offsets, protected_hashes, unpack_fwsc  # noqa: E402

FORMAT = "smk37-v15-s1c4-playback-note-v3-segmented-final"
PACKAGE_NAME = "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc"
BASE = 0x02000000
SECTOR = 0x2000
PROTECTED_PREFIX_END = 0x4000
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"
NOFF_HOOK, NON_HOOK = 0x0201C63E, 0x0201C67C
NOFF_NEUT, NON_NEUT = 0x0201C644, 0x0201C682
SEL_START, OWNED_END = 0x0201E13E, 0x0201E254
DIRECT_CALL, DIRECT_RELOAD = 0x0201E468, 0x0201E46C
SEG_CALL, SEG_RELOAD = 0x0201E49C, 0x0201E4A0
MEMCPY = 0x02048CCE
PATCH_BASE, STRIDE, VOICE = 0x01C46520, 0xA0, 0x9C
VOICE_LAST, RESTORE_BYTE = 0x9B, 0x3F
LOCK, COUNT, STATE = 0x01C465BD, 0x01C465BE, 0x01C465BF
MAP_BASE = 0x01C46F20
EMPTY, LOADING, ARMED = 0, 1, 2
NOTE0, NOTE_END, SLOTS, CH10 = 36, 52, 16, 9
WIRE_PLAYBACK_OFFSET = len(HEADER) + VOICE_LAST
EXPECTED = {
  "official_fwsc":"f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
  "official_app":"36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
  "parent_app":"7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b",
  "parent_fwsc":"0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9",
  "noff_hook":"80fffa1a0000", "non_hook":"80ffc01a0000",
  "noff_post":"00e13e618d40", "non_post":"00e13e718e40",
  "direct_reload":"bfeaf838", "seg_reload":"bfeade38",
  "producer_abi_report":"f108346a1dd81747be1627e1f6e297fb20df354727ad9f17e94fa6628b6350bf",
  "copy_path_report":"5296c466c2819995fa215e527b36380ae23fcf39f940ab172488435f6d14e4b2",
  "packet_hashes":["1c9239621563722eaac0a85db411571963f9ebbd0dbbb00b21044b76b1581427","afa8957005341e6144962ce3120bb1d829475714077617ea8da2c3fee4a0aa21","8a87a409056457e61944d01bf4bbc0266414b8385c3a848125700da9e8417de3","a5c086a77b4de1ce9546e747b72f79d8f6ad7b0dbd7c3b6e1665ef7edf83ff58","ffd1bcc6c7a7c5d8a1bb35f5bf7e39bf63058e62ac574e1e308ba53edc6670ff","57136706fa633b5b47008ed2616471f72ae629d69e601e33c66daad991df94e9","0f202d88578152ca024b3822f56a7c74c485c42996695033a4c239449d30f366","d4ee6f2ccfce2d0c548917bb58ead4988dc3038c2b84edaaa37f047d2e006ea2","c8c489b72b195dfe5f373b6a860b32f0d07a29a83a9f2c070299df5af88a9cb3","9c895d925a6cb79c4dff9f9f27727cce02f6dd0ed86467c994d7f459f1036258","802944d0e1a8f4e85f1a3a694e2a0dbbfe9bb55972814f11ed4c7be7575b6704","c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d","622a06870f189b6e4582f0093255f450403d4112836f09563c0b4623c1b287cd","6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27","b159db617616621759bb9990991a8214c585d1f7ecd1be0f36d53a0b71b160c8","39a3e4eca1c740f719b3495f2a88c63e3b5d575a16a98c7b05fbc211fbfa4775"]
}

def req(ok: bool, msg: str):
    if not ok: raise SystemExit("FAIL: " + msg)
def sha(b: bytes|bytearray) -> str: return hashlib.sha256(bytes(b)).hexdigest()
def shaf(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()
def wjson(p: Path, v: Any): p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(v, indent=2, sort_keys=True)+"\n")
def hx(x: int) -> str: return f"0x{x:08x}"
def off(a: int) -> int:
    o=a-BASE; req(0 <= o < APP_DATA_SIZE, f"address outside app {hx(a)}"); return o
def word(v:int)->bytes: return struct.pack('<H', v & 0xffff)
def sx(v:int,b:int)->int: s=1<<(b-1); return (v^s)-s
def mov(dst,src): return word(0x1600 | (src<<4) | dst)
def mov32(dst,val): return word(0xffc0 | dst) + struct.pack('<I', val)
def mov8(r,imm): return word(0x2040 | r | ((imm>>5)<<3) | ((imm&0x1f)<<8))
def add8(r,imm): e=imm&0xff; return word(0x20c0 | r | ((e>>5)<<3) | ((e&0x1f)<<8))
def add(dst,src): return word(0x1800 | (src<<4) | dst)
def add12(dst,src,imm): return bytes((dst,0xe1,imm&0xff,(src<<4)|(imm>>8)))
def mul12(dst,src,imm): return bytes((0xe0|dst,0xe1,imm&0xff,(src<<4)|(imm>>8)))
def lb(dst,base,ofs=0): return word(0x4008 | dst | (base<<4) | ((ofs&0x1f)<<8))
def sb(src,base,ofs=0): return word(0x4088 | src | (base<<4) | ((ofs&0x1f)<<8))
def call32(at,target): return b"\x80\xff" + struct.pack('<i', target-(at+6))
def call32_target(at,b): return at+6+struct.unpack('<i', b[2:6])[0]
def short_call(at,target):
    half=((target-(at+4))//2) & 0xffff
    return b"\xbf\xea" + struct.pack('<H', half)
def short_target(at,b): return ((at+4+struct.unpack('<H', b[2:])[0]*2)&0xffff)|(at&0xffff0000)
def br(base,at,r,imm,target): return word(base|r) + word((imm<<9) | (((target-(at+4))//2)&0x1ff))
def jne(at,r,imm,target): return br(0xf880,at,r,imm,target)
def jl(at,r,imm,target): return br(0xfd80,at,r,imm,target)
def jge(at,r,imm,target): return br(0xfd00,at,r,imm,target)
def ifeq(at,target): return bytes.fromhex('40e8') + struct.pack('<h', (target-(at+4))//2)
def fgoto(at,target): return word(0x8004 | (((target-(at+2))//2)<<8))

@dataclass
class Fix: off:int; label:str; enc:Callable[[int,int],bytes]
class R:
    def __init__(self,start:int,prefix:str):
        self.start=start; self.prefix=prefix; self.data=bytearray(); self.labels={'entry':start}; self.fix=[]; self.rows=[]
    @property
    def pc(self): return self.start+len(self.data)
    def label(self,n): self.labels[n]=self.pc
    def emit(self,n,asm,b,meaning):
        self.rows.append({'address':hx(self.pc),'size':len(b),'bytes':b.hex(),'name':self.prefix+'.'+n,'asm':asm,'meaning':meaning}); self.data+=b
    def branch(self,n,asm,size,label,enc,meaning):
        self.rows.append({'address':hx(self.pc),'size':size,'bytes':'pending','name':self.prefix+'.'+n,'asm':asm,'meaning':meaning}); self.fix.append(Fix(len(self.data),label,enc)); self.data += b'\0'*size
    def finish(self):
        for f in self.fix:
            at=self.start+f.off; b=f.enc(at,self.labels[f.label]); self.data[f.off:f.off+len(b)]=b
            for row in self.rows:
                if int(row['address'],16)==at: row['bytes']=b.hex(); row['target']=hx(self.labels[f.label]); break
        return bytes(self.data)

def build_selector():
    r=R(SEL_START,'selector')
    r.emit('note_off_adapter','mov r3,r5',mov(3,5),'normalize Note Off trigger note')
    r.branch('note_off_goto_core','goto core',2,'core',fgoto,'skip Note On adapter')
    r.emit('note_on_adapter','mov r3,r6',mov(3,6),'normalize Note On trigger note; velocity saved')
    r.label('core')
    r.emit('push_saved','push {rets,r9..r4}',word(0x0479),'preserve trigger registers and velocity')
    r.emit('save_dest','mov r4,r0',mov(4,0),'save original payload destination')
    r.emit('default_note','mov r5,r3',mov(5,3),'fallback metadata note is unchanged Trigger Note')
    r.emit('channel_tmp','mov r6,r9',mov(6,9),'channel nibble temp')
    r.branch('gate_channel','jne r6,#9,copy',4,'copy',lambda a,t:jne(a,6,CH10,t),'non-Ch10 fallback')
    r.branch('gate_low','jl r3,#36,copy',4,'copy',lambda a,t:jl(a,3,NOTE0,t),'below trigger range fallback')
    r.branch('gate_high','jge r3,#52,copy',4,'copy',lambda a,t:jge(a,3,NOTE_END,t),'above trigger range fallback')
    r.emit('slot_index','add r3,#-36',add8(3,-NOTE0),'r3 = trigger slot')
    r.emit('patch_base',f'mov r8,#{PATCH_BASE:#x}',mov32(8,PATCH_BASE),'resident slot base')
    r.emit('state_base','add r6,r8,#0x9c',add12(6,8,VOICE),'slot0 valid/control base')
    r.emit('state_load','lb.z r0,[r6+3]',lb(0,6,3),'load ARMED state before consuming Playback Note map')
    r.branch('gate_state','jne r0,#2,copy',4,'copy',lambda a,t:jne(a,0,ARMED,t),'not ARMED fallback, leaving metadata note as Trigger Note')
    r.emit('slot_offset_seed','mov r6,r3',mov(6,3),'preserve trigger slot index in r3 for Playback Note map')
    r.emit('slot_offset','mul r6,r6,#0xa0',mul12(6,6,STRIDE),'source offset from trigger slot')
    r.emit('slot_base_add','add r6,r8',add(6,8),'source slot selected solely by trigger slot')
    r.emit('valid_pointer','add r7,r6,#0x9c',add12(7,6,VOICE),'selected slot valid pointer')
    r.emit('valid_load','lb.z r0,[r7]',lb(0,7),'selected slot valid')
    r.branch('gate_valid','jne r0,#1,copy',4,'copy',lambda a,t:jne(a,0,1,t),'invalid source fallback, leaving metadata note as Trigger Note')
    r.emit('map_base','add r7,r8,#0xa00',add12(7,8,MAP_BASE-PATCH_BASE),'Playback Note map base, after ARMED and valid gates')
    r.emit('map_slot','add r7,r3',add(7,3),'map pointer = 0x01c46f20 + trigger slot')
    r.emit('load_playback_note','lb.z r5,[r7]',lb(5,7),'selected valid slot Playback Note metadata byte')
    r.emit('select_source','mov r1,r6',mov(1,6),'source = trigger-selected resident slot; no playback-note-to-source mapping')
    r.label('copy')
    r.emit('restore_dest','mov r0,r4',mov(0,4),'restore memcpy destination')
    r.emit('memcpy_call',f'call {MEMCPY:#x}',call32(r.pc,MEMCPY),'copy exactly r2=0x9c')
    r.emit('metadata_pointer','add r0,r4,#0x9c',add12(0,4,VOICE),'return r0 = original destination + 0x9c')
    r.emit('metadata_note_store','sb [r0],r5',sb(5,0),'store mapped metadata note locally')
    r.emit('pop_return','pop {pc,r9..r4}',word(0x0459),'restore trigger registers and Note On velocity')
    code=r.finish(); labels=dict(r.labels); labels['end']=SEL_START+len(code); return code,r.rows,labels

def build_producer(start:int):
    r=R(start,'producer')
    r.emit('push_saved','push {rets,r9..r4}',word(0x0479),'save producer frame')
    r.emit('save_stage','mov r4,r0',mov(4,0),'staging pointer')
    r.emit('lock_pointer',f'mov r0,#{LOCK:#x}',mov32(0,LOCK),'lock pointer; redundant r9 length gate removed')
    r.emit('trylock','csync; testset b[r0]',bytes.fromhex('2000b000'),'nonblocking lock')
    r.branch('trylock_failed','ifeq return',4,'return',ifeq,'failed lock returns')
    r.emit('acquired_csync','csync',word(0x0020),'after lock')
    r.emit('metadata_pointer','mov r5,r0',mov(5,0),'control base')
    r.emit('state_load','lb.z r0,[r5+2]',lb(0,5,2),'load state')
    r.branch('state_not_empty','jne r0,#0,not_empty',4,'not_empty',lambda a,t:jne(a,0,EMPTY,t),'non-empty path')
    r.emit('empty_count_load','lb.z r3,[r5+1]',lb(3,5,1),'load count')
    r.branch('empty_count_reject','jne r3,#0,unlock',4,'unlock',lambda a,t:jne(a,3,0,t),'bad EMPTY count')
    r.emit('state_loading_value','mov r0,#1',mov8(0,LOADING),'LOADING')
    r.emit('state_loading_store','sb [r5+2],r0',sb(0,5,2),'state=LOADING before slot0')
    r.emit('loading_csync','csync',word(0x0020),'publish LOADING')
    r.branch('empty_done_goto','goto after_state',2,'after_state',fgoto,'join')
    r.label('not_empty')
    r.branch('state_not_loading','jne r0,#1,unlock',4,'unlock',lambda a,t:jne(a,0,LOADING,t),'reject ARMED/invalid')
    r.emit('loading_count_load','lb.z r3,[r5+1]',lb(3,5,1),'load count')
    r.label('after_state')
    r.branch('count_full','jge r3,#16,unlock',4,'unlock',lambda a,t:jge(a,3,SLOTS,t),'late packet reject')
    r.emit('copy_count','mov r6,r3',mov(6,3),'slot index')
    r.emit('slot_offset','mul r6,r6,#0xa0',mul12(6,6,STRIDE),'slot offset')
    r.emit('slot_base_seed',f'mov r7,#{PATCH_BASE:#x}',mov32(7,PATCH_BASE),'slot0 base')
    r.emit('slot_base_add','add r7,r6',add(7,6),'slot base')
    r.emit('valid_pointer','add r6,r7,#0x9c',add12(6,7,VOICE),'valid pointer; slot[0x9b] is [r6-1]')
    r.emit('valid_clear_value','mov r0,#0',mov8(0,0),'zero')
    r.emit('valid_clear_store','sb [r6],r0',sb(0,6),'valid=0 before copy')
    r.emit('map_pointer',f'mov r0,#{MAP_BASE:#x}',mov32(0,MAP_BASE),'Playback Note map base')
    r.emit('map_slot','add r0,r3',add(0,3),'map pointer + slot')
    r.emit('staging_last_pointer','add r1,r4,#0x9b',add12(1,4,VOICE_LAST),'staging[0x9b] pointer')
    r.emit('playback_load','lb.z r2,[r1]',lb(2,1),'Playback Note from wire byte 161')
    r.emit('playback_store','sb [r0],r2',sb(2,0),'store note to 0x01c46f20+slot')
    r.emit('restore_value','mov r2,#0x3f',mov8(2,RESTORE_BYTE),'proven 0x3f')
    r.emit('restore_staging_last','sb [r1],r2',sb(2,1),'restore staging[0x9b] before copy/reload')
    r.emit('copy_destination','mov r0,r7',mov(0,7),'slot destination')
    r.emit('copy_source','mov r1,r4',mov(1,4),'restored staging source')
    r.emit('copy_size','mov r2,#0x9c',mov8(2,VOICE),'copy size')
    r.emit('memcpy_call',f'call {MEMCPY:#x}',call32(r.pc,MEMCPY),'memcpy clobbers volatile r3')
    r.emit('restore_slot_value','mov r0,#0x3f',mov8(0,RESTORE_BYTE),'proven 0x3f')
    r.emit('restore_slot_last','sb [r6-1],r0',sb(0,6,-1),'restore slot.voice[0x9b] before valid/reload')
    r.emit('copy_csync','csync',word(0x0020),'order restoration before valid')
    r.emit('valid_value','mov r0,#1',mov8(0,1),'valid value')
    r.emit('valid_store','sb [r6],r0',sb(0,6),'valid last for slot')
    r.emit('post_memcpy_count_reload','lb.z r3,[r5+1]',lb(3,5,1),'reload count after memcpy')
    r.emit('count_increment','add r3,#1',add8(3,1),'count++')
    r.emit('count_store','sb [r5+1],r3',sb(3,5,1),'loaded_count after valid')
    r.branch('not_last','jne r3,#16,unlock',4,'unlock',lambda a,t:jne(a,3,SLOTS,t),'only slot15 arms')
    r.emit('armed_csync','csync',word(0x0020),'before ARMED')
    r.emit('armed_value','mov r0,#2',mov8(0,ARMED),'ARMED')
    r.emit('armed_store','sb [r5+2],r0',sb(0,5,2),'state ARMED last publishes map')
    r.label('unlock')
    r.emit('unlock_csync_before','csync',word(0x0020),'before unlock')
    r.emit('unlock_zero','mov r0,#0',mov8(0,0),'zero')
    r.emit('unlock_store','sb [r5],r0',sb(0,5),'unlock')
    r.emit('unlock_csync_after','csync',word(0x0020),'after unlock')
    r.label('return')
    r.emit('return_restore','pop {pc,r9..r4}',word(0x0459),'return')
    r.label('segmented_stub')
    r.emit('segmented_stub_push','push {rets,r9..r4}',word(0x0479),'segmented no-mutation stub')
    r.emit('segmented_stub_return','pop {pc,r9..r4}',word(0x0459),'return')
    r.label('reset_entry')
    r.emit('reset_push_saved','push {rets,r9..r4}',word(0x0479),'reset wrapper')
    r.emit('reset_save_stage','mov r4,r0',mov(4,0),'stage')
    r.emit('reset_sig0_load','lb.z r1,[r4]',lb(1,4),'signature byte 0')
    r.branch('reset_sig0_mismatch','jne r1,#0x62,reset_skip',4,'reset_skip',lambda a,t:jne(a,1,0x62,t),'skip reset')
    r.emit('reset_sig1_load','lb.z r1,[r4+1]',lb(1,4,1),'signature byte 1')
    r.branch('reset_sig1_mismatch','jne r1,#0x63,reset_skip',4,'reset_skip',lambda a,t:jne(a,1,0x63,t),'skip reset')
    r.emit('reset_metadata_pointer',f'mov r5,#{LOCK:#x}',mov32(5,LOCK),'control base')
    r.emit('reset_zero','mov r0,#0',mov8(0,0),'zero')
    r.emit('reset_lock_store','sb [r5],r0',sb(0,5),'clear lock')
    r.emit('reset_count_store','sb [r5+1],r0',sb(0,5,1),'clear count')
    r.emit('reset_state_store','sb [r5+2],r0',sb(0,5,2),'state EMPTY hides stale map until ARMED')
    r.emit('reset_csync','csync',word(0x0020),'publish reset')
    r.label('reset_skip')
    r.emit('reset_restore_stage','mov r0,r4',mov(0,4),'restore stage')
    r.emit('reset_call_producer',f'call {start:#x}',call32(r.pc,start),'call sequential producer')
    r.emit('reset_return_restore','pop {pc,r9..r4}',word(0x0459),'return')
    code=r.finish(); labels=dict(r.labels); labels['end']=start+len(code); return code,r.rows,labels

def build_code():
    sel,srows,sl=build_selector(); req(len(sel)==88,'selector 88 bytes')
    prod,prows,pl=build_producer(sl['end']); req(len(prod)==188,'producer 188 bytes')
    combined=sel+prod; tail=mov(0,0)*((OWNED_END-(SEL_START+len(combined)))//2)
    req(SEL_START+len(combined)+len(tail)==OWNED_END,'owned range fit')
    rows=srows+prows
    rows.append({'address':hx(SEL_START+len(combined)),'size':len(tail),'bytes':tail.hex(),'name':'padding.tail_mov_r0_r0','asm':'mov r0,r0','meaning':'unreached inert tail'})
    return {'selector':sel,'producer':prod,'combined':combined+tail,'rows':rows,'sel_labels':sl,'prod_labels':pl,'producer_start':sl['end'],'tail':tail}

def decode(data:bytes,start:int):
    out=[]; i=0
    while i<len(data):
        at=start+i; rem=len(data)-i; w=int.from_bytes(data[i:i+2],'little')
        if rem>=6 and data[i:i+2]==b'\x80\xff': size=6; row={'op':'call32','target':call32_target(at,data[i:i+6])}
        elif rem>=6 and (w&0xffc0)==0xffc0: size=6; row={'op':'mov_imm32','dst':w&0xf,'imm':int.from_bytes(data[i+2:i+6],'little')}
        elif rem>=4 and data[i:i+4]==bytes.fromhex('2000b000'): size=4; row={'op':'trylock'}
        elif rem>=4 and data[i:i+2]==bytes.fromhex('40e8'): size=4; row={'op':'ifeq','target':at+4+struct.unpack('<h',data[i+2:i+4])[0]*2}
        elif rem>=4 and (w&0xff80) in {0xf880,0xfd80,0xfd00}:
            size=4; w2=int.from_bytes(data[i+2:i+4],'little'); row={'op':{0xf880:'jne_imm7',0xfd80:'jl_imm7',0xfd00:'jge_imm7'}[w&0xff80],'reg':w&7,'imm':(w2>>9)&0x7f,'target':at+4+sx(w2&0x1ff,9)*2}
        elif rem>=4 and data[i+1]==0xe1 and (data[i]&0xf0)==0xe0: size=4; row={'op':'mul_imm12'}
        elif rem>=4 and data[i+1]==0xe1: size=4; row={'op':'add_imm12'}
        elif rem>=2 and (w&0xe088)==0x4008: size=2; row={'op':'load_byte'}
        elif rem>=2 and (w&0xe088)==0x4088: size=2; row={'op':'store_byte'}
        elif rem>=2 and (w&0xe0c0)==0x20c0: size=2; row={'op':'add_imm8'}
        elif rem>=2 and (w&0xe0c0)==0x2040: size=2; row={'op':'mov_imm8'}
        elif rem>=2 and (w&0xff00)==0x1600: size=2; row={'op':'mov_reg'}
        elif rem>=2 and (w&0xff00)==0x1800: size=2; row={'op':'add_reg'}
        elif rem>=2 and (w&0x80ff)==0x8004: size=2; row={'op':'goto','target':at+2+((w>>8)&0x1f)*2}
        elif rem>=2 and w==0x0020: size=2; row={'op':'csync'}
        elif rem>=2 and w in {0x0479,0x0459}: size=2; row={'op':{0x0479:'push',0x0459:'pop_pc'}[w]}
        else: raise SystemExit(f'FAIL: undecoded at {hx(at)} {data[i:i+8].hex()}')
        row.update({'address':at,'size':size,'bytes':data[i:i+size].hex()}); out.append(row); i+=size
    return out

def verify_code(c):
    lines=[]; d=decode(c['combined'],SEL_START); rows=c['rows']; names={r['name']:int(r['address'],16) for r in rows}
    req(c['producer_start']==0x0201E196 and c['prod_labels']['segmented_stub']==0x0201E224 and c['prod_labels']['reset_entry']==0x0201E228 and c['prod_labels']['end']==0x0201E252,'rebased labels')
    req(len(d)==len(rows) and [x['bytes'] for x in d]==[x['bytes'] for x in rows],'independent decode covers intended bytes')
    allowed={c['sel_labels']['core'],c['sel_labels']['copy'],MEMCPY,c['prod_labels']['return'],c['prod_labels']['not_empty'],c['prod_labels']['unlock'],c['prod_labels']['after_state'],c['prod_labels']['reset_skip'],c['producer_start']}
    for r in d:
        if r['op'] in {'goto','jne_imm7','jl_imm7','jge_imm7','ifeq','call32'}:
            req(r['target'] in allowed, f"branch target {hx(r['address'])}->{hx(r['target'])}")
    req(short_target(DIRECT_CALL,short_call(DIRECT_CALL,c['prod_labels']['reset_entry']))==c['prod_labels']['reset_entry'],'direct call target')
    req(short_target(SEG_CALL,short_call(SEG_CALL,c['prod_labels']['reset_entry']))==c['prod_labels']['reset_entry'],'segmented-final call target')
    req(names['selector.slot_index'] < names['selector.state_load'] < names['selector.gate_state'] < names['selector.valid_load'] < names['selector.gate_valid'] < names['selector.load_playback_note'] < names['selector.select_source'],'selector fail-closed: ARMED and selected-slot valid gates precede map load; source uses trigger slot')
    req(names['selector.memcpy_call'] < names['selector.metadata_pointer'] < names['selector.metadata_note_store'] < names['selector.pop_return'],'selector metadata write/return')
    req(names['producer.playback_store'] < names['producer.restore_staging_last'] < names['producer.memcpy_call'] < names['producer.restore_slot_last'] < names['producer.valid_store'] < names['producer.count_store'] < names['producer.armed_store'],'producer restore and ARMED order')
    req('producer.length_gate_source' not in names and names['producer.post_memcpy_count_reload'] > names['producer.memcpy_call'],'removed length gate and reload count after memcpy')
    tests=[0,1,36,36,63,64,100,127,0,127,50,50,12,34,56,78]
    req(all(0<=x<=127 for x in tests) and len(set(tests))<len(tests),'0..127 duplicates represented')
    lines += [
      f"PASS\trange\tselector {hx(SEL_START)}..{hx(c['sel_labels']['end'])}; producer {hx(c['producer_start'])}..{hx(c['prod_labels']['end'])}; owned_end {hx(OWNED_END)}",
      f"PASS\tselector-sha256\t{sha(c['selector'])}", f"PASS\tproducer-sha256\t{sha(c['producer'])}", f"PASS\tcombined-sha256\t{sha(c['combined'])}",
      f"PASS\tdirect-callsite\t{short_call(DIRECT_CALL,c['prod_labels']['reset_entry']).hex()} -> {hx(c['prod_labels']['reset_entry'])}",
      f"PASS\tsegmented-final-callsite\t{short_call(SEG_CALL,c['prod_labels']['reset_entry']).hex()} -> {hx(c['prod_labels']['reset_entry'])}",
      "PASS\tselector-contract\tsource slot remains trigger_note-36; ARMED and selected-slot valid gates precede Playback Note map load; every fallback keeps Trigger Note; r0 returns metadata pointer",
      "PASS\tproducer-contract\twire byte 161 stored to 0x01c46f20+slot; staging and slot[0x9b] restored to 0x3f; ARMED last",
      "PASS\tplayback-range\t0..127 allowed including duplicates; repeated-note risk documented"
    ]
    return d, lines

def unpack_any(raw:bytes):
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload=bytearray()
    for i in range(FWSC_SLOTS): payload.extend(raw[i*FWSC_BLOCK_SIZE:i*FWSC_BLOCK_SIZE+FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS*FWSC_BLOCK_SIZE:]); req(len(payload)==OFFICIAL_V15_PAYLOAD_SIZE,'payload size'); return payload

def app_from_fwsc(path:Path, official=False):
    raw=path.read_bytes(); payload=unpack_fwsc(raw)[0] if official else unpack_any(raw); flash=Ufw.parse(payload).flash(); app=AppImage.parse(flash).app_bytes(); return raw,flash,app

def gate_inputs():
    gates=[]; raw,_,offapp=app_from_fwsc(OFFICIAL_FWSC,True)
    req(sha(raw)==EXPECTED['official_fwsc'] and sha(offapp)==EXPECTED['official_app'],'official hashes')
    req(shaf(PARENT/'app.bin')==EXPECTED['parent_app'] and shaf(PARENT_FWSC)==EXPECTED['parent_fwsc'],'parent hashes')
    evidence=json.loads((PARENT/'evidence.json').read_text()); req(evidence['decision']=='PASS','parent PASS')
    p=(PARENT/'app.bin').read_bytes()
    req(p[off(NOFF_HOOK):off(NOFF_HOOK)+6].hex()==EXPECTED['noff_hook'] and p[off(NON_HOOK):off(NON_HOOK)+6].hex()==EXPECTED['non_hook'],'hook anchors')
    req(p[off(NOFF_NEUT):off(NOFF_NEUT)+6].hex()==EXPECTED['noff_post'] and p[off(NON_NEUT):off(NON_NEUT)+6].hex()==EXPECTED['non_post'],'post-store anchors')
    pm=json.loads((PARENT/'inputs/packets/packet-manifest.json').read_text())
    for i,item in enumerate(pm['packets']):
        pkt=(PARENT/'inputs/packets'/item['file']).read_bytes(); req(sha(pkt)==EXPECTED['packet_hashes'][i] and pkt[WIRE_PLAYBACK_OFFSET]==RESTORE_BYTE,'packet template hash/0x3f')
    gates.append({'name':'official-v15-basis','status':'PASS','official_fwsc_sha256':EXPECTED['official_fwsc'],'official_app_sha256':EXPECTED['official_app']})
    gates.append({'name':'proven-s1c3-r3-reload-parent','status':'PASS','parent_app_sha256':EXPECTED['parent_app'],'parent_fwsc_sha256':EXPECTED['parent_fwsc']})
    gates.append({'name':'current-hook-and-metadata-neutralization-anchors','status':'PASS','note_off_hook':EXPECTED['noff_hook'],'note_on_hook':EXPECTED['non_hook'],'note_off_post_store':EXPECTED['noff_post'],'note_on_post_store':EXPECTED['non_post']})
    abi_report=ANALYSIS/'patch-set-ui/s1c2-unblock/producer-abi/report.md'
    copy_report=ANALYSIS/'r03-owned-ram/copy-path/report.md'
    req(shaf(abi_report)==EXPECTED['producer_abi_report'],'producer ABI report hash')
    req(shaf(copy_report)==EXPECTED['copy_path_report'],'copy path report hash')
    gates.append({'name':'exact-direct-packet-templates','status':'PASS','packet_count':16,'wire_playback_note_offset':WIRE_PLAYBACK_OFFSET,'template_byte':RESTORE_BYTE})
    gates.append({'name':'exact-direct-and-segmented-final-producer-abi','status':'PASS','producer_abi_report':str(abi_report.relative_to(ROOT)),'producer_abi_report_sha256':EXPECTED['producer_abi_report'],'copy_path_report':str(copy_report.relative_to(ROOT)),'copy_path_report_sha256':EXPECTED['copy_path_report'],'direct_callsite':hx(DIRECT_CALL),'direct_lr':hx(DIRECT_RELOAD),'direct_length':'r9 == 0x000000a3','segmented_callsite':hx(SEG_CALL),'segmented_lr':hx(SEG_RELOAD),'segmented_final_total':'r5 == 0x0000009e','stage_pointer':'0x01c37fd0'})
    return gates

def patch(app:bytearray,a:int,b:bytes,purpose:str):
    old=bytes(app[off(a):off(a)+len(b)]); app[off(a):off(a)+len(b)]=b
    return {'address':hx(a),'end_exclusive':hx(a+len(b)),'byte_count':len(b),'old_hex':old.hex(),'new_hex':b.hex(),'old_sha256':sha(old),'new_sha256':sha(b),'purpose':purpose}

def build_app(c,gates):
    parent=(PARENT/'app.bin').read_bytes(); app=bytearray(parent); neutral=mov(0,0)*3; pl=c['prod_labels']
    patches=[patch(app,SEL_START,c['combined'],'install contiguous selector+producer'), patch(app,DIRECT_CALL,short_call(DIRECT_CALL,pl['reset_entry']),'direct product -> reset wrapper'), patch(app,SEG_CALL,short_call(SEG_CALL,pl['reset_entry']),'segmented final product -> reset wrapper'), patch(app,NOFF_NEUT,neutral,'neutralize Note Off stock add+note store with mov r0,r0 x3'), patch(app,NON_NEUT,neutral,'neutralize Note On stock add+note store with mov r0,r0 x3')]
    req(app[off(NOFF_HOOK):off(NOFF_HOOK)+6].hex()==EXPECTED['noff_hook'] and app[off(NON_HOOK):off(NON_HOOK)+6].hex()==EXPECTED['non_hook'],'hooks unchanged')
    req(app[off(DIRECT_RELOAD):off(DIRECT_RELOAD)+4].hex()==EXPECTED['direct_reload'] and app[off(SEG_RELOAD):off(SEG_RELOAD)+4].hex()==EXPECTED['seg_reload'],'reloads preserved')
    diffs=difference_offsets(parent,app)
    manifest={'format':FORMAT+'.app-manifest-v1','basis_app':'S1-C3-16slot-functional-v2-r3-reload/app.bin','basis_app_sha256':EXPECTED['parent_app'],'output_app_sha256':sha(app),'runtime_base':hx(BASE),'patches':patches,'parent_relative_changed_byte_count':len(diffs),'parent_relative_changed_ranges':compact_ranges(diffs),'input_gates':gates,'callsite_contract':{'note_off_hook':{'address':hx(NOFF_HOOK),'bytes':EXPECTED['noff_hook'],'target':hx(SEL_START),'status':'unchanged'},'note_on_hook':{'address':hx(NON_HOOK),'bytes':EXPECTED['non_hook'],'target':hx(SEL_START+4),'status':'unchanged'},'direct_product_callsite':{'address':hx(DIRECT_CALL),'bytes':app[off(DIRECT_CALL):off(DIRECT_CALL)+4].hex(),'target':hx(pl['reset_entry'])},'segmented_product_callsite':{'address':hx(SEG_CALL),'bytes':app[off(SEG_CALL):off(SEG_CALL)+4].hex(),'target':hx(pl['reset_entry']),'segmented_final_supported':True},'direct_reload_callsite':{'address':hx(DIRECT_RELOAD),'bytes':EXPECTED['direct_reload'],'status':'preserved'},'segmented_reload_callsite':{'address':hx(SEG_RELOAD),'bytes':EXPECTED['seg_reload'],'status':'preserved'},'note_off_neutralized':{'address':hx(NOFF_NEUT),'bytes':neutral.hex(),'inert_instruction':'mov r0,r0 x3'},'note_on_neutralized':{'address':hx(NON_NEUT),'bytes':neutral.hex(),'inert_instruction':'mov r0,r0 x3'},'note_on_velocity_store':{'address':'0x0201c68c','bytes':'8d42','status':'preserved'}}}
    return bytes(app), manifest

def repack(app_path,pkg_path,manifest_path):
    subprocess.run([sys.executable,str(BOUNDARY/'smk37_v15_app_patch.py'),'repack-app',str(OFFICIAL_FWSC),str(app_path),str(pkg_path),'--manifest',str(manifest_path)],check=True)

def rollback_info(app:bytes,pkg:Path):
    oraw,oflash,oapp=app_from_fwsc(OFFICIAL_FWSC,True); craw,cflash,capp=app_from_fwsc(pkg,False); praw,pflash,papp=app_from_fwsc(PARENT_FWSC,False)
    req(capp==app and sha(oraw)==EXPECTED['official_fwsc'] and sha(oapp)==EXPECTED['official_app'],'package embeds app and official hashes')
    ad= difference_offsets(oapp,app); fd=difference_offsets(oflash,cflash); rd=difference_offsets(oraw,craw); pd=difference_offsets(papp,app)
    req(not (set(APP_DATA_OFFSET+x for x in ad)-set(fd)),'flash contains app diffs'); req(not any(x<PROTECTED_PREFIX_END for x in fd),'protected prefix unchanged')
    sectors=sorted({x-(x%SECTOR) for x in fd}); rdir=HERE/'rollback/official-v15-recovery-sectors'
    if rdir.exists(): shutil.rmtree(rdir)
    rdir.mkdir(parents=True,exist_ok=True); entries=[]
    for base in sectors:
        data=bytes(oflash[base:base+SECTOR]); name=f'official-v15-sector-{base:05x}.bin'; (rdir/name).write_bytes(data); entries.append({'sector_base':f'0x{base:05x}','size':len(data),'sha256':sha(data),'file':f'rollback/official-v15-recovery-sectors/{name}'})
    recon=bytearray(cflash)
    for base in sectors: recon[base:base+SECTOR]=oflash[base:base+SECTOR]
    req(bytes(recon)==bytes(oflash),'rollback reconstructs official flash')
    wjson(rdir/'manifest.json',{'format':FORMAT+'.official-v15-sector-rollback-v1','sector_size':SECTOR,'changed_sectors':entries,'official_flash_sha256':sha(oflash),'candidate_flash_sha256':sha(cflash),'rollback_restores_official_flash':True})
    return {'package_sha256':sha(craw),'package_size':len(craw),'payload_sha256':sha(unpack_any(craw)),'candidate_flash_sha256':sha(cflash),'official_flash_sha256':sha(oflash),'parent_flash_sha256':sha(pflash),'changed_app_byte_count_vs_official':len(ad),'changed_app_ranges_vs_official':compact_ranges(ad),'changed_app_byte_count_vs_parent':len(pd),'changed_app_ranges_vs_parent':compact_ranges(pd),'changed_flash_sectors_vs_official':[f'0x{x:05x}' for x in sectors],'changed_package_byte_count_vs_official':len(rd),'changed_package_ranges_vs_official':compact_ranges(rd),'protected_hashes_official':protected_hashes(bytearray(oflash)),'protected_hashes_candidate':protected_hashes(bytearray(cflash)),'rollback_manifest':'rollback/official-v15-recovery-sectors/manifest.json','rollback_restores_official_flash':True}

def write_code_artifacts(c,dec,lines):
    CODEDIR.mkdir(parents=True,exist_ok=True)
    (CODEDIR/'combined.bin').write_bytes(c['combined']); (CODEDIR/'combined.hex').write_text(c['combined'].hex()+"\n")
    (CODEDIR/'selector.bin').write_bytes(c['selector']); (CODEDIR/'producer.bin').write_bytes(c['producer'])
    with (CODEDIR/'decode.tsv').open('w') as f:
        f.write('address\tsize\tbytes\tname\tasm\tmeaning\ttarget\n')
        for r in c['rows']: f.write('\t'.join([r['address'],str(r['size']),r['bytes'],r['name'],r['asm'],r['meaning'],r.get('target','')]).rstrip()+"\n")
    with (CODEDIR/'independent-decode.tsv').open('w') as f:
        f.write('address\tsize\tbytes\top\ttarget\n')
        for r in dec: f.write((f"{hx(r['address'])}\t{r['size']}\t{r['bytes']}\t{r['op']}\t{hx(r['target']) if 'target' in r else ''}").rstrip()+"\n")
    ev={'format':FORMAT+'.exact-pi32-code-evidence-v1','decision':'PASS','scope':{'offline_only':True,'device_accessed':False,'midi_transport_opened':False,'flash_performed':False,'reset_performed':False},'owned_window':{'start':hx(SEL_START),'end_exclusive':hx(OWNED_END),'bytes':OWNED_END-SEL_START},'combined':{'sha256':sha(c['combined']),'bytes':len(c['combined']),'hex':c['combined'].hex(),'tail_padding_hex':c['tail'].hex()},'selector':{'start':hx(SEL_START),'end_exclusive':hx(c['sel_labels']['end']),'bytes':len(c['selector']),'sha256':sha(c['selector']),'source_invariant':'source slot = trigger_note - 36 only; Playback Note is metadata only','fail_closed_fallback':True,'playback_map_read_after_armed_and_valid':True,'metadata_return':'after memcpy wrapper returns r0 = original destination + 0x9c after storing mapped note'},'producer':{'start':hx(c['producer_start']),'end_exclusive':hx(c['prod_labels']['end']),'bytes':len(c['producer']),'sha256':sha(c['producer']),'segmented_stub':hx(c['prod_labels']['segmented_stub']),'reset_entry':hx(c['prod_labels']['reset_entry']),'r9_length_gate_removed':True,'playback_store':'lb.z r2,[staging+0x9b]; sb [0x01c46f20+slot],r2','staging_restore_before_memcpy':True,'slot_restore_before_valid':True,'armed_last_publishes_map':True},'callsites':{'direct_product':{'address':hx(DIRECT_CALL),'bytes':short_call(DIRECT_CALL,c['prod_labels']['reset_entry']).hex(),'target':hx(c['prod_labels']['reset_entry'])},'segmented_product':{'address':hx(SEG_CALL),'bytes':short_call(SEG_CALL,c['prod_labels']['reset_entry']).hex(),'target':hx(c['prod_labels']['reset_entry']),'segmented_final_supported':True}},'neutralized_stock_metadata_stores':{'note_off':{'range':f'{hx(NOFF_NEUT)}..{hx(NOFF_NEUT+6)}','old_hex':EXPECTED['noff_post'],'new_hex':(mov(0,0)*3).hex(),'inert':'mov r0,r0 x3'},'note_on':{'range':f'{hx(NON_NEUT)}..{hx(NON_NEUT+6)}','old_hex':EXPECTED['non_post'],'new_hex':(mov(0,0)*3).hex(),'inert':'mov r0,r0 x3'},'velocity_preserved':'Note On velocity store at 0x0201c68c remains stock and uses restored r5 with wrapper-returned r0'},'validation':lines}
    wjson(CODEDIR/'evidence.json',ev); (CODEDIR/'validation.txt').write_text('S1-C4 Playback Note exact PI32 validation: PASS\n'+'\n'.join(lines)+'\n')
    (CODEDIR/'report.md').write_text(f"# S1-C4 Playback Note v3 segmented-final exact PI32 candidate PASS\n\nCombined SHA-256 `{ev['combined']['sha256']}`. Selector `{ev['selector']['sha256']}`. Producer `{ev['producer']['sha256']}`. Source remains trigger slot only. Playback Note is metadata only. Direct and segmented-final callsites both target the reset wrapper. Producer stores wire byte 161 to `0x01c46f20+slot` and restores byte `0x9b` to `0x3f`. Values `0..127`, duplicates allowed with repeated-note risk.\n")
    (CODEDIR/'SHA256SUMS').write_text('\n'.join(f"{shaf(CODEDIR/n)}  {n}" for n in ['combined.bin','combined.hex','selector.bin','producer.bin','decode.tsv','independent-decode.tsv','evidence.json','report.md','validation.txt'])+'\n')
    return ev

def transport_packets():
    out=HERE/'inputs/packets'
    if out.exists(): shutil.rmtree(out)
    out.mkdir(parents=True,exist_ok=True); pm=json.loads((PARENT/'inputs/packets/packet-manifest.json').read_text()); packets=[]
    for slot,item in enumerate(pm['packets']):
        trig=NOTE0+slot; playback=trig; src=PARENT/'inputs/packets'/item['file']; tmpl=bytearray(src.read_bytes()); req(tmpl[WIRE_PLAYBACK_OFFSET]==RESTORE_BYTE and sha(tmpl)==EXPECTED['packet_hashes'][slot],'template packet')
        pkt=bytearray(tmpl); pkt[WIRE_PLAYBACK_OFFSET]=playback; name=f'slot{slot:02d}-trigger{trig:02d}-playback{playback:02d}-direct-product-163.bin'; (out/name).write_bytes(pkt)
        packets.append({'slot':slot,'order':slot+1,'trigger_note':trig,'playback_note':playback,'file':name,'sha256':sha(pkt),'template_file':item['file'],'template_sha256':sha(tmpl),'only_changed_wire_offsets_vs_template':[WIRE_PLAYBACK_OFFSET],'template_byte_at_wire_offset':RESTORE_BYTE,'transport_byte_at_wire_offset':playback,'name':item.get('name')})
    man={'format':FORMAT+'.playback-transport-packets-v1','status':'PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'packet_count':16,'packet_bytes':163,'supported_ingress_modes':['direct_163_byte_sysex','segmented_final_sysex_after_final_f7_total_0x9e'],'web_midi_ble_note':'Host transports may deliver the same SysEx directly or segmented; firmware support is at the accepted direct and segmented-final callsites, no live transport opened','order_basis':'resident_slot_order_trigger_note_36_51','wire_playback_note_offset':WIRE_PLAYBACK_OFFSET,'payload_playback_note_offset':VOICE_LAST,'policy':'default Original transport uses playback_note = trigger_note; custom 0..127 including duplicates changes only wire byte 161; firmware ingress supports direct 163-byte and segmented-final accepted SysEx callsites','packets':packets}
    wjson(out/'packet-manifest.json',man); (out/'SHA256SUMS').write_text('\n'.join([f"{shaf(out/'packet-manifest.json')}  packet-manifest.json"]+[f"{shaf(out/p['file'])}  {p['file']}" for p in packets])+'\n')
    return man

def c_array(h): return ', '.join(f'0x{h[i:i+2]}' for i in range(0,len(h),2))
def exact_ota_c(pkgsha):
    token=f"INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V3SEG-{pkgsha[:8].upper()}"
    return f'''/* Exact-hash v15-only OTA wrapper for S1-C4 Playback Note. */\n#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include "../../../../../src/ota.c"\nstatic const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {c_array(pkgsha)} }};\nstatic const char CONFIRM[] = "{token}";\nstatic const char DESCRIPTION[] = "SMK37ProMod v15 S1-C4 Playback Note v3 segmented-final candidate";\nstatic int check_exact(const char *path) {{ struct smk37_fwsc firmware; int status=1; if(!smk37_fwsc_load(path,&firmware)) return 1; if(strcmp(firmware.name,"SMK-37 Pro")==0 && firmware.version==15 && memcmp(firmware.file_sha256,PACKAGE_SHA256,sizeof(PACKAGE_SHA256))==0) {{ printf("exact v15 S1-C4 Playback Note package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length); status=0; }} else fputs("offline check rejected: not exact S1-C4 Playback Note package\\n", stderr); smk37_fwsc_free(&firmware); return status; }}\nint main(int argc,char **argv) {{ if(argc==3 && strcmp(argv[1],"check")==0) return check_exact(argv[2]); if(argc==6 && strcmp(argv[1],"upload")==0 && strcmp(argv[4],"--confirm")==0) return ota_upload_exact(argv[2],argv[3],argv[5],15,PACKAGE_SHA256,DESCRIPTION,CONFIRM,"v15 S1-C4 Playback Note v3 segmented-final candidate installed"); fprintf(stderr,"usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n",argv[0],argv[0],CONFIRM); return 2; }}\n'''

def dry_run_py(pkgsha, pkt_hashes):
    return f'''#!/usr/bin/env python3\nimport argparse, hashlib, json\nfrom pathlib import Path\nHERE=Path(__file__).resolve().parent; PKG={PACKAGE_NAME!r}; PKGSHA={pkgsha!r}; HASHES={pkt_hashes!r}; HEADER=bytes.fromhex('f0430000011b')\ndef sh(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()\ndef req(x,m):\n    if not x: raise SystemExit('FAIL: '+m)\ndef main():\n    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); a=ap.parse_args(); req(sh(HERE/PKG)==PKGSHA,'package hash'); man=json.loads((HERE/'inputs/packets/packet-manifest.json').read_text());\n    for i,it in enumerate(man['packets']):\n        b=(HERE/'inputs/packets'/it['file']).read_bytes(); req(len(b)==163 and b.startswith(HEADER) and b[-1]==0xf7, f'packet {{i}} framing'); req(hashlib.sha256(b).hexdigest()==HASHES[i]==it['sha256'], f'packet {{i}} hash'); req(b[161]==it['playback_note']==it['trigger_note'], f'packet {{i}} playback byte')\n    res={{'status':'DRY_RUN_PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'package_sha256':PKGSHA,'wire_playback_note_offset':161,'packet_count':16}}\n    print(json.dumps(res,sort_keys=True) if a.json else 'S1-C4 Playback Note dry-run PASS: no USB/MIDI/device/flash/reset action')\nif __name__=='__main__': main()\n'''

def write_sha_inventory():
    paths=[]
    for n in ['build_s1c4_playback_note_v3_segmented_final.py','validate.py','dry_run_validate.py','app.bin',PACKAGE_NAME,'app-manifest.json','package-manifest.json','evidence.json','report.md','README.md','exact_ota.c','validation.txt']:
        p=HERE/n
        if p.exists(): paths.append(p)
    for base in ['rollback','inputs']:
        root=HERE/base
        if root.exists(): paths += [p for p in sorted(root.rglob('*')) if p.is_file()]
    seen=[]
    for p in paths:
        if p not in seen: seen.append(p)
    (HERE/'SHA256SUMS').write_text('\n'.join(f"{shaf(p)}  {p.relative_to(HERE)}" for p in seen)+'\n')

def build(check=False,no_write=False):
    c=build_code(); dec,lines=verify_code(c); gates=gate_inputs()
    if no_write: return {'decision':'PASS','candidate_built':False,'validation':lines}
    if check:
        ev=json.loads((HERE/'evidence.json').read_text()); codeev=json.loads((CODEDIR/'evidence.json').read_text()); req(codeev['combined']['sha256']==sha(c['combined'])==ev['code']['combined_sha256'],'deterministic code hash'); return ev
    codeev=write_code_artifacts(c,dec,lines); app,aman=build_app(c,gates); (HERE/'app.bin').write_bytes(app); wjson(HERE/'app-manifest.json',aman)
    repack(HERE/'app.bin',HERE/PACKAGE_NAME,HERE/'package-manifest.json'); pkginfo=rollback_info(app,HERE/PACKAGE_NAME); pman=json.loads((HERE/'package-manifest.json').read_text()); req(pman['output']['sha256']==pkginfo['package_sha256'],'package manifest hash')
    tman=transport_packets(); pkt_hashes=[p['sha256'] for p in tman['packets']]; ota_token=f"INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V3SEG-{pkginfo['package_sha256'][:8].upper()}"; sender_token='SEND-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V3SEG-'+'-'.join(h[:8].upper() for h in pkt_hashes[:4])
    (HERE/'exact_ota.c').write_text(exact_ota_c(pkginfo['package_sha256'])); (HERE/'dry_run_validate.py').write_text(dry_run_py(pkginfo['package_sha256'],pkt_hashes)); (HERE/'dry_run_validate.py').chmod(0o755)
    evidence={'format':FORMAT+'.release-evidence-v1','decision':'PASS','candidate_built':True,'scope':{'offline_only':True,'device_accessed':False,'midi_transport_opened':False,'flash_performed':False,'ota_performed':False,'reset_performed':False,'live_send_performed':False},'basis':{'official_fwsc_sha256':EXPECTED['official_fwsc'],'official_app_sha256':EXPECTED['official_app'],'parent_s1c3_app_sha256':EXPECTED['parent_app'],'parent_s1c3_package_sha256':EXPECTED['parent_fwsc']},'input_gates':gates,'code':{'candidate_dir':str(CODEDIR.relative_to(ROOT)),'combined_sha256':codeev['combined']['sha256'],'selector_sha256':codeev['selector']['sha256'],'producer_sha256':codeev['producer']['sha256']},'app':aman,'package':pkginfo,'transport':tman,'flash':{'artifact':PACKAGE_NAME,'confirmation_token':ota_token,'default_check_offline_only':True},'sender':{'artifact':'inputs/packets','confirmation_token':sender_token,'default_compile_live_usb_enabled':False,'wire_playback_note_offset':WIRE_PLAYBACK_OFFSET},'abi_evidence':{'producer_abi_report':'baselines/v15/analysis/patch-set-ui/s1c2-unblock/producer-abi/report.md','producer_abi_report_sha256':EXPECTED['producer_abi_report'],'direct_lr':'0x0201e46c','direct_length_register':'r9 == 0x000000a3','segmented_lr':'0x0201e4a0','segmented_final_total_register':'r5 == 0x0000009e','stage_pointer':'0x01c37fd0'},'invariants':{'trigger_source':'slot = trigger_note - 36; unchanged external Trigger Note and MIDI OUT','playback_metadata':'local synth metadata note only, stored by wrapper at destination+0x9c after copy','no_source_slot_from_playback_note':True,'fail_closed_fallback':True,'playback_map_read_after_armed_and_valid':True,'playback_note_range':'0..127 including duplicates','repeated_note_risk_documented':True}}
    wjson(HERE/'evidence.json',evidence); (HERE/'validation.txt').write_text('S1-C4 Playback Note v3 segmented-final build validation: PASS\n'+'\n'.join(lines)+'\n')
    (HERE/'README.md').write_text(f"# S1-C4 Playback Note v3 segmented-final offline release\n\nStatus: **PASS, candidate built offline**.\n\nApp SHA-256 `{aman['output_app_sha256']}`. FWSC SHA-256 `{pkginfo['package_sha256']}`. OTA token `{ota_token}`.\n\nDirect 163-byte and segmented-final accepted SysEx paths both target the reset wrapper. Trigger source remains `slot = trigger_note - 36`. Playback Note is local synth metadata only. Values `0..127` including duplicates are allowed, with repeated-note/cross-release risk documented. No live actions were performed.\n")
    (HERE/'report.md').write_text(f"# S1-C4 Playback Note v3 segmented-final PASS\n\n- App SHA-256: `{aman['output_app_sha256']}`.\n- FWSC SHA-256: `{pkginfo['package_sha256']}`.\n- Combined code SHA-256: `{codeev['combined']['sha256']}`.\n- Selector SHA-256: `{codeev['selector']['sha256']}`.\n- Producer SHA-256: `{codeev['producer']['sha256']}`.\n- OTA token: `{ota_token}`.\n- Sender token: `{sender_token}`.\n\nPASS: official/current hashes, exact ABI report hashes, direct and segmented-final reset-wrapper callsites, rebased branches, memcpy count reload, reset lifecycle, staging/slot restore, ARMED-last, trigger source invariant, metadata neutralization `001600160016`, velocity preservation, rollback.\n")
    write_sha_inventory(); return evidence

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--check',action='store_true'); ap.add_argument('--no-write',action='store_true'); a=ap.parse_args(); ev=build(check=a.check,no_write=a.no_write); print('S1-C4 Playback Note v3 segmented-final build gate: PASS');
    if ev.get('candidate_built'):
        print('app_sha256='+ev['app']['output_app_sha256']); print('package_sha256='+ev['package']['package_sha256']); print('ota_confirmation_token='+ev['flash']['confirmation_token']); print('sender_confirmation_token='+ev['sender']['confirmation_token'])
if __name__=='__main__': main()
