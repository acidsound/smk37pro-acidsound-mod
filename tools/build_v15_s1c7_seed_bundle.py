#!/usr/bin/env python3
"""Build the target-specific guarded WL82 S1C7 forced-recovery seed bundle.

Offline only. It packages the existing audited S1C7 seed sectors behind exact
prehash, dual-dump, write/readback, and rollback gates. The generated real-write
path is Windows-only because the audited mutable transport is the reviewed
SCSI_PASS_THROUGH_DIRECT transport. macOS receives deterministic dry validators
and an explicit unsupported blocker for live writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

LIVE_DUAL_DUMP_SHA256 = "078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946"
SOURCE_NAME = "s1c7-current-set-prefix-seed-20260804"
BUNDLE_NAME = "SMK37Pro-WL82-v15-S1C7-seed-20260804-v1"
SECTORS = (0x0FB000, 0x0FC000)
SECTOR_SIZE = 0x1000
ZIP_TIME = (2026, 8, 4, 0, 0, 0)
TEMPLATE = Path("build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit(msg)


def write_hashes(root: Path) -> None:
    entries = []
    for p in sorted(x for x in root.rglob("*") if x.is_file() and x.name != "SHA256SUMS.txt"):
        entries.append(f"{sha(p.read_bytes())}  {p.relative_to(root).as_posix()}")
    (root / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")


def write_zip(root: Path, output: Path) -> None:
    top = root.name
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for d in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: p.as_posix()):
            info = zipfile.ZipInfo(f"{top}/{d.relative_to(root).as_posix()}/", ZIP_TIME)
            info.external_attr = (0o755 << 16) | 0x10
            z.writestr(info, b"")
        for p in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
            info = zipfile.ZipInfo(f"{top}/{p.relative_to(root).as_posix()}", ZIP_TIME)
            info.external_attr = ((0o755 if os.access(p, os.X_OK) else 0o644) << 16)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


GUARD = r'''#!/usr/bin/env python3
"""Guarded SMK-37 Pro WL82 S1C7 seed writer.

Only LoaderV2 Flash mutations implemented: erase sector 0xFB01 and write Flash
0xFB04. Both are contract-checked to exactly sectors {0x0FB000,0x0FC000}; writes
are max 256 bytes and carry CRC16-XMODEM little-endian. The tool requires two
identical fresh 1 MiB dumps with SHA-256
078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946 before seed
writes. Rollback writes only the original bytes for the same two sectors.
"""
from __future__ import annotations
import argparse, hashlib, importlib.util, json, sys, tempfile, time
from pathlib import Path

FLASH_SIZE=0x100000; SECTOR_SIZE=0x1000; IO_CHUNK_SIZE=256
SECTORS={0x0FB000,0x0FC000}; LIVE_DUAL_DUMP_SHA256="078c13d698ad08a4cfac7723e87014000e5557e655bd1f21d75493dc8f652946"
EXPECTED_VENDOR="WL82"; EXPECTED_PRODUCT="UBOOT1.00"; LOADER_ADDRESS=0x1C02000; LOADER_ARGUMENT_SPI_NOR=1; LOADER_BLOCK_SIZE=512
OFFICIAL_LOADER_SIZE=31232; OFFICIAL_LOADER_SHA256="9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27"
EXPECTED_DEVICE_TYPE=0x03; EXPECTED_DEVICE_ID=15425556; EXPECTED_FLASH_ID=60256
STANDARD_INQUIRY_CDB=bytes([0x12,0,0,0,36,0]); CMD_UBOOT_WRITE_MEMORY=0xFB06; CMD_UBOOT_JUMP_MEMORY=0xFB08; CMD_ERASE_SECTOR=0xFB01; CMD_WRITE_FLASH=0xFB04; CMD_READ_FLASH=0xFD05; CMD_GET_ONLINE_DEVICE=0xFC0A; CMD_READ_ID=0xFC0B; CMD_GET_USB_BUFFER_SIZE=0xFC14
ALLOWED={CMD_UBOOT_WRITE_MEMORY,CMD_UBOOT_JUMP_MEMORY,CMD_ERASE_SECTOR,CMD_WRITE_FLASH,CMD_READ_FLASH,CMD_GET_ONLINE_DEVICE,CMD_READ_ID,CMD_GET_USB_BUFFER_SIZE}
CONFIRM_SEED=["I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_S1C7_SEED_SECTORS","I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_SHA_078C13D698AD08A4CFAC7723E87014000E5557E655BD1F21D75493DC8F652946","WRITE_S1C7_SEED_SECTORS_NOW"]
CONFIRM_ROLLBACK=["I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_S1C7_SEED_SECTORS","I_HAVE_A_READBACK_OR_BACKUP_TO_ROLL_BACK_FROM","ROLL_BACK_S1C7_SEED_SECTORS_NOW"]
class SafetyError(RuntimeError): pass
def sha256_bytes(d:bytes)->str: return hashlib.sha256(d).hexdigest()
def sha256_file(p:Path)->str: return sha256_bytes(p.read_bytes())
def crc16_xmodem(data:bytes, initial:int=0)->int:
    crc=initial&0xffff
    for value in data:
        crc ^= value << 8
        for _ in range(8): crc = ((crc << 1) ^ 0x1021) & 0xffff if crc & 0x8000 else (crc << 1) & 0xffff
    return crc
def in_sector(a:int,n:int)->bool: return any(s <= a and a+n <= s+SECTOR_SIZE for s in SECTORS)
def build_vendor_cdb(cmd:int,args:bytes=b"")->bytes:
    if cmd not in ALLOWED: raise SafetyError(f"CDB 0x{cmd:04X} is not implemented")
    c=cmd.to_bytes(2,"big")+args
    if len(c)>16: raise SafetyError("CDB too long")
    return c+b"\xff"*(16-len(c))
def validate_transfer_contract(cdb:bytes,data_out:bytes|None=None,data_in_length:int=0)->int|None:
    if data_out is not None and data_in_length: raise SafetyError("simultaneous data-in/out prohibited")
    if cdb==STANDARD_INQUIRY_CDB:
        if data_out is not None or data_in_length!=36: raise SafetyError("bad INQUIRY")
        return None
    if len(cdb)!=16: raise SafetyError("only 16-byte vendor CDBs accepted")
    cmd=int.from_bytes(cdb[:2],"big")
    if cmd not in ALLOWED: raise SafetyError(f"non-implemented CDB 0x{cmd:04X}")
    if cmd==CMD_ERASE_SECTOR:
        a=int.from_bytes(cdb[2:6],"big")
        if data_out is not None or data_in_length!=16 or a not in SECTORS or cdb[6:]!=b"\xff"*10: raise SafetyError("erase contract mismatch")
    elif cmd==CMD_WRITE_FLASH:
        a=int.from_bytes(cdb[2:6],"big"); n=int.from_bytes(cdb[6:8],"big")
        if data_out is None or not 1<=len(data_out)<=IO_CHUNK_SIZE or n!=len(data_out) or cdb[8]!=0 or int.from_bytes(cdb[9:11],"little")!=crc16_xmodem(data_out) or not in_sector(a,n) or (a//IO_CHUNK_SIZE)!=((a+n-1)//IO_CHUNK_SIZE) or cdb[11:]!=b"\xff"*5: raise SafetyError("write contract mismatch")
    elif cmd==CMD_READ_FLASH:
        a=int.from_bytes(cdb[2:6],"big"); n=int.from_bytes(cdb[6:8],"big")
        if data_out is not None or n!=data_in_length or not 1<=n<=IO_CHUNK_SIZE or a+n>FLASH_SIZE or cdb[8:]!=b"\xff"*8: raise SafetyError("read contract mismatch")
    elif cmd==CMD_UBOOT_WRITE_MEMORY:
        a=int.from_bytes(cdb[2:6],"big"); n=int.from_bytes(cdb[6:8],"big")
        if data_out is None or not 1<=len(data_out)<=LOADER_BLOCK_SIZE or n!=len(data_out) or cdb[8]!=0 or int.from_bytes(cdb[9:11],"little")!=crc16_xmodem(data_out) or not LOADER_ADDRESS<=a or a+n>LOADER_ADDRESS+OFFICIAL_LOADER_SIZE or cdb[11:]!=b"\xff"*5: raise SafetyError("RAM loader write mismatch")
    elif cmd==CMD_UBOOT_JUMP_MEMORY:
        if data_out is not None or data_in_length!=16 or int.from_bytes(cdb[2:6],"big")!=LOADER_ADDRESS or int.from_bytes(cdb[6:8],"big")!=LOADER_ARGUMENT_SPI_NOR or cdb[8:]!=b"\xff"*8: raise SafetyError("RAM loader jump mismatch")
    elif cmd in {CMD_GET_ONLINE_DEVICE,CMD_READ_ID,CMD_GET_USB_BUFFER_SIZE}:
        if data_out is not None or data_in_length!=16 or cdb[2:]!=b"\xff"*14: raise SafetyError("loader info mismatch")
    return cmd
class Client:
    def __init__(self,t): self.t=t
    def inquiry(self):
        d=self.t.execute(STANDARD_INQUIRY_CDB,data_in_length=36); f=lambda s,n:d[s:s+n].decode('ascii','strict').strip(' \x00'); r={"vendor":f(8,8),"product":f(16,16),"revision":f(32,4)}
        if r["vendor"]!=EXPECTED_VENDOR or r["product"]!=EXPECTED_PRODUCT: raise SafetyError(f"unexpected identity {r}")
        return r
    def resp(self,cmd,args=b""):
        r=self.t.execute(build_vendor_cdb(cmd,args),data_in_length=16)
        if len(r)!=16 or int.from_bytes(r[:2],"big")!=cmd: raise SafetyError(f"bad response for 0x{cmd:04X}")
        return r[2:]
    def upload_official_loader(self,loader):
        if len(loader)!=OFFICIAL_LOADER_SIZE or sha256_bytes(loader)!=OFFICIAL_LOADER_SHA256: raise SafetyError("official loader bytes mismatch")
        for off in range(0,len(loader),LOADER_BLOCK_SIZE):
            b=loader[off:off+LOADER_BLOCK_SIZE]; self.t.execute(build_vendor_cdb(CMD_UBOOT_WRITE_MEMORY,(LOADER_ADDRESS+off).to_bytes(4,'big')+len(b).to_bytes(2,'big')+b'\0'+crc16_xmodem(b).to_bytes(2,'little')),data_out=b)
        self.resp(CMD_UBOOT_JUMP_MEMORY,LOADER_ADDRESS.to_bytes(4,'big')+LOADER_ARGUMENT_SPI_NOR.to_bytes(2,'big')); time.sleep(.5)
    def loader_info(self):
        size=int.from_bytes(self.resp(CMD_GET_USB_BUFFER_SIZE)[:4],"big"); online=self.resp(CMD_GET_ONLINE_DEVICE); fid=int.from_bytes(self.resp(CMD_READ_ID)[:3],"big"); did=int.from_bytes(online[2:6],"little")
        if not 256<=size<=0x10000 or online[0]!=EXPECTED_DEVICE_TYPE or did!=EXPECTED_DEVICE_ID or fid!=EXPECTED_FLASH_ID: raise SafetyError("loader identity mismatch")
        return {"usb_buffer_size":size,"device_type":online[0],"device_id":did,"flash_id":fid}
    def read_flash(self,a,n): return self.t.execute(build_vendor_cdb(CMD_READ_FLASH,a.to_bytes(4,'big')+n.to_bytes(2,'big')),data_in_length=n)
    def erase_sector(self,a): self.resp(CMD_ERASE_SECTOR,a.to_bytes(4,'big'))
    def write_flash(self,a,d): self.t.execute(build_vendor_cdb(CMD_WRITE_FLASH,a.to_bytes(4,'big')+len(d).to_bytes(2,'big')+b'\0'+crc16_xmodem(d).to_bytes(2,'little')),data_out=d)
def read_exact(c,a,n):
    out=bytearray()
    while len(out)<n:
        k=min(IO_CHUNK_SIZE,n-len(out)); out.extend(c.read_flash(a+len(out),k))
    return bytes(out)
def full(c):
    out=bytearray()
    for a in range(0,FLASH_SIZE,IO_CHUNK_SIZE): out.extend(c.read_flash(a,IO_CHUNK_SIZE))
    if len(out)!=FLASH_SIZE: raise SafetyError("dump was not exactly 1 MiB")
    return bytes(out)
def load_manifest(root:Path):
    m=json.loads((root/'seed-sectors/manifest.json').read_text('utf-8'))
    addrs={int(x['sector_base'],0) for x in m['sectors']}
    if m.get('format')!='smk37-v15-s1c7-forced-recovery-seed-bundle-v1' or addrs!=SECTORS: raise SafetyError('manifest format or sector set mismatch')
    if m['input_dump']['sha256']!=LIVE_DUAL_DUMP_SHA256 or not m['input_dump']['required_double_dump_identity']: raise SafetyError('target dump gate mismatch')
    return m
def validate_offline(root:Path,m:dict):
    for x in m['sectors']:
        for key, hkey in [('write_file','patched_sha256'),('rollback_file','expected_pre_sha256')]:
            p=root/'seed-sectors'/x[key]
            if p.stat().st_size!=SECTOR_SIZE or sha256_file(p)!=x[hkey]: raise SafetyError(f"sector artifact hash failed: {p}")
    print('offline validation PASS')
def verify_pre(c,m):
    for x in m['sectors']:
        a=int(x['sector_base'],0); d=read_exact(c,a,SECTOR_SIZE)
        if sha256_bytes(d)!=x['expected_pre_sha256']: raise SafetyError(f"prehash mismatch at 0x{a:05X}")
def verify_outside(pre,post):
    for a in range(0,FLASH_SIZE,SECTOR_SIZE):
        if a not in SECTORS and pre[a:a+SECTOR_SIZE]!=post[a:a+SECTOR_SIZE]: raise SafetyError(f"outside-sector changed at 0x{a:05X}")
def write_plan(c,root,m,mode,journal_path=None):
    rows=[]
    for x in sorted(m['sectors'],key=lambda y:int(y['sector_base'],0)):
        a=int(x['sector_base'],0); fn=x['write_file'] if mode=='seed' else x['rollback_file']; expected=x['patched_sha256'] if mode=='seed' else x['expected_pre_sha256']; data=(root/'seed-sectors'/fn).read_bytes()
        c.erase_sector(a); erased=read_exact(c,a,SECTOR_SIZE)
        if erased!=b'\xff'*SECTOR_SIZE: raise SafetyError(f"erase verify failed at 0x{a:05X}")
        for off in range(0,SECTOR_SIZE,IO_CHUNK_SIZE): c.write_flash(a+off,data[off:off+IO_CHUNK_SIZE])
        got=sha256_bytes(read_exact(c,a,SECTOR_SIZE))
        if got!=expected: raise SafetyError(f"readback mismatch at 0x{a:05X}")
        rows.append({"sector_base":x['sector_base'],"mode":mode,"readback_sha256":got,"write_chunks":16})
        if journal_path: journal_path.write_text(json.dumps({"status":"in_progress","completed_sectors":rows},indent=2)+'\n')
    return rows
class FakeTransport:
    def __init__(self,flash): self.flash=bytearray(flash); self.erased=[]; self.writes=[]; self.observed_vendor_cdbs=[]
    def execute(self,cdb,data_out=None,data_in_length=0):
        cmd=validate_transfer_contract(cdb,data_out,data_in_length)
        if cmd is None:
            r=bytearray(36); r[8:16]=b'WL82    '; r[16:32]=b'UBOOT1.00       '; r[32:36]=b'1.00'; return bytes(r)
        self.observed_vendor_cdbs.append(cmd); a=int.from_bytes(cdb[2:6],'big')
        if cmd==CMD_GET_USB_BUFFER_SIZE: return cmd.to_bytes(2,'big')+(256).to_bytes(4,'big')+b'\0'*10
        if cmd==CMD_GET_ONLINE_DEVICE: return cmd.to_bytes(2,'big')+bytes([EXPECTED_DEVICE_TYPE,0])+EXPECTED_DEVICE_ID.to_bytes(4,'little')+b'\0'*8
        if cmd==CMD_READ_ID: return cmd.to_bytes(2,'big')+EXPECTED_FLASH_ID.to_bytes(3,'big')+b'\0'*11
        if cmd==CMD_UBOOT_WRITE_MEMORY: return b''
        if cmd==CMD_UBOOT_JUMP_MEMORY: return cmd.to_bytes(2,'big')+b'\0'*14
        if cmd==CMD_READ_FLASH:
            n=int.from_bytes(cdb[6:8],'big'); return bytes(self.flash[a:a+n])
        if cmd==CMD_ERASE_SECTOR: self.flash[a:a+SECTOR_SIZE]=b'\xff'*SECTOR_SIZE; self.erased.append(a); return cmd.to_bytes(2,'big')+b'\0'*14
        if cmd==CMD_WRITE_FLASH: self.flash[a:a+len(data_out)]=data_out; self.writes.append((a,len(data_out))); return b''
        raise AssertionError('unhandled')
def self_test(root:Path):
    if crc16_xmodem(b'123456789')!=0x31C3: raise AssertionError('CRC vector failed')
    m=load_manifest(root); validate_offline(root,m); base=bytearray(b'\0'*FLASH_SIZE)
    for x in m['sectors']: base[int(x['sector_base'],0):int(x['sector_base'],0)+SECTOR_SIZE]=(root/'seed-sectors'/x['rollback_file']).read_bytes()
    c=Client(FakeTransport(bytes(base))); verify_pre(c,m); write_plan(c,root,m,'seed')
    post=bytes(c.t.flash)
    for x in m['sectors']:
        a=int(x['sector_base'],0)
        if sha256_bytes(post[a:a+SECTOR_SIZE])!=x['patched_sha256']: raise AssertionError('seed hash mismatch')
    write_plan(c,root,m,'rollback')
    if c.t.erased != [0x0FB000,0x0FC000,0x0FB000,0x0FC000] or any(n>256 for _,n in c.t.writes): raise AssertionError('scope failed')
    for bad in (0,0xFA00,0xFB02,0xFE00):
        try: build_vendor_cdb(bad)
        except SafetyError: pass
        else: raise AssertionError('forbidden CDB accepted')
    print('self-test PASS: S1C7 seed/rollback fake erase-write-readback, exact sectors, CRC, CDB guards')
def run_windows(args,mode):
    root=args.prep; m=load_manifest(root); validate_offline(root,m)
    needed=CONFIRM_SEED if mode=='seed' else CONFIRM_ROLLBACK
    if args.confirm!=needed: raise SafetyError('missing exact explicit confirmations')
    src=root/'tools/windows_scsi_transport.py'; spec=importlib.util.spec_from_file_location('transport',src); mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); mod.validate_transfer_contract=validate_transfer_contract
    ev=root/'restore'/f'{mode}-evidence-{time.strftime("%Y%m%d-%H%M%S",time.gmtime())}'; ev.mkdir(parents=True,exist_ok=False)
    with mod.WindowsScsiTransport(args.device) as t:
        c=Client(t); identity=c.inquiry(); c.upload_official_loader(args.loader.read_bytes()); info=c.loader_info(); pre_a=full(c); pre_b=full(c)
        if pre_a!=pre_b: raise SafetyError('fresh double-dump preflight failed')
        if mode=='seed' and sha256_bytes(pre_a)!=LIVE_DUAL_DUMP_SHA256: raise SafetyError('fresh double-dump SHA does not match target live SHA gate')
        (ev/'pre-dump-a.bin').write_bytes(pre_a); (ev/'pre-dump-b.bin').write_bytes(pre_b); verify_pre(c,m) if mode=='seed' else None
        rows=write_plan(c,root,m,mode,ev/'progress-journal.json'); post=full(c); verify_outside(pre_a,post); (ev/'post-dump.bin').write_bytes(post)
        j={"format":"smk37-s1c7-seed-journal-v1","mode":mode,"identity":identity,"loader_info":info,"fresh_pre_dump_sha256":sha256_bytes(pre_a),"post_dump_sha256":sha256_bytes(post),"outside_seed_sectors_unchanged":True,"sectors":rows,"observed_cdbs":[f'0x{x:04X}' for x in sorted(set(t.observed_vendor_cdbs))]}
        (ev/'restore-journal.json').write_text(json.dumps(j,indent=2)+'\n'); print(json.dumps({"journal":str(ev/'restore-journal.json'),"mode":mode,"sectors":[x['sector_base'] for x in rows]},indent=2))
def macos_blocker(_args):
    raise SafetyError('macOS live writes are not supported in this bundle: no audited mutable macOS WL82 transport is present. Use macos-dry-check only, or run the Windows command on a Windows host.')
def parse(argv):
    ap=argparse.ArgumentParser(description=__doc__); root=Path(__file__).resolve().parents[1]; sp=ap.add_subparsers(dest='cmd',required=True); sp.add_parser('self-test'); sp.add_parser('validate-offline'); sp.add_parser('macos-dry-check')
    for name in ('windows-seed','windows-rollback','macos-seed'):
        p=sp.add_parser(name); p.add_argument('--device',default=r'\\.\PhysicalDriveN'); p.add_argument('--prep',type=Path,default=root); p.add_argument('--loader',type=Path,default=root/'assets/wl82loader.bin'); p.add_argument('--confirm',action='append',default=[])
    return ap.parse_args(argv)
def main(argv):
    try:
        a=parse(argv); root=Path(__file__).resolve().parents[1]
        if a.cmd=='self-test': self_test(root); return 0
        if a.cmd in ('validate-offline','macos-dry-check'): validate_offline(root,load_manifest(root)); return 0
        if a.cmd=='windows-seed': return run_windows(a,'seed') or 0
        if a.cmd=='windows-rollback': return run_windows(a,'rollback') or 0
        if a.cmd=='macos-seed': return macos_blocker(a) or 2
    except (SafetyError,OSError,json.JSONDecodeError,AssertionError) as e:
        print(f'SAFE STOP: {e}',file=sys.stderr); return 2
if __name__=='__main__': raise SystemExit(main(sys.argv[1:]))
'''


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source", type=Path, default=Path("build") / SOURCE_NAME)
    ap.add_argument("--output-dir", type=Path, default=Path("build") / BUNDLE_NAME)
    ap.add_argument("--output-zip", type=Path, default=Path("build") / f"{BUNDLE_NAME}.zip")
    args = ap.parse_args()
    root = Path.cwd()
    src = args.source
    out = args.output_dir
    require(src.is_dir(), "missing S1C7 source seed directory")
    require(not out.exists(), "refusing to overwrite existing bundle directory")
    require(not args.output_zip.exists(), "refusing to overwrite existing bundle zip")
    source_manifest = json.loads((src / "manifest.json").read_text("utf-8"))
    require(source_manifest["input_dump"]["sha256"] == LIVE_DUAL_DUMP_SHA256, "live dual dump SHA gate mismatch")
    require(source_manifest["input_dump"]["required_double_dump_identity"] is True, "dual dump gate missing")
    require(tuple(int(x["sector_base"], 0) for x in source_manifest["sectors"]) == SECTORS, "unexpected sector scope")

    (out / "seed-sectors" / "write-sectors").mkdir(parents=True)
    (out / "seed-sectors" / "rollback-sectors").mkdir(parents=True)
    for item in source_manifest["sectors"]:
        for key in ("write_file", "rollback_file"):
            s = src / item[key]
            d = out / "seed-sectors" / item[key]
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, d)
    manifest = {
        "format": "smk37-v15-s1c7-forced-recovery-seed-bundle-v1",
        "source_manifest": str(src.as_posix()),
        "source_manifest_sha256": sha((src / "manifest.json").read_bytes()),
        "input_dump": source_manifest["input_dump"],
        "offline_only_built": True,
        "device_accessed_during_build": False,
        "transport_opened_during_build": False,
        "safety_policy": {
            "write_scope": "exactly sectors 0x0fb000 and 0x0fc000",
            "preserve_all_other_bytes": True,
            "required_before_seed_write": "two identical fresh 1 MiB dumps whose SHA-256 equals the locked live SHA",
            "rollback": "rollback-sectors restore the exact sector bytes from the locked live dump and preserve all other sectors",
            "forbidden": ["chip erase", "full-flash write", "writes outside 0x0fb000/0x0fc000", "using on any other dump SHA", "live writes during build"],
        },
        "macos": {"live_write_supported": False, "blocker": "No audited mutable macOS WL82 transport is present in this repository bundle; macos-dry-check is supported."},
        "windows": {"live_write_supported": True, "transport": "reviewed windows_scsi_transport.py copied from audited rollback bundle"},
        "sectors": source_manifest["sectors"],
        "post_dump_sha256_if_sectors_applied": source_manifest["post_dump_sha256_if_sectors_applied"],
        "rollback_restores_exact_input_dump": True,
    }
    (out / "seed-sectors" / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (out / "restore").mkdir()
    guard_path = out / "restore" / "smk37_wl82_s1c7_guarded_seed.py"
    guard_path.write_text(GUARD, encoding="utf-8")
    guard_path.chmod(0o755)
    for rel in ("tools/windows_scsi_transport.py", "assets/wl82loader.bin", "THIRD-PARTY-NOTICES.md"):
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(TEMPLATE / rel, dst)
    (out / "README.md").write_text(
        f"# SMK-37 Pro WL82 S1C7 guarded seed bundle\n\n"
        f"Target live dual-dump SHA-256: `{LIVE_DUAL_DUMP_SHA256}`.\n\n"
        "This bundle can seed exactly sectors `0x0fb000` and `0x0fc000` and preserves all other bytes. "
        "It requires two identical fresh 1 MiB dumps and exact sector prehashes before any write, then readback-verifies every sector. "
        "Rollback writes the original two sector images from the locked live dump.\n\n"
        "## Dry checks\n\n"
        "```sh\npython3 restore/smk37_wl82_s1c7_guarded_seed.py self-test\npython3 restore/smk37_wl82_s1c7_guarded_seed.py validate-offline\npython3 restore/smk37_wl82_s1c7_guarded_seed.py macos-dry-check\n```\n\n"
        "## macOS live command\n\n"
        "macOS live writes are blocked in this target-specific bundle because no audited mutable macOS WL82 transport is present. "
        "The supported macOS command is the dry validator above.\n\n"
        "## Windows seed command\n\n"
        "```powershell\npy -3 restore\\smk37_wl82_s1c7_guarded_seed.py windows-seed --device \\\\.\\PhysicalDriveN --confirm I_UNDERSTAND_THIS_ERASES_EXACTLY_TWO_S1C7_SEED_SECTORS --confirm I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_SHA_078C13D698AD08A4CFAC7723E87014000E5557E655BD1F21D75493DC8F652946 --confirm WRITE_S1C7_SEED_SECTORS_NOW\n```\n\n"
        "Replace `PhysicalDriveN` only after identifying the WL82 UBOOT device.\n",
        encoding="utf-8",
    )
    write_hashes(out)
    subprocess.run([sys.executable, str(guard_path), "self-test"], cwd=root, check=True)
    subprocess.run([sys.executable, str(guard_path), "validate-offline"], cwd=root, check=True)
    write_zip(out, args.output_zip)
    print(json.dumps({"bundle": str(out), "zip": str(args.output_zip), "zip_sha256": sha(args.output_zip.read_bytes()), "sectors": [f"0x{x:05x}" for x in SECTORS], "device_accessed": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
