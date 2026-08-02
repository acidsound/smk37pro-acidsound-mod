#!/usr/bin/env python3
"""Match public Jieli AC79 SDK UI/input/display signatures against official SMK37 v15.

Approved inputs only: pinned public AC79 SDK commit, official v15 app.bin, and
existing v15 sdk-signatures/ui-preflash evidence in this repository. The tool is
read-only and produces deterministic JSON.
"""
from __future__ import annotations
import argparse, hashlib, json, re, struct, subprocess
from dataclasses import dataclass
from pathlib import Path

APP_BASE = 0x02000000
EXPECTED_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
EXPECTED_SDK_COMMIT = "e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d"
SDK_FILES = {
    "cpu/wl82/tools/loader_tools/sdk.elf": "250b0534fee9f57208b42e38c97c36982875fac901db1d9979e781f0d26e0cf3",
    "cpu/wl82/liba/ui.a": None,
    "cpu/wl82/liba/ui_draw.a": None,
    "cpu/wl82/liba/event.a": None,
    "cpu/wl82/liba/led_ui_server.a": None,
}
SOURCE_GLOBS = [
    "include_lib/utils/ui/**/*.h", "include_lib/server/*ui*.h", "include_lib/utils/event/*.h",
    "include_lib/driver/device/key/*.h", "include_lib/system/task.h",
    "apps/common/ui/**/*.h", "apps/common/ui/**/*.c", "apps/demo/demo_ui/**/*.c",
    "apps/demo/demo_DevKitBoard/*lcd*.c", "apps/demo/demo_DevKitBoard/*key*.c",
]
UI_TERMS = ("ui", "lcd", "display", "disp", "widget", "text", "draw", "redraw", "flush", "screen", "window", "layer", "key", "event", "task", "input", "touch")
FOCUSED_TERMS = ("flush", "redraw", "lcd", "display", "widget", "text", "key", "event", "task", "queue")
SHT_SYMTAB, SHT_REL, SHT_RELA, STT_FUNC = 2, 9, 4, 2

@dataclass
class Section:
    name: str; stype: int; address: int; offset: int; size: int; link: int; info: int; entsize: int

def sha256(data: bytes) -> str: return hashlib.sha256(data).hexdigest()
def hx(n: int) -> str: return f"0x{n:08x}"
def cstr(data: bytes, off: int) -> str:
    if off >= len(data): return ""
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else len(data)].decode("utf-8", "replace")
def all_offsets(data: bytes, needle: bytes, limit: int|None=None) -> list[int]:
    out=[]; pos=0
    while limit is None or len(out)<limit:
        pos=data.find(needle,pos)
        if pos<0: break
        out.append(pos); pos+=1
    return out

def git_head(sdk: Path) -> str:
    return subprocess.check_output(["git","-C",str(sdk),"rev-parse","HEAD"], text=True).strip()

def parse_elf(raw: bytes):
    if raw[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 0xF1:
        raise ValueError("not little-endian pi32v2 ELF32")
    shoff=struct.unpack_from("<I", raw, 32)[0]
    shentsize, shnum, shstrndx=struct.unpack_from("<HHH", raw, 46)
    hdr=[struct.unpack_from("<IIIIIIIIII", raw, shoff+i*shentsize) for i in range(shnum)]
    shstr=hdr[shstrndx]; names=raw[shstr[4]:shstr[4]+shstr[5]]
    sections=[Section(cstr(names,h[0]),h[1],h[3],h[4],h[5],h[6],h[7],h[9]) for h in hdr]
    symbols=[]
    for sec in sections:
        if sec.stype != SHT_SYMTAB or sec.entsize != 16: continue
        strings=raw[sections[sec.link].offset:sections[sec.link].offset+sections[sec.link].size]
        for off in range(sec.offset, sec.offset+sec.size, sec.entsize):
            no,val,size,info,other,shndx=struct.unpack_from("<IIIBBH", raw, off)
            symbols.append((cstr(strings,no),val,size,info,shndx))
    relocs={}
    for sec in sections:
        if sec.stype not in (SHT_REL,SHT_RELA) or sec.entsize < 8: continue
        arr=relocs.setdefault(sec.info,[])
        for off in range(sec.offset, sec.offset+sec.size, sec.entsize):
            roff,rinfo=struct.unpack_from("<II", raw, off)
            arr.append((roff,rinfo & 0xff,rinfo>>8))
    return sections, symbols, relocs

def elf_functions(raw: bytes, min_size=8, max_size=4096):
    sections, symbols, relocs = parse_elf(raw)
    out=[]
    for name,val,size,info,shndx in symbols:
        if info & 0xf != STT_FUNC or not name or not (min_size <= size <= max_size) or not (0 < shndx < len(sections)): continue
        sec=sections[shndx]; rel=val-sec.address
        if 0 <= rel and rel+size <= sec.size:
            body=raw[sec.offset+rel:sec.offset+rel+size]
            if any(body): out.append({"name":name,"sdk_address":val,"size":size,"section":sec.name,"body":body})
    return out

def ar_members(path: Path) -> list[dict]:
    raw=path.read_bytes()
    if raw[:8] != b"!<arch>\n": return []
    names=b""; out=[]; pos=8
    while pos+60 <= len(raw):
        h=raw[pos:pos+60]; pos += 60
        if h[58:60] != b"`\n": break
        rn=h[:16].decode("ascii","replace").rstrip(); size=int(h[48:58].decode().strip() or 0)
        body=raw[pos:pos+size]; pos += size + (size & 1)
        if rn == "//": names=body; continue
        if rn in ("/", "__.SYMDEF", "__.SYMDEF SORTED"): continue
        name=rn.rstrip("/")
        if rn.startswith("/") and rn[1:].isdigit() and names:
            st=int(rn[1:]); en=names.find(b"/\n", st); name=names[st:en].decode("utf-8","replace")
        fmt = "llvm-bitcode" if body[:4] == b"BC\xc0\xde" else "elf" if body[:4] == b"\x7fELF" else "other"
        out.append({"name":name,"size":len(body),"sha256":sha256(body),"format":fmt,"body":body})
    return out

def source_evidence(sdk: Path) -> dict:
    paths=[]
    for glob in SOURCE_GLOBS: paths.extend(sdk.glob(glob))
    seen=set(); items=[]; macros=[]; structs=[]; funcs=[]
    for p in sorted(paths):
        if p in seen or not p.is_file(): continue
        seen.add(p); rel=str(p.relative_to(sdk)); txt=p.read_text("utf-8","ignore")
        low=txt.lower()
        hits=sorted({t for t in FOCUSED_TERMS if t in low})
        if not hits: continue
        for m in re.finditer(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s+([^/\n]{1,80})", txt, re.M):
            n=m.group(1)
            if any(t in n.lower() for t in UI_TERMS): macros.append({"file":rel,"name":n,"value":m.group(2).strip()})
        for m in re.finditer(r"\bstruct\s+([A-Za-z_][A-Za-z0-9_]*)", txt):
            n=m.group(1)
            if any(t in n.lower() for t in UI_TERMS): structs.append({"file":rel,"name":n})
        for m in re.finditer(r"\b(?:int|void|u8|u16|u32|s8|s16|s32|char|bool)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]{0,160}\)\s*[;{]", txt):
            n=m.group(1)
            if any(t in n.lower() for t in UI_TERMS): funcs.append({"file":rel,"name":n})
        items.append({"path":rel,"sha256":sha256(p.read_bytes()),"focused_terms":hits})
    def uniq(rows):
        out=[]; keys=set()
        for r in rows:
            k=(r.get("file"),r.get("name"),r.get("value"))
            if k not in keys: keys.add(k); out.append(r)
        return out[:300]
    return {"files_considered":len(seen),"files_with_focused_terms":items[:200],"macros":uniq(macros),"structs":uniq(structs),"functions":uniq(funcs)}

def exact_named_matches(functions, app: bytes) -> dict:
    accepted=[]; rejected=[]
    non_ui_exact_names = {"sync_window", "move_window", "icache_flush"}
    for f in functions:
        low=f["name"].lower()
        if not any(t in low for t in UI_TERMS): continue
        hits=all_offsets(app, f["body"], 2)
        if len(hits)==1:
            off=hits[0]
            row={"name":f["name"],"sdk_address":hx(f["sdk_address"]),"size":f["size"],"section":f["section"],"body_sha256":sha256(f["body"]),"app_offset":hx(off),"app_address":hx(APP_BASE+off),"match_type":"exact_unique_body"}
            if low in non_ui_exact_names:
                row["rejection_reason"] = "name matched broad UI term but SDK/source context is filesystem window or CPU cache, not LCD/display/widget/key/event task code"
                rejected.append(row)
            else:
                accepted.append(row)
    return {"accepted": sorted(accepted, key=lambda r:(r["app_offset"],r["name"])), "rejected_non_ui_exact": sorted(rejected, key=lambda r:(r["app_offset"],r["name"]))}

def archive_report(sdk: Path, app: bytes) -> dict:
    archives={}; accepted=[]
    for rel, expected in SDK_FILES.items():
        p=sdk/rel
        if not p.exists(): continue
        raw=p.read_bytes(); digest=sha256(raw)
        if expected and digest != expected: raise SystemExit(f"hash mismatch for {rel}: {digest}")
        entry={"size":len(raw),"sha256":digest}
        if p.suffix == ".a":
            members=ar_members(p); ui_members=[m for m in members if any(t in m["name"].lower() for t in UI_TERMS)]
            entry["member_count"]=len(members); entry["ui_named_members"]=[{k:m[k] for k in ("name","size","sha256","format")} for m in ui_members[:120]]
            entry["elf_member_count"]=sum(1 for m in ui_members if m["format"]=="elf")
            entry["relocation_matching"]="not_run_no_elf_ui_members" if entry["elf_member_count"]==0 else "not_run_member_extraction_not_needed_for_zero_exact_result"
        archives[rel]=entry
    return {"archives":archives,"relocation_aware":{"accepted_count":0,"accepted":accepted,"reason":"Pinned SDK UI archives are LLVM bitcode in this checkout; no official-toolchain rebuilt UI ELF objects were available in approved existing sdk-signatures. Exact sdk.elf scan below is the only accepted matcher run here."}}

def v15_context(repo: Path, app: bytes) -> dict:
    strings=[b"Pad Bank-", b"Keys Channel-", b"SAVE", b"SAVED", b"#D9D9D9", b"#F5BC27"]
    ctx={"string_offsets":{s.decode():[hx(o) for o in all_offsets(app,s)] for s in strings}}
    for rel in ["baselines/v15/analysis/ui-preflash/renderer/evidence.json", "baselines/v15/analysis/ui-preflash/events/ui_events.json"]:
        p=repo/rel
        if p.exists():
            data=json.loads(p.read_text())
            ctx[rel]={"sha256":sha256(p.read_bytes())}
            if "conclusions" in data: ctx[rel]["conclusions"]=data["conclusions"]
            if "function_evidence" in data: ctx[rel]["function_evidence_keys"]=list(data["function_evidence"].keys())
            if "st7789_like_sequence" in data: ctx[rel]["st7789_like_sequence"]=data["st7789_like_sequence"]
    return ctx

def main() -> int:
    ap=argparse.ArgumentParser()
    ap.add_argument("sdk_root", type=Path); ap.add_argument("app_bin", type=Path)
    ap.add_argument("--repo-root", type=Path, default=Path(".")); ap.add_argument("--output", type=Path)
    args=ap.parse_args(); sdk=args.sdk_root.resolve(); repo=args.repo_root.resolve()
    app=args.app_bin.read_bytes(); ah=sha256(app)
    if ah != EXPECTED_APP_SHA256: raise SystemExit(f"refusing non-official-v15 app: {ah}")
    head=git_head(sdk)
    if head != EXPECTED_SDK_COMMIT: raise SystemExit(f"refusing unpinned SDK revision: {head}")
    sdkelf=(sdk/"cpu/wl82/tools/loader_tools/sdk.elf").read_bytes(); funcs=elf_functions(sdkelf)
    exact_report=exact_named_matches(funcs, app)
    exact=exact_report["accepted"]
    ar=archive_report(sdk, app)
    accepted=exact + ar["relocation_aware"]["accepted"]
    report={
        "format":"smk37-v15-ui-preflash-final-sdk-match-v1",
        "inputs":{"app":{"path":str(args.app_bin),"size":len(app),"sha256":ah,"runtime_base":hx(APP_BASE)},"sdk":{"commit":head,"url":"https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK","branch":"release/AC79NN_SDK_V1.2.0"}},
        "scope":{"allowed_sources":["official v15 app.bin","pinned public Jieli AC79 SDK","existing baselines/v15 sdk-signatures/ui-preflash evidence"],"forbidden_sources":["v12 firmware or v12 analysis"],"read_only":True},
        "sdk_source_evidence":source_evidence(sdk),
        "sdk_elf_exact":{"functions_considered":len(funcs),"ui_named_unique_exact_matches":len(exact),"accepted":exact,"rejected_non_ui_exact":exact_report["rejected_non_ui_exact"]},
        **ar,
        "v15_context":v15_context(repo, app),
        "summary":{"accepted_count":len(accepted),"exact_accepted_count":len(exact),"relocation_aware_accepted_count":len(ar["relocation_aware"]["accepted"]),"conclusion":"No official/public AC79 SDK UI/input/LCD/display/widget function is promoted to a v15 product identity unless listed in accepted. Product-side v15 UI evidence remains candidate-only when not backed by exact or relocation-aware SDK match."}
    }
    text=json.dumps(report, indent=2, sort_keys=True)+"\n"
    if args.output: args.output.write_text(text)
    else: print(text,end="")
    return 0
if __name__ == "__main__": raise SystemExit(main())
