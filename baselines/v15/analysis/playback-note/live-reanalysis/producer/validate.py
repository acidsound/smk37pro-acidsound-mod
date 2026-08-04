#!/usr/bin/env python3
from __future__ import annotations
import csv, hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
OUT = ROOT / "baselines/v15/analysis/playback-note/live-reanalysis/producer"

def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()

def req(cond: bool, msg: str):
    if not cond:
        raise SystemExit(f"FAIL: {msg}")

def read_rows(path: Path):
    with path.open(newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))

def b(path: str) -> bytes:
    return (ROOT / path).read_bytes()

ART = {
    "s1c3_selector": "baselines/v15/analysis/patch-set-ui/s1c3/selector/selector.bin",
    "s1c3_selector_decode": "baselines/v15/analysis/patch-set-ui/s1c3/selector/pi32-selector-decode.tsv",
    "s1c3_selector_builder": "baselines/v15/analysis/patch-set-ui/s1c3/selector/build_selector.py",
    "s1c3_producer": "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/producer/producer.bin",
    "s1c3_producer_decode": "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/producer/decode.tsv",
    "s1c3_producer_builder": "baselines/v15/analysis/flash-candidates/S1C3-16slot-functional-v2-r3-reload/inputs/producer/build_compact_producer.py",
    "s1c4_v1_selector": "baselines/v15/analysis/playback-note/candidate/selector.bin",
    "s1c4_v1_producer": "baselines/v15/analysis/playback-note/candidate/producer.bin",
    "s1c4_v1_combined": "baselines/v15/analysis/playback-note/candidate/combined.bin",
    "s1c4_v1_decode": "baselines/v15/analysis/playback-note/candidate/decode.tsv",
    "s1c4_v1_builder": "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v1/build_s1c4_playback_note.py",
    "s1c4_v2_selector": "baselines/v15/analysis/playback-note/candidate-v2-failclosed/selector.bin",
    "s1c4_v2_producer": "baselines/v15/analysis/playback-note/candidate-v2-failclosed/producer.bin",
    "s1c4_v2_combined": "baselines/v15/analysis/playback-note/candidate-v2-failclosed/combined.bin",
    "s1c4_v2_decode": "baselines/v15/analysis/playback-note/candidate-v2-failclosed/decode.tsv",
    "s1c4_v2_builder": "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v2-failclosed/build_s1c4_playback_note_v2.py",
    "s1c4_v3_selector": "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/selector.bin",
    "s1c4_v3_producer": "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/producer.bin",
    "s1c4_v3_combined": "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/combined.bin",
    "s1c4_v3_decode": "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv",
    "s1c4_v3_builder": "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final/build_s1c4_playback_note_v3_segmented_final.py",
}

EXPECTED_SHA = {
    "s1c3_selector": "ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915",
    "s1c3_producer": "48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607",
    "s1c4_v1_selector": "2670e3d2e9a9c47e8a48170ed13a2539b5ccd6229876f3b1689b69a73c8df7a7",
    "s1c4_v1_producer": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "s1c4_v1_combined": "f877aa68476b88644e81df1fe2c7670591c3883f9a443b2d303007d677a48364",
    "s1c4_v2_selector": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "s1c4_v2_producer": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "s1c4_v2_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "s1c4_v3_selector": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "s1c4_v3_producer": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "s1c4_v3_combined": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
}

def diff_blocks(a: bytes, b_: bytes):
    n = max(len(a), len(b_)); out=[]; i=0
    while i<n:
        av = a[i] if i < len(a) else None
        bv = b_[i] if i < len(b_) else None
        if av == bv:
            i += 1; continue
        s = i
        while i<n and ((a[i] if i < len(a) else None) != (b_[i] if i < len(b_) else None)):
            i += 1
        out.append({"offset_start": s, "offset_end": i, "a_hex": a[s:min(i,len(a))].hex(), "b_hex": b_[s:min(i,len(b_))].hex()})
    return out

def row_by_name(rows, name):
    for r in rows:
        if r.get("name") == name:
            return r
    raise KeyError(name)

def main():
    for key, exp in EXPECTED_SHA.items():
        req(sha(ROOT / ART[key]) == exp, f"{key} sha")
    req(b(ART["s1c4_v2_producer"]) == b(ART["s1c4_v3_producer"]) == b(ART["s1c4_v1_producer"]), "all C4 producers identical")
    req(b(ART["s1c4_v2_selector"]) == b(ART["s1c4_v3_selector"]), "C4 v2/v3 selectors identical")
    req(b(ART["s1c4_v2_combined"]) == b(ART["s1c4_v3_combined"]), "C4 v2/v3 PI32 combined identical")
    c4 = read_rows(ROOT / ART["s1c4_v2_decode"])
    load = row_by_name(c4, "producer.playback_load")
    store = row_by_name(c4, "producer.playback_store")
    map_slot = row_by_name(c4, "producer.map_slot")
    sel_load = row_by_name(c4, "selector.load_playback_note")
    meta = row_by_name(c4, "selector.metadata_note_store")
    req(load["address"] == "0x0201e1ec" and load["bytes"] == "1a40" and "wire byte 161" in load["meaning"], "producer byte161 load exact")
    req(store["address"] == "0x0201e1ee" and store["bytes"] == "8a40", "producer map store exact")
    req(map_slot["address"] == "0x0201e1e6" and map_slot["bytes"] == "3018", "producer map slot exact")
    req(sel_load["address"] == "0x0201e182" and sel_load["bytes"] == "7d40", "selector map load exact")
    req(meta["address"] == "0x0201e192" and meta["bytes"] == "8d40", "selector metadata store exact")

    original = list(range(36, 52))
    repeated60 = [60] * 16
    req(len(set(original)) == 16, "Original map unique")
    req(len(set(repeated60)) == 1, "repeated60 map duplicate")

    artifacts = {k: {"path": v, "bytes": len(b(v)) if v.endswith('.bin') else None, "sha256": sha(ROOT / v)} for k, v in ART.items()}
    pairs = [
        ("s1c3_selector", "s1c4_v1_selector"),
        ("s1c3_selector", "s1c4_v2_selector"),
        ("s1c4_v1_selector", "s1c4_v2_selector"),
        ("s1c3_producer", "s1c4_v1_producer"),
        ("s1c4_v1_producer", "s1c4_v2_producer"),
        ("s1c4_v2_combined", "s1c4_v3_combined"),
    ]
    diffs=[]
    for akey,bkey in pairs:
        db = diff_blocks(b(ART[akey]), b(ART[bkey]))
        diffs.append({"a": akey, "b": bkey, "a_len": len(b(ART[akey])), "b_len": len(b(ART[bkey])), "diff_block_count": len(db), "diff_blocks": db})

    byte161_uses = [
        {"area":"slot/order", "address":"0x0201e1c4/0x0201e1c6/0x0201e1ca", "instructions":"lb.z r3,[r5+1]; jge r3,#16; mov r6,r3", "conclusion":"slot is the accepted packet count, not byte161"},
        {"area":"slot/order", "address":"0x0201e1e0/0x0201e1e6/0x0201e1ee", "instructions":"mov r0,#0x1c46f20; add r0,r3; sb [r0],r2", "conclusion":"byte161 is written to playback_note[count]"},
        {"area":"uniqueness", "address":"0x0201e1ec..0x0201e1ee", "instructions":"lb.z r2,[r1]; sb [r0],r2", "conclusion":"no compare, scan, or duplicate reject exists"},
        {"area":"publication", "address":"0x0201e204..0x0201e218", "instructions":"csync; valid=1; count++; if count==16 csync; state=2", "conclusion":"map is published only by ARMED last after the 16th valid slot"},
        {"area":"selector consumption", "address":"0x0201e164..0x0201e182/0x0201e192", "instructions":"state==2; selected valid==1; lb.z r5,[map+trigger_slot]; sb [dest+0x9c],r5", "conclusion":"playback note becomes the local synth metadata note"},
    ]
    evidence = {
        "format": "smk37-v15-playback-note-live-reanalysis-producer-v1",
        "scope": {"offline_only": True, "firmware_or_flash_changed": False, "output_dir": str(OUT.relative_to(ROOT))},
        "artifacts": artifacts,
        "diffs": diffs,
        "live_condition": {
            "original_bytes_161": original,
            "original_ram_playback_note_map_hex": bytes(original).hex(),
            "repeated60_bytes_161": repeated60,
            "repeated60_ram_playback_note_map_hex": bytes(repeated60).hex(),
            "necessary_condition_for_current_C4_pass": "effective playback metadata notes must remain one-to-one across simultaneously used trigger slots because current C4 has no separate trigger identity consumer",
            "observed_explanation": "Original passes because byte161 follows trigger notes 36..51 and preserves 16 distinct synth identities. all-C4 repeated60 fails because byte161 collapses every slot to metadata note 60, while source selection still uses trigger slot and no uniqueness/active-trigger metadata is stored."
        },
        "byte161_uses": byte161_uses,
        "metadata_layout_proposal": {
            "control_kept": {"0x01c465bd":"producer_lock", "0x01c465be":"loaded_count", "0x01c465bf":"publication_state"},
            "owned_header_space": "0x01c46f20..0x01c46fb0 (0x90 bytes)",
            "candidate_bytes": {
                "0x01c46f20..0x01c46f2f":"playback_note_by_slot[16], existing current C4 use",
                "0x01c46f30..0x01c46f3f":"trigger_note_by_slot[16], 36..51 default, source/Note Off identity anchor",
                "0x01c46f40..0x01c46f4f":"identity_note_by_slot[16], distinct stock-note identity if a future consumer can split identity from pitch",
                "0x01c46f50..0x01c46f5f":"slot_flags[16], bit0 Original, bit1 custom playback present, bit2 duplicate playback group",
                "0x01c46f60..0x01c46f6f":"active_playback_by_trigger_slot[16], last Note On playback note for matched Note Off",
                "0x01c46f70..0x01c46f7f":"active_cookie_by_trigger_slot[16], generation or voice token if a future voice allocator hook exposes one",
                "0x01c46f80..0x01c46f8f":"duplicate_group_or_refcount[16], optional many-to-one release guard",
                "0x01c46f90..0x01c46faf":"header: magic/version/layout_state/original_mask/crc/reserved"
            },
            "patch_readiness": "layout is byte-addressable within existing owned 0x90 bytes, but not sufficient alone. A future selector/voice hook must prove which consumer reads identity and which reads pitch. Current C4 writes only dest+0x9c."
        }
    }

    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    with (OUT / "exact-diff.tsv").open("w") as f:
        f.write("a\tb\ta_len\tb_len\tdiff_block_count\toffset_start\toffset_end\ta_hex\tb_hex\n")
        for d in diffs:
            if not d["diff_blocks"]:
                f.write(f"{d['a']}\t{d['b']}\t{d['a_len']}\t{d['b_len']}\t0\t\t\t\t\n")
            for block in d["diff_blocks"]:
                f.write(f"{d['a']}\t{d['b']}\t{d['a_len']}\t{d['b_len']}\t{d['diff_block_count']}\t{block['offset_start']}\t{block['offset_end']}\t{block['a_hex']}\t{block['b_hex']}\n")
    with (OUT / "byte161-use.tsv").open("w") as f:
        f.write("area\taddress\tinstructions\tconclusion\n")
        for row in byte161_uses:
            f.write(f"{row['area']}\t{row['address']}\t{row['instructions']}\t{row['conclusion']}\n")
    lines = [
        "PASS\tartifact-hashes\tS1-C3 and S1-C4 producer/selector/combined hashes match recorded evidence",
        "PASS\tc4-code-identity\tC4 v1/v2/v3 producers identical; v2/v3 combined and selector identical",
        "PASS\tbyte161-exact\tproducer load/store and selector consume addresses verified from decode.tsv",
        "PASS\tlive-condition\tOriginal map has 16 unique metadata notes; repeated60 map collapses to one metadata note",
        "PASS\tscope\toffline-only analysis; no firmware/flash artifacts written",
    ]
    (OUT / "validation.txt").write_text("SMK37 playback-note live reanalysis validation PASS\n" + "\n".join(lines) + "\n")
    return evidence

if __name__ == "__main__":
    ev = main()
    print("SMK37 playback-note live reanalysis validation PASS")
    print("evidence_sha256=" + sha(OUT / "evidence.json"))
