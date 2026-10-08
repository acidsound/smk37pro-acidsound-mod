#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parent; PKG='SMK37Pro-v15-S1C4-playback-note-v2-slotmeta.fwsc'; PKGSHA='4151fb69acf44c75e58072871818869ebc0520828b86e3b05f87d325fc821c71'; HASHES=['ebb0a98d0a15c01d3f3035f114f852de703920d712d607cc2342637ec3421b88', '182e4a54ef667974c364471675854de526b1b773eeaf35e9edef9629af620cc2', '964715e7c31f7512a9690736fcaa61c1500f55814d807ed8f677d6e9810a21ec', 'a16c453b38e7d76791abd90198728db96cda06be454683643e3ba1327e2e6bc9', '3014185c51b494570b792220203155131a5ecaf6a234be2b18b90ea1dfc14df2', '2de0d665aaaeb67a755d2a978dacdb55bacc0cc8a26863df81d4533f65944d3c', '6ae4c27b605c3e40572953cb9146e83471bbdc2463df2871b2cef5e2e1dd16b2', '68b1162755692c41cee6290b2626cfdf0eb1cefeaa106d7dfb71cc64ddbc6cbf', 'd5c460400f82f8b3fe450157021829adbdf83dbb5791fb2eba8e0159884b1fe2', '3294900a53fc9320f22bfcb1137d7c7421760dfeba4b4f7d725ea046f2d28a23', '1f1e9530ce97cfe957ff5995330dbd2bf3abb1893fa1dd05aa8222a90db8845d', 'a62621ba5927c8a7dfadae2ef8898d499d4484ba336fd8b182bfe9ce5578d286', '7abc2a3009ae6c68a1ad8d6d2f7c6bf9e33d18fd213ec6fc47165673a8837830', '88ca1d1555bc67f99290b6c802192dfef2b4f22e867030cccd1bb692714c1873', '898918184fc8f89879ffb07aff2fbbbd2fbeabc590a133139a86f3394f6b8287', 'fdcd31bb040918ac398dfb1a508841d0698a3292670b0a484e435c0f1257c890']; HEADER=bytes.fromhex('f0430000011b')
def sh(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def req(x,m):
    if not x: raise SystemExit('FAIL: '+m)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); a=ap.parse_args(); req(sh(HERE/PKG)==PKGSHA,'package hash'); man=json.loads((HERE/'inputs/packets/packet-manifest.json').read_text());
    for i,it in enumerate(man['packets']):
        b=(HERE/'inputs/packets'/it['file']).read_bytes(); req(len(b)==163 and b.startswith(HEADER) and b[-1]==0xf7, f'packet {i} framing'); req(hashlib.sha256(b).hexdigest()==HASHES[i]==it['sha256'], f'packet {i} hash'); req(b[161]==it['playback_note']==it['trigger_note'], f'packet {i} playback byte')
    res={'status':'DRY_RUN_PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'package_sha256':PKGSHA,'wire_playback_note_offset':161,'packet_count':16}
    print(json.dumps(res,sort_keys=True) if a.json else 'S1-C4 Playback Note dry-run PASS: no USB/MIDI/device/flash/reset action')
if __name__=='__main__': main()
