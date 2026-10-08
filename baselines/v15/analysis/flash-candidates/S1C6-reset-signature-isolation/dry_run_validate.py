#!/usr/bin/env python3
import argparse, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parent; PKG='SMK37Pro-v15-S1C6-reset-signature-isolation-S16-marked.fwsc'; PKGSHA='fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886'; HASHES=['f0f9376291d53e169daae0cbb05de43ad2a6c6f836ff5edd1541f314e2515c8e', '7c7a8ac8d57bd78b8d531fa8997e7d9c18ce4e0d8a267cc22549ba71d5e3e9c4', '523ccbc81eef766fc73bda72a78d3a28ba3f1fcabc1146db78252673f8d5ed7a', '14d65142c52fbd4775ab071639886c203cc03d860deb62e6de25c048cb9a712b', 'efab2e0db1e444d4ab8e96cd7125825fdbd0445e3e05b8436ae7bbd2ae830364', '981e0772ac58174cb94a1794bbdac10da9c2679a0f69112b14a114d75d70481b', 'd73e236482ecd7d9b791ea6119b13d63b09eae5565f682b8f2dc0b4678277579', '85625d999b3c23b578362fde17e9022db16ef9ecde5926e198f3206977cdba17', '3e06351976cdd90b3e888b32ccca8716de991c95ff44eb73e9c26a3b912150dd', 'ef96628a3f2cb2a2b6028687e1dc9fa89f147edf7b4c4eb229b7d27250704805', 'c6483dabc9e1a863f2682b5c11ea8a91e3ef38212926930d8de24afa3db6f9de', '11c7dfae80eb8ddaf88ec971ff1b3ce8b4d76894f4550ec3a0b5113c7e58bdde', 'a97d43e1351177f4b7e4770b2170d07ae7d7dbd33bd6bb6439a441cb66f74a68', '3680c3abf14c6a13096fe56953789bc2572fe2fd0d82248f8e4e893482a3be19', '6611e75bfb8b11206f6303a63fdf6d50ee9beb8a72be2e69f9233a8f87e93f3a', '8b3bbbccf103bd41ea93430b694be1b8ab17d9a29ed0bee3d6fc0570e7d95721', 'b06e83fdf0972a652ca4561eb08c6312b51be24c54c2619a1d6c2d67cc2bf30c']; HEADER=bytes.fromhex('f0430000011b')
def sh(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def req(x,m):
    if not x: raise SystemExit('FAIL: '+m)
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--json',action='store_true'); a=ap.parse_args(); req(sh(HERE/PKG)==PKGSHA,'package hash'); man=json.loads((HERE/'inputs/packets/packet-manifest.json').read_text()); req(man['packet_count']==17 and man['reset_packet_count']==1 and man['voice_packet_count']==16,'17-packet manifest')
    for i,it in enumerate(man['packets']):
        b=(HERE/'inputs/packets'/it['file']).read_bytes(); req(len(b)==163 and b.startswith(HEADER) and b[-1]==0xf7, f'packet {i} framing'); req(hashlib.sha256(b).hexdigest()==HASHES[i]==it['sha256'], f'packet {i} hash')
        if it['kind']=='reset': req(b[6]==0x64 and b[7]==0x65 and b[161]==0x00, f'reset packet signature/byte161')
        else: req(b[161]==it['playback_note']==60, f'packet {i} C4 playback byte')
    res={'status':'DRY_RUN_PASS','device_accessed':False,'midi_transport_opened':False,'send_enabled':False,'package_sha256':PKGSHA,'wire_playback_note_offset':161,'packet_count':17,'reset_signature':'0x64 0x65','duplicate_playback_note':'all C4 (60)'}
    print(json.dumps(res,sort_keys=True) if a.json else 'S1-C6 Reset Signature Isolation dry-run PASS: 1 reset + 16 all-C4 packets, no USB/MIDI/device/flash/reset action')
if __name__=='__main__': main()
