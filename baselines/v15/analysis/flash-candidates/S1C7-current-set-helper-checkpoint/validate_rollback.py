#!/usr/bin/env python3
"""Offline rollback/readback validator for S1-C7 package and optional host-seed sectors.

Default mode checks packaged rollback sectors only. Optional dump arguments must be
regular files, never device paths, and validate target-specific raw-record seed
readback/rollback outside this script's default no-device scope.
"""
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path
HERE=Path(__file__).resolve().parent

def sha_bytes(b: bytes) -> str: return hashlib.sha256(b).hexdigest()
def sha_path(p: Path) -> str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for c in iter(lambda:f.read(1024*1024), b''): h.update(c)
    return h.hexdigest()
def req(ok: bool, msg: str) -> None:
    if not ok: raise SystemExit('FAIL: '+msg)
def regular_file(p: Path) -> None:
    req(p.exists() and p.is_file() and not p.is_symlink(), f'{p} must be a regular file')
    req(not str(p).startswith('/dev/'), 'device paths are forbidden')

def check_packaged() -> None:
    rb=json.loads((HERE/'rollback'/'official-v15-recovery-sectors'/'manifest.json').read_text())
    req(rb['rollback_restores_official_flash'] is True,'packaged rollback restores official')
    for e in rb['changed_sectors']:
        p=HERE/e['file']; b=p.read_bytes()
        req(len(b)==e['size']==0x2000, f"sector size {p.name}")
        req(sha_bytes(b)==e['sha256'], f"sector hash {p.name}")
    seed=json.loads((HERE/'host-seeded-records'/'prefix-manifest.json').read_text())
    req(seed['requires_exact_host_seeded_records'] is True,'seed exactness required')

def validate_seed_readback(manifest: dict, post_a: Path, post_b: Path) -> None:
    regular_file(post_a); regular_file(post_b)
    a=post_a.read_bytes(); b=post_b.read_bytes(); req(a==b,'post readback dumps identical')
    for rec in manifest['records']:
        off=int(rec['physical_offset'],16); prefix=(HERE/'host-seeded-records'/rec['prefix_file']).read_bytes()
        req(a[off:off+len(prefix)]==prefix, f"seed prefix readback record {rec['record_index']}")
    print('PASS optional host-seed readback dumps match exact S1-C7 prefixes')

def validate_seed_rollback(pre: Path, rollback_dump: Path) -> None:
    regular_file(pre); regular_file(rollback_dump)
    req(sha_path(pre)==sha_path(rollback_dump),'rollback readback equals exact pre-dump')
    print('PASS optional host-seed rollback dump equals pre-dump byte-for-byte')

def main() -> None:
    ap=argparse.ArgumentParser()
    ap.add_argument('--post-dump-a', type=Path)
    ap.add_argument('--post-dump-b', type=Path)
    ap.add_argument('--pre-dump', type=Path)
    ap.add_argument('--rollback-readback-dump', type=Path)
    args=ap.parse_args()
    check_packaged()
    seed=json.loads((HERE/'host-seeded-records'/'prefix-manifest.json').read_text())
    if args.post_dump_a or args.post_dump_b:
        req(args.post_dump_a and args.post_dump_b,'provide both post dumps')
        validate_seed_readback(seed,args.post_dump_a,args.post_dump_b)
    if args.pre_dump or args.rollback_readback_dump:
        req(args.pre_dump and args.rollback_readback_dump,'provide pre and rollback readback dump')
        validate_seed_rollback(args.pre_dump,args.rollback_readback_dump)
    print('S1-C7 rollback validator PASS: packaged rollback checked; no device path opened')
if __name__=='__main__': main()
