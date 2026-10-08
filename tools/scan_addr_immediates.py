#!/usr/bin/env python3
import gzip, re, collections

V15 = 'baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz'
V16 = 'baselines/v15/analysis/v15-vs-v16-app-diff-2026-10-01/results/v16-recursive-listing.tsv.gz'
WINDOWS = [(0x10000,0x20000,'lsfr'),(0x20000,0x30000,'bsfr'),(0x40000,0x50000,'hsfr'),
           (0x50000,0x60000,'psfr'),(0x1ee0000,0x1ef0000,'csfr'),
           (0x1f20000,0x2000000,'cache'),(0x4000000,0x4010000,'sdram'),
           (0x1c00000,0x1c80000,'ram0')]

def scan(path):
    c = collections.defaultdict(set)
    with gzip.open(path, 'rt') as f:
        f.readline()
        for line in f:
            q = line.rstrip().split(chr(9))
            if len(q) < 7 or q[3] not in ('mov','movz'):
                continue
            for t in re.findall(r'0x[0-9a-fA-F]+', q[4]):
                v = int(t,16)
                for lo,hi,nm in WINDOWS:
                    if lo <= v < hi:
                        c[nm].add(v)
    return c

a = scan(V15)
b = scan(V16)
print('window        v15  v16')
for lo,hi,nm in WINDOWS:
    print('%-12s %5d %5d' % (nm, len(a[nm]), len(b[nm])))

ra = sorted(a['ram0'])
rb = sorted(b['ram0'])
print()
print('RAM0 distinct: v15=%d v16=%d' % (len(ra), len(rb)))
for v in ra:
    cand = [w for w in rb if 0 <= w - v <= 0x100]
    if len(cand) == 1:
        print('%#012x -> %#012x  +%#x' % (v, cand[0], cand[0] - v))

