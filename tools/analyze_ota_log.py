#!/usr/bin/env python3
"""Analyze an exact_ota transcript to derive the device-side OTA pattern.

Parses "request N flash=F address=0x... length=L" lines and reports:
  - request count per stage (split at 0xE0000000 / 0xF0000000)
  - stage-1 structural verification reads (the first reads)
  - stage-2 write coverage: addresses, chunk sizes, mapping to flash offsets
"""
from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

REQ = re.compile(r"request (\d+) flash=(\d+) address=(0x[0-9a-f]+) length=(\d+)")


def main() -> int:
    path = Path(sys.argv[1] if len(sys.argv) > 1 else "logs/v15/ota-v15-s1c6-reset-sig-20260814.log")
    requests: list[tuple[int, int, int]] = []  # (address, length, flash)
    for line in path.read_text(errors="replace").splitlines():
        m = REQ.search(line)
        if m:
            requests.append((int(m.group(3), 16), int(m.group(4)), int(m.group(2))))

    print(f"total requests: {len(requests)}")

    # split stages at completion markers
    stage1: list[tuple[int, int, int]] = []
    stage2: list[tuple[int, int, int]] = []
    current = stage1
    for addr, length, flash in requests:
        if addr == 0xE0000000:
            print(f"stage-1 completion at request #{len(stage1) + 1} (0xE0000000 len {length})")
            current = stage2
            continue
        if addr == 0xF0000000:
            print(f"stage-2 completion at request #{len(stage1) + len(stage2) + 1} (0xF0000000 len {length})")
            continue
        current.append((addr, length, flash))

    print(f"stage-1 requests: {len(stage1)}")
    print(f"stage-2 requests: {len(stage2)}")

    print("\n--- stage-1 first 12 reads ---")
    for addr, length, flash in stage1[:12]:
        print(f"  addr=0x{addr:08x} len={length}")
    print("--- stage-1 last 6 reads ---")
    for addr, length, flash in stage1[-6:]:
        print(f"  addr=0x{addr:08x} len={length}")

    # stage-2 coverage analysis
    print("\n--- stage-2 coverage ---")
    addr_counter = Counter()
    lens = Counter()
    max_addr = 0
    for addr, length, flash in stage2:
        addr_counter[addr] += 1
        lens[length] += 1
        max_addr = max(max_addr, addr)
    print(f"unique addresses: {len(addr_counter)} of {len(stage2)} requests")
    print(f"length histogram: {dict(lens)}")
    print(f"max address: 0x{max_addr:08x}")

    # derive mapping: find base such that (addr - base) is a plausible flash offset
    # flash.bin data spans payload 0x400..0x9C400; if written to flash 0x0..0x9C000,
    # then addr maps to flash (addr - 0x400). Check what addr range stage-2 covers.
    addrs = sorted({a for a, _, _ in stage2})
    print(f"address range: 0x{addrs[0]:08x} .. 0x{addrs[-1]:08x}")
    gaps = [(addrs[i], addrs[i + 1]) for i in range(len(addrs) - 1) if addrs[i + 1] - addrs[i] > 0x1000]
    print(f"gaps > 0x1000: {len(gaps)}")
    for g in gaps[:10]:
        print(f"  gap 0x{g[0]:08x} -> 0x{g[1]:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
