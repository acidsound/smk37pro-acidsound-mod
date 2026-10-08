# R03 official-v15 heap-prefix reservation audit

## Result

The official SDK `sbrk()` is now identified at `0x0205e9da` with all 80
non-relocated bytes exact. Its three relocations recover:

- `sbrk.__init_addr = 0x01c32d94`
- `HEAP_BEGIN = 0x01c46520`
- `HEAP_END = 0x01c7fd30`

This closes the previous unknown-heap-boundary blocker.

## Option A: zeroed pointer anchor

`0x01c4651c..0x01c46520` is the exact four-byte linker alignment
padding between the BSS end and 32-byte-aligned heap start. Increasing the boot
BSS-zero length from `0x0003cb48` to `0x0003cb4c` initializes
the slot to null and stops exactly at `HEAP_BEGIN`.

The slot itself is **PASS**. The complete option is **BLOCK** until a thread-safe
v15 allocation entry and producer code placement are proven.

## Option B: fixed zeroed heap prefix

Increasing BSS zeroing through `0x01c465e0` and changing the single matched
`HEAP_BEGIN` immediate to `0x01c465e0` reserves
`0x01c46520..0x01c465e0` (`0xc0` bytes). The proposed layout is:

- voice: `0x01c46520..0x01c465bc` (`0x9c`)
- valid: `0x01c465bc`
- active count: `0x01c465bd`
- generation: `0x01c465c0..0x01c465c4`
- guard: `0x01c465c4..0x01c465e0`

Static ownership is **PASS if and only if both exact patches are applied**.
The public linker establishes that the allocator begins at `HEAP_BEGIN`, and the
matched v15 `sbrk()` confirms that boundary at runtime. The reserved interval has
no absolute reference other than the old `HEAP_BEGIN` relocation.

This is not yet an R03 PASS. It reduces heap capacity by `0xc0`, conflicting
with the current “do not change allocator” requirement even though allocator ABI
and implementation are unchanged. A controlled-checkpoint exception plus heap
stress validation would be required. Producer/consumer code placement also
remains blocked.

## Provenance

- SDK commit: `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`
- SDK `mem_heap.c` SHA-256: `411cb79e74853a5b7ce9135514f59d8eafb5b098ced2f8acde08201fdfcf380c`
- official toolchain archive SHA-256: `f686586bcfb45e0f0bb27fd2b39c7a7f313cb4f0e88a66a14da621ffa8225958`
- `pi32v2/bin/clang` SHA-256: `42b94f9e11140b0fcab8f807b2872ad245b8eeca03a2d792f8706c5a3a35d34c`
- rebuilt object SHA-256: `82fb6c5a2546861c6114442f556b573da739717c5f53cfbc31853337e36e5fb6`

## Reproduce

```sh
./reproduce_mem_heap.sh SDK_ROOT PI32_CLANG mem_heap.pi32.o
python3 analyze_heap_prefix.py
shasum -a 256 -c SHA256SUMS
```
