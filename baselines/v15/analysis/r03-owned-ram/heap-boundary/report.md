# R03 heap-boundary RAM ownership audit for official v15

Scope: exact official v15 app only. This audit performs no patching, flashing,
device access, or v12-derived reasoning. The public AC79 SDK is used only through
pinned local signature evidence to calibrate ABI/FreeRTOS shapes and SoC facts,
then every claim is checked against v15-internal bytes/listings.

## Verdict

**BLOCK.** A fixed `0xa4` RAM region is **not proven ownable** by shrinking or
relocating a heap, or by extending a proven allocation, with no alias.

The reason is not that RAM is too small. The exact boot image clearly zeros a
large BSS span and initializes stacks inside it, and the app contains a
malloc-like entry plus FreeRTOS list/task infrastructure. The blocker is that the
v15-internal evidence recovered here does **not** prove an allocator arena
start/end, every dynamic stack/task/heap consumer, or a bounded allocation whose
lifetime and alias exclusions reserve `0xa4` bytes for R03. Under Gate A, a
zeroed gap or absence of decoded xrefs remains a hard BLOCK.

## Exact boot memory evidence

| item | value |
| --- | --- |
| data copy source | `0x0208d160` |
| data copy destination | `0x01c00000..0x01c099d4` |
| data copy size | `0x000099d4` |
| BSS zero start | `0x01c099d4` |
| BSS zero end exclusive | `0x01c4651c` |
| BSS zero size | `0x0003cb48` |

Boot stack/register initializers:

| address | register | value | inside zeroed BSS |
| --- | --- | --- | --- |
| `0x02000004` | `sp` | `0x01c3a2d4` | True |
| `0x0200000a` | `ssp` | `0x01c3b2d4` | True |
| `0x02000098` | `usp` | `0x01c3b5d4` | True |
| `0x0200009e` | `sp` | `0x01c3c5d4` | True |

Important consequence: the zeroed span is not free RAM. It contains stock globals
and stack pointers. Any proposed fixed `0xa4` destination inside or adjacent to
this span needs an owner/lifetime proof, not just zero-on-boot behavior.

## Task/RTOS and allocator ABI evidence

Pinned SDK evidence establishes the pi32v2 scalar ABI model used for calibration:
`r0..r3` carry the first four scalar/pointer arguments and `r0` carries return.
The same SDK report has exact FreeRTOS list/task infrastructure matches inside
v15 near the allocator region:

| SDK symbol | v15 address | size | body sha256 |
| --- | ---: | ---: | --- |
| `prvSearchForNameWithinSingleList` | `0x02060f86` | 80 | `09e6a28ffaf3312b17651ca47fae18cd410c1cd1f902b138480a99f7e0344da2` |
| `vListInsertEnd` | `0x02061050` | 22 | `a6638b9ae8badf619a75091f3949b8d60662ad2f0bfb09fc4ef8d4f7e71a21c9` |
| `vListInsert` | `0x02061ac0` | 42 | `ae3324358c901b50e4e88da120be60f419d17d059f758ecf09643e92c63c965f` |
| `vListInitialise` | `0x02061e68` | 18 | `52363e08dd2e7299ab7000725d7d2751c4bacaa0b797c7bc3127436edd665747` |

Decoded v15 call inventory for key targets:

| target | address | decoded call count | first callsites |
| --- | ---: | ---: | --- |
| `heap_init_candidate` | `0x02060e2c` | 1 | `0x02000084` |
| `malloc_like_candidate` | `0x02060ed4` | 57 | `0x02000324, 0x02000340, 0x02001f74, 0x02003b9a, 0x02003d24, 0x02003d90, 0x02004a48, 0x02007390` |
| `free_like_candidate` | `0x0205fc2e` | 98 | `0x02004426, 0x02004786, 0x02009fa6, 0x0201e0b4, 0x0201e136, 0x0201f3f4, 0x0201f83e, 0x0201fb4a` |
| `memcpy_like_candidate` | `0x02048cce` | 146 | `0x02000060, 0x02000546, 0x02000556, 0x02000568, 0x020007b6, 0x02000e8a, 0x02000eb8, 0x02000ee2` |

`0x02060e2c` is called once during boot after BSS zero/data copy. `0x02060ed4`
has many decoded callsites and is treated here as the malloc-like entry for ABI
risk analysis. `0x0205fc2e` has a deallocation-like call pattern. These names are
calibrated, not promoted into a complete allocator proof: the required heap arena
bounds are not recovered.

## Heap-boundary decision matrix

| question | decision | evidence | blocker |
| --- | --- | --- | --- |
| Exact boot BSS zeroing known? | PASS | boot rows show `0x01c099d4` zeroed for `0x3cb48` bytes | none |
| Stack initialization known? | PASS | `sp=0x01c3a2d4`, `ssp=0x01c3b2d4`, later `usp=0x01c3b5d4`, `sp=0x01c3c5d4` | margins and later task stacks not bounded |
| Task/RTOS presence known? | PASS/PARTIAL | exact SDK FreeRTOS list anchors in v15 | no complete task/stack allocation inventory |
| Allocator ABI known enough for call risk? | PARTIAL | SDK ABI calibration plus many v15 callsites to malloc/free-like targets | allocator body is not fully decoded into arena map here |
| Heap arena start/end proven? | BLOCK | only allocator globals/calls and boot init bytes were recovered | no exact v15-internal arena low/high, high-water, or linker map |
| Shrink/relocate heap to own `0xa4`? | BLOCK | no arena bounds or all-consumer stack/heap inventory | cannot prove no alias after shrink/relocation |
| Extend a proven allocation by `0xa4`? | BLOCK | no bounded official allocation with owner/lifetime and spare tail was found | cannot prove object size, lifetime, and all aliases |
| Use zeroed BSS gap as fixed `0xa4`? | BLOCK | boot zeroing is initialization only | Gate A forbids absence-only claims |

## PASS/BLOCK answer

**BLOCK.** Do not claim R03-owned RAM from heap shrinkage, heap relocation, or an
extended allocation based on current official-v15 evidence. A future PASS would
need at minimum:

1. exact v15 allocator arena start/end and metadata format;
2. complete task stack creation/static stack inventory and stack bounds;
3. complete heap allocation consumer inventory or a linked allocation map;
4. a concrete `0xa4` range with owner, lifetime, valid/generation metadata, and
   DMA/stack/heap/task/USB/UI/audio/storage no-alias proof;
5. independent verification that the proposed change does not alter stock
   allocator ABI or claimed polyphony.

## Validation

| check | status | detail |
| --- | --- | --- |
| `official-v15-app-sha256` | PASS | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `manifest-app-binding` | PASS | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `bss-end-arithmetic` | PASS | `0x01c4651c` |
| `data-copy-end-arithmetic` | PASS | `0x01c099d4` |
| `boot-stack-pointers-inside-zeroed-bss` | PASS | `[{'address': '0x02000004', 'register': 'sp', 'value': '0x01c3a2d4', 'inside_zeroed_bss': True}, {'address': '0x0200000a', 'register': 'ssp', 'value': '0x01c3b2d4', 'inside_zeroed_bss': True}, {'address': '0x02000098', 'register': 'usp', 'value': '0x01c3b5d4', 'inside_zeroed_bss': True}, {'address': '0x0200009e', 'register': 'sp', 'value': '0x01c3c5d4', 'inside_zeroed_bss': True}]` |
| `single-heap-init-candidate-call` | PASS | `{'target': '0x02060e2c', 'count_in_decoded_listing': 1, 'first_20_callsite_addresses': ['0x02000084'], 'functions_first_20': ['-']}` |
| `malloc-like-calls-present` | PASS | `57` |
| `freertos-sdk-exact-anchors-present` | PASS | `4` |
| `fixed-region-size` | PASS | `0x000000a4` |
| `voice-plus-metadata-budget` | PASS | `voice=0x0000009c total=0x000000a4` |
| `heap-bounds-proven` | BLOCK | `No v15-internal exact arena start/end and no no-alias proof were recovered` |
| `decision-is-block` | PASS | `BLOCK` |

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/heap-boundary/analyze_heap_boundary.py
cd baselines/v15/analysis/r03-owned-ram/heap-boundary
shasum -a 256 -c SHA256SUMS
```

Generated files:

- `analyze_heap_boundary.py`
- `evidence.json`
- `boot-rows.tsv`
- `allocator-calls.tsv`
- `validation.txt`
- `report.md`
- `SHA256SUMS`
