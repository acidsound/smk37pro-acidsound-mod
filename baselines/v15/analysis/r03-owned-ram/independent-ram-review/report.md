# Independent official-v15 R03 RAM ownership review

Date: 2026-08-02 UTC

Scope: exact official v15 only. This review reads the R03 requirements, prior R03 analyses, the pinned official-SDK `mem_heap.c` object, and the official v15 app. It does not patch firmware, flash, or access the device. No v12 assumption is used.

## Decision

| question | decision | reason |
| --- | --- | --- |
| Option A four-byte pointer anchor | **PASS** | Extending the boot zero by four bytes converts exact linker padding `0x01c4651c..0x01c46520` into a null pointer slot and stops at the proven heap start. |
| Option A as a complete R03 owned-RAM candidate | **BLOCK** | The slot is only an anchor. No exact thread-safe v15 allocator entry, returned object, allocation-failure path, never-free lifetime, or producer placement is proven. |
| Option B static Gate A ownership | **PASS only with both exact patches** | Zeroing through `0x01c465e0` and moving `HEAP_BEGIN` to `0x01c465e0` creates a fixed, boot-zeroed `0xc0` range that the matched `sbrk()` cannot allocate. |
| Option B under the current unmodified R03 requirements | **BLOCK** | Gate C says R03 must not change the allocator. Moving its lower bound changes arena capacity by `0xc0`, even though the implementation, ABI, end address, and claimed polyphony can remain unchanged. |
| Controlled checkpoint exception for Option B | **JUSTIFIABLE, narrowly** | It may authorize offline implementation and further review. It does not make R03 PASS or authorize flashing until heap-headroom, accounting, code-placement, and all remaining gates pass. |
| R03 overall now | **BLOCK** | Producer/consumer executable placement and exact ABI remain blocked independently of the RAM decision. |

## Revalidated evidence

- Official app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Pinned `mem_heap.pi32.o` SHA-256: `82fb6c5a2546861c6114442f556b573da739717c5f53cfbc31853337e36e5fb6`.
- `sbrk()` is `0x62` bytes at `0x0205e9da`. All 80 bytes outside its three relocated six-byte instructions are exact. Only the twelve relocation payload bytes differ.
- Recovered relocations are `sbrk.__init_addr=0x01c32d94`, `HEAP_BEGIN=0x01c46520`, and `HEAP_END=0x01c7fd30`.
- Boot zeros `0x01c099d4..0x01c4651c` with a word-granular loop. The four bytes through `0x01c46520` are exact linker alignment padding before the 32-byte-aligned heap.
- Original heap span is `0x39810` bytes. Option B span is `0x39750`; loss is exactly `0xc0` bytes, 192 bytes or about `0.081516%` of the original span. The exact `sbrk()` rejects a positive increment ending at or beyond `HEAP_END`, so these are boundary spans, not a claim that every byte is allocatable payload.
- Option B changes the boot zero size from `0x3cb48` to `0x3cc0c`. That is a `0xc4` zeroing extension: four padding bytes plus the `0xc0` former heap prefix. Heap loss remains exactly `0xc0`.

The scan finding no other literal reference into the prefix is supporting evidence only. Option B does not rely on absence of xrefs for ownership. Ownership comes from the paired boot-zero and allocator-boundary construction.

## Option A: exact risks

The pointer slot itself has exact address, alignment, boot initialization, and session lifetime. It is not the voice destination required by Gate A.

The complete option remains blocked until all of these are exact for v15:

1. a thread-safe allocation entry and scalar ABI;
2. a successful bounded allocation of at least `0xa4` bytes, with null/failure handling;
3. one-time publication of the returned pointer and proof it is never freed or replaced while referenced;
4. initialization of the allocation before any Note path can read it;
5. `valid`, `generation`, and active-note behavior, including a concurrency primitive around publish/read;
6. executable placement for allocation and producer/consumer logic.

A checkpoint exception is **not justified** for Option A. The blocker is missing executable and allocator proof, not an intentionally bounded policy tradeoff. Waiving it would substitute an SDK resemblance or guessed entry for exact v15 evidence.

## Option B: ownership and risks

A defensible layout within `0x01c46520..0x01c465e0` is:

- voice `0x01c46520..0x01c465bc` (`0x9c` bytes);
- `valid` at `0x01c465bc`;
- active count at `0x01c465bd`;
- alignment padding `0x01c465be..0x01c465c0`;
- generation `0x01c465c0..0x01c465c4`;
- guard/reserved `0x01c465c4..0x01c465e0`.

Boot zeroing gives `valid=0`, active count `0`, and generation `0`. The eventual producer must reject reload while active count is nonzero, keep `valid=0` during the copy, copy exactly `0x9c`, publish generation and validity only after completion, and make Note On/Off use the same published generation.

Exact residual risks are:

1. **Heap exhaustion:** no official-v15 worst-case high-water evidence proves that losing 192 bytes is harmless. The small percentage is not a safety proof.
2. **Paired-patch dependency:** the `HEAP_BEGIN` relocation and boot zero length must be exact-gated and changed together. The new word count is valid because `0x3cc0c` is divisible by four.
3. **Capacity/statistics accounting:** only `sbrk()` is exact in the supplied object match. The SDK source also has `MALLOC_SIZE` users such as free-space/statistics paths, but their v15 bodies and resolved value are not exact here. Any such v15 consumer must be recovered and either shown consistent or patched deliberately.
4. **Non-literal access:** the literal scan is not a complete computed-address proof. The structural heap-boundary reservation is the primary no-alias argument; any separately recovered DMA or fixed-arena path into this range would invalidate the PASS.
5. **Publication concurrency:** fixed RAM does not itself prove atomic producer/consumer behavior. Exact code and locking/interrupt semantics remain required.
6. **Overall code placement:** prior copy-path and app-tail reviews still block the required wrapper and consumer bodies.

## Controlled checkpoint exception

A controlled exception is justified only with this wording and boundary:

> For exact official v15 only, permit Option B to move the `sbrk()` lower boundary from `0x01c46520` to `0x01c465e0`, reserving exactly `0xc0` bytes, while leaving allocator code, ABI, `HEAP_END`, and claimed polyphony unchanged. This exception authorizes offline construction and validation only. It expires if any address, size, allocator body, or target app hash changes.

Before it can support a Flash candidate, require:

- exact two-patch manifest and deterministic validator;
- recovery of all v15 heap-capacity/statistics consumers, including any `MALLOC_SIZE` equivalent;
- static proof that no other arena or direct/computed owner uses the prefix;
- worst-case heap high-water and allocation-failure testing across boot, UI changes, USB/product SysEx, storage, and audio/overlap stress;
- exact producer/consumer placement and ABI review;
- the existing Gate D independent reviews, rollback, uploader rejection tests, and later Gate E live sequence.

Thus the exception is reasonable as a checkpoint-management decision because the tradeoff is exact and bounded. It is not reasonable as a waiver of evidence or as a present R03 PASS.

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/independent-ram-review/analyze_independent_ram_review.py
cd baselines/v15/analysis/r03-owned-ram/independent-ram-review
shasum -a 256 -c SHA256SUMS
```

Optional source provenance check after obtaining pinned SDK commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`:

```sh
python3 analyze_independent_ram_review.py \
  --sdk-mem-heap /absolute/path/to/apps/common/system/mem_heap.c
```
