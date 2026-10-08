# Official-v15 R03 producer/consumer layout design check

Date: 2026-08-02 UTC

Scope: exact official v15 only. No firmware was built or flashed. No device was
accessed. No v12 address, R01d boot hook, or early-boot callsite is used.

## Decision

**The destroyed stock-packer region has enough code space, and the fixed
`0xc0` reservation can be established from exact official-v15 boundaries.**
The byte-exact serialized-event design uses **158 of 278 bytes**, ending at
`0x0201e1dc` with **120 bytes free**.

The checkpoint is nevertheless **BLOCKED from build/flash** for two remaining
system-level proofs:

1. producer and consumer serialization, or an exact IRQ-save/scheduler-lock
   ABI, is not yet proven; and
2. no heap high-water evidence proves that removing `0xc0` from the allocator
   arena cannot expose a pre-existing allocation failure.

This is therefore a placement and ABI design PASS, not authorization to create
or install R03 firmware.

## Exact input gates

| artifact | SHA-256 |
| --- | --- |
| official v15 app | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| official v15 FWSC | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| Quarkslab exhaustive listing | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |

`analyze_layout.py` checks the app/package manifest bindings, every original
patch-site byte sequence, required disassembly rows, and all generated branch
and call encodings.

## 1. Exact RAM boundary proof

### Official boot zeroing

The official entry sequence contains:

```text
0x02000016  c3 ff d4 99 c0 01  mov r3,#0x01c099d4
0x0200001e  c2 ff 48 cb 03 00  mov r2,#0x0003cb48
0x02000024  a2 a2              lsr r2,r2,#2
0x02000026  02 03              rep 0x2,r2
0x02000028  b1 05              sw r1,[r3 ++= 4]
```

Therefore official BSS zeroing is exactly:

- start: `0x01c099d4`
- size: `0x0003cb48`
- end exclusive: `0x01c4651c`

### Official heap start and end

Official v15 contains a 0x62-byte `sbrk`-shape body at
`0x0205e9da..0x0205ea3c`, SHA-256
`cfbf871082dc6e52b7dd08f678dc5b4080d6cd29d4b44da4e556fd481eabbe1a`.
It differs from the pinned public AC79 SDK `sbrk` body only at the product's
relocated static pointer and boundary immediates. The relevant official-v15
instructions are:

```text
0x0205e9f8  c5 ff 20 65 c4 01  mov r5,#0x01c46520  ; HEAP_BEGIN
0x0205ea00  ca ff 30 fd c7 01  mov r10,#0x01c7fd30 ; HEAP_END
```

The complete official app contains exactly one little-endian occurrence of
each of these three control literals:

- BSS size `0x0003cb48`: one occurrence, file offset `0x20`
- heap begin `0x01c46520`: one occurrence, file offset `0x5e9fa`
- heap end `0x01c7fd30`: one occurrence, file offset `0x5ea02`

This closes the earlier heap-boundary gap. `0x01c46520` is not a guessed free
address. It is the exact lower bound from which official `sbrk` begins handing
memory to the allocator.

### Fixed `0xc0` reservation

Reserve:

```text
0x01c46520..0x01c465e0  size 0xc0
```

Required boundary changes:

| address | official bytes | proposed bytes | meaning |
| --- | --- | --- | --- |
| `0x0200001e` | `c2ff48cb0300` | `c2ff0ccc0300` | BSS size `0x3cb48 -> 0x3cc0c`, zero through `0x01c465e0` |
| `0x0205e9f8` | `c5ff2065c401` | `c5ffe065c401` | `HEAP_BEGIN 0x01c46520 -> 0x01c465e0` |

The heap end remains `0x01c7fd30`. The allocator arena changes from
`0x39810` to `0x39750` bytes, exactly `0xc0` smaller. The reserved range is
zeroed before normal startup and is below the new allocator lower bound, so it
has a constructive owner and no heap alias. This is materially stronger than
an absence-of-xrefs claim.

### State layout

| range/address | purpose |
| --- | --- |
| `0x01c46520..0x01c465bc` | 156-byte expanded voice |
| `0x01c465bc` | `valid` byte, zero at reset, one only after successful publish |
| `0x01c465bd` | saturating Ch10 active-event count |
| `0x01c465be` | generation byte, increments modulo 256 on successful publish |
| `0x01c465bf` | flags/reserved byte |
| `0x01c465c0..0x01c465e0` | reserved for locking or later checkpoint diagnostics |

The active count tracks all Ch10 Note On/Off pairs, including stock-fallback
notes before the first valid publish. This is necessary. Counting only owned
notes would allow a product packet to publish while a pre-valid stock note was
active, causing Note Off to select a different source.

## 2. Exact consumer ABI

The official dispatcher has one channel nibble in `r9` for both copy sites.
At each site:

- `r0` is the destination voice slot
- `r1 = r8 = 0x01c34c74` is the stock source
- `r2 = 0x9c`

Exact sites:

```text
Note Off
0x0201c63a  mov r2,#0x9c
0x0201c63c  mov r1,r8
0x0201c63e  80ff8ac60200  call 0x02048cce

Note On
0x0201c678  mov r2,#0x9c
0x0201c67a  mov r1,r8
0x0201c67c  80ff4cc60200  call 0x02048cce
```

The R02 live result already proved the call-to-wrapper and Ch10 branch shape on
these event paths. R03 keeps that ABI but gives Note On and Note Off separate
entries because count ordering differs:

- Note On increments before selecting/copying the source.
- Note Off copies first and decrements afterward.
- Non-Ch10 calls stock `memcpy` with the untouched stock arguments.
- Ch10 with `valid == 0` also calls stock `memcpy`.
- Ch10 with `valid != 0` substitutes only `r1 = 0x01c46520`.

Thus a pad pressed before the first accepted product packet receives a safe
stock voice, never uninitialized owned RAM.

## 3. Exact producer ABI

The two producer callsites are after official product acceptance gates:

### Direct complete packet

```text
0x0201e462  jne r0,#0xf7
0x0201e466  mov r0,r8           ; r0 = 0x01c37fd0
0x0201e468  bfea69fe            ; stock packer call
0x0201e46c  call 0x02005660     ; stock reload remains
```

### Segmented final packet

```text
0x0201e480  jne r1,#0xf7
0x0201e484  jne r5,#0x9e
0x0201e49a  mov r0,r6           ; r0 = 0x01c37fd0
0x0201e49c  bfea4ffe            ; stock packer call
0x0201e4a0  call 0x02005660     ; stock reload remains
```

The producer receives `r0 = stage`, preserves it in `r4`, and performs:

1. reject immediately if `active_count != 0`;
2. clear `valid`;
3. copy exactly `0x9c` bytes from stage to `0x01c46520`;
4. recheck `active_count` and leave invalid if it changed;
5. increment generation; and
6. set `valid = 1` last.

Malformed or partial traffic cannot reach these entries because the stock
handler retains all framing, length, and final-F7 gates. Repeated accepted
packets publish only when the active count is zero. A rejected reload leaves
the existing valid generation unchanged if rejected before copying, or leaves
`valid = 0` if a concurrent event is observed after copying.

The stock post-packer reload calls remain. Because the stock packer is gone,
the selected stock record is not updated by the accepted R03 load packet. The
post-call reload therefore restores the existing selected stock patch while
Ch10 uses the separately owned voice. This treats accepted single-voice product
SysEx as the R03 volatile load protocol, not as stock SAVE/persistence.

## 4. Explicit SAVE rejection

Neutralizing only `0x02026dac` is insufficient. The SAVE path performs its
first storage write at `0x02026da6`, before calling the stock packer:

```text
0x02026d9e  add r4,r8,0x1a14
0x02026da2  mov r2,#0xa3
0x02026da4  mov r0,r4
0x02026da6  beeaacee  call 0x02004b02  ; first persistent write
0x02026daa  mov r0,r4
0x02026dac  bfeac7b9  call 0x0201e13e  ; packed write path
```

The safe rejection point is therefore `0x02026da6`, before either write:

| address | replacement | effect |
| --- | --- | --- |
| `0x02026da6` | `04960000` | compact `goto 0x02026dd4` plus `nop` |
| `0x02026dac` | `00000000` | neutralize now-unreachable direct packer call |

`0x02026dd4` is the stock local exit path that clears `obj+0x1ec` and goes to
the common continuation. This is a no-write SAVE rejection. It is silent rather
than a new user-visible error, because no exact UI error ABI has been proven.

## 5. Exact code budget

Destroyed stock-packer region:

```text
0x0201e13e..0x0201e254 = 0x116 = 278 bytes
```

Proposed in-memory assembled layout:

| routine | range | bytes | behavior |
| --- | --- | ---: | --- |
| Note On consumer | `0x0201e13e..0x0201e16e` | 48 | Ch10 count increment, valid/source select, stock fallback |
| Note Off consumer | `0x0201e16e..0x0201e1a6` | 56 | valid/source select, copy, saturating decrement |
| post-F7 producer | `0x0201e1a6..0x0201e1dc` | 54 | active rejection, copy, generation, valid publish |
| **total** | `0x0201e13e..0x0201e1dc` | **158** | |
| **remaining** | `0x0201e1dc..0x0201e254` | **120** | available for a proven lock/IRQ-save protocol |

Routine SHA-256 values:

- Note On: `1b4838a1d3481434cce314810ed8185c625d6dbb84bf4670f7c6c5b68d0939f7`
- Note Off: `3db9747e80d4dbf2d3cdbe6319380e3f67bb4092e212189212437d590377995e`
- producer: `671977782d83d123c4ce6ec6def6cde0fe04ee13f009f1deb5f45088414ea2a0`

Exact callsite encodings for this placement:

| site | target | replacement |
| --- | --- | --- |
| `0x0201c67c` Note On | `0x0201e13e` | `80ffbc1a0000` |
| `0x0201c63e` Note Off | `0x0201e16e` | `80ff2a1b0000` |
| `0x0201e468` direct product | `0x0201e1a6` | `bfea9dfe` |
| `0x0201e49c` segmented product | `0x0201e1a6` | `bfea83fe` |

Code capacity is not a blocker. Even the unsynchronized fixed-RAM body leaves
120 bytes, enough space to add a compact synchronization protocol once its ABI
is proven.

## 6. Four-byte pointer anchor alternative

The anchor candidate is exact:

```text
BSS end exclusive  0x01c4651c
anchor              0x01c4651c..0x01c46520
official HEAP_BEGIN 0x01c46520
```

Extending BSS by four bytes would make the anchor reset to null while leaving
`HEAP_BEGIN` unchanged. A mechanical pointer-based implementation has a
208-byte lower bound and still fits the 278-byte region with 70 bytes
remaining.

It is nevertheless **rejected for R03**:

1. before allocation, one 32-bit word cannot simultaneously hold a pointer and
   a safe active-note count;
2. a pre-valid stock Ch10 note could therefore be active when the first producer
   allocates and publishes, recreating Note On/Off source mismatch;
3. lazy `malloc` entry, handler-context lock behavior, and failure handling are
   not proven to the same level as the fixed boundary;
4. the allocation consumes the same `0xc0` heap capacity at runtime but adds a
   failure path and pointer publication race; and
5. allocating from a Note event to establish the count earlier would put an
   unproven allocator call on the live audio/MIDI path.

The anchor may be useful in a later design after a safe allocation/init context
and pre-allocation count representation are proven. It is not the controlled
R03 choice.

## 7. Remaining hard blockers

### Producer/consumer interleaving

The active-count protocol is correct if product and Note dispatch are serialized.
Static v15 shows both the product handler and another wrapper can call
`0x0201c5ec`, but it does not prove that USB product handling and physical-pad
Note dispatch cannot interleave across task/interrupt contexts.

There is a final race without a lock:

1. producer performs its final `active_count == 0` check;
2. Note On increments and sees `valid == 0`, so it copies stock;
3. producer publishes `valid = 1`; and
4. Note Off later copies owned data.

The 120-byte cave margin is sufficient for synchronization, but unconditional
`cli`/`sti` is not accepted because the wrapper entry interrupt state and nested
critical-section behavior are not proven. Before build, prove one of:

- both paths execute under one serialized dispatcher/task lock;
- an exact IRQ-save/restore pair with preserved prior state; or
- an exact scheduler/mutex/spinlock ABI safe in both contexts.

### Heap high-water

Moving `HEAP_BEGIN` is semantically precise and prevents alias, but it reduces
available heap by 192 bytes. Static proof cannot show whether official v15 ever
runs within 192 bytes of allocation failure. Before build, obtain a non-device
proof from a linked map/allocator model if available, or define a later guarded
live checkpoint that measures allocator headroom without weakening rollback
requirements.

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/producer-consumer-layout/analyze_layout.py --format validation
python3 baselines/v15/analysis/r03-owned-ram/producer-consumer-layout/analyze_layout.py --format json > "$JCODE_SCRATCH_DIR/r03-layout.json"
cd baselines/v15/analysis/r03-owned-ram/producer-consumer-layout
shasum -a 256 -c SHA256SUMS
```

The script writes nothing. Checked-in `evidence.json` and `validation.txt` are
captured stdout from those two modes.
