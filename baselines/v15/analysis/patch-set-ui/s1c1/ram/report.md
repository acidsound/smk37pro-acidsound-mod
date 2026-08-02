# S1-C1 official-v15/H2 minimum owned-RAM layout

Date: 2026-08-02 UTC

Scope: official v15 static evidence and the recorded H0/H1/H2 live results only. H2 is the live parent. This work built no firmware, accessed no device, flashed nothing, and used no v12 evidence.

## Decision

- **Static two-slot placement: PASS.** Reserve exactly `0x140` bytes at `0x01c46520..0x01c46660`.
- **H2 address compatibility: PASS.** Slot 0 voice, state/valid, and lock stay at `0x01c46520`, `0x01c465bc`, and `0x01c465bd`.
- **Minimum map/state metadata: PASS.** Four bytes are sufficient and already fit in slot 0's `0x9c..0x9f` tail.
- **Existing H0/H1/H2 boundary discriminator: PASS only for the recorded H2-sized `0xa0` smoke sequence.**
- **Additional S1-C1 heap headroom: BLOCK.** Nothing recorded proves safety after removing another `0xa0` from the H2 heap.
- **S1-C1 firmware build/live selector: BLOCK** until the exact headroom gate below passes. Other code placement, parser, and note-register gates are outside this RAM-only result.

## 1. Exact inherited boundaries

Official v15:

| Item | Value |
|---|---:|
| BSS start | `0x01c099d4` |
| BSS size | `0x0003cb48` |
| BSS end exclusive | `0x01c4651c` |
| linker alignment pad | `0x01c4651c..0x01c46520`, 4 bytes |
| `HEAP_BEGIN` | `0x01c46520` |
| `HEAP_END` | `0x01c7fd30` |
| heap boundary span | `0x39810` = 235,536 bytes |

H2 changed both boundaries through `0x01c465c0`:

| Item | H2 value | Change from official |
|---|---:|---:|
| BSS size | `0x0003cbec` | `+0x0a4` |
| BSS end exclusive | `0x01c465c0` | `+0x0a4` from official BSS end |
| `HEAP_BEGIN` | `0x01c465c0` | `+0x0a0` |
| heap boundary span | `0x39770` = 235,376 bytes | `-0x0a0` |
| fixed owned range | `0x01c46520..0x01c465c0` | `0x0a0` bytes |

The BSS increase is four bytes larger than the heap loss because official v15 has four bytes of alignment padding before `HEAP_BEGIN`.

## 2. Minimum two-note immutable layout

The S1-C1 requirement is exactly two `0xa0` slots plus the smallest map/state metadata. It does not need the later 128-byte map or 16-slot header.

```text
0x01c46520..0x01c465bc  0x9c  slot 0 immutable voice, exact H2 source
0x01c465bc              1     global set_state, exact H2 valid address
0x01c465bd              1     global nonblocking producer lock, exact H2 lock
0x01c465be              1     allowlisted MIDI note selecting slot 0
0x01c465bf              1     allowlisted MIDI note selecting slot 1
0x01c465c0..0x01c4665c  0x9c  slot 1 immutable voice
0x01c4665c..0x01c46660  4     zero reserved tail, preserving slot 1 stride
```

The four metadata bytes are not an extra reservation. They exactly fill slot 0's tail:

```text
2 * 0xa0 = 0x140 total bytes
slot 0 = 0x9c voice + 4 global map/state bytes = 0xa0
slot 1 = 0x9c voice + 4 zero reserved bytes     = 0xa0
```

This is smaller than a direct 128-byte note table and is complete for exactly two allowlisted notes. Two byte comparisons encode the whole map. A slot index, count, generation, checksum field, or per-slot valid byte is not required for the first immutable, all-or-none selector.

### Publication rule

1. Boot zero leaves `set_state == 0`, so both consumers use H2/stock fallback.
2. The producer takes the existing nonblocking lock at `0x01c465bd`.
3. It rejects notes above 127 and rejects equal note values.
4. While state remains zero, it copies both complete `0x9c` payloads and writes both note bytes.
5. It executes `csync`, then writes `set_state = 1` at `0x01c465bc` last.
6. Once state is one, every mutation is rejected until reboot.
7. Consumers never lock. They select slot 0 or slot 1 only when state is exactly one, otherwise they preserve H2 fallback.

Using `0x01c465bc` as the global armed state retains H2's valid-last contract. It also avoids exposing one valid slot while the other slot or map is incomplete.

## 3. Exact BSS and heap arithmetic

Two strides from the live H2 base end at:

```text
0x01c46520 + 2 * 0x000000a0
= 0x01c46520 + 0x00000140
= 0x01c46660
```

New BSS size:

```text
0x01c46660 - 0x01c099d4 = 0x0003cc8c
```

Changes from official v15:

```text
BSS:  0x0003cc8c - 0x0003cb48 = +0x00000144
heap: 0x01c46660 - 0x01c46520 = -0x00000140 capacity
```

Changes from H2:

```text
BSS:  0x0003cc8c - 0x0003cbec = +0x000000a0
heap: 0x01c46660 - 0x01c465c0 = -0x000000a0 capacity
```

Remaining heap boundary span:

```text
0x01c7fd30 - 0x01c46660 = 0x000396d0 = 235,216 bytes
```

Exact immediate changes, derived only and not applied:

| Address | Official v15 | H2 | S1-C1 two-slot value |
|---|---|---|---|
| `0x0200001e` BSS size | `c2ff48cb0300` | `c2ffeccb0300` | `c2ff8ccc0300` |
| `0x0205e9f8` `HEAP_BEGIN` | `c5ff2065c401` | `c5ffc065c401` | `c5ff6066c401` |

`HEAP_END` remains `0x01c7fd30`. The two changes must remain paired. Extending BSS without moving `HEAP_BEGIN`, or moving `HEAP_BEGIN` without zeroing the complete owned range, is a hard BLOCK.

## 4. What H0/H1/H2 do and do not discriminate

### Defensible narrow result

H0 is a valid narrow boundary discriminator for the existing H2-sized reservation because it changed only the official BSS and `HEAP_BEGIN` immediates to reserve `0xa0`, then passed the recorded first-stock-Pad smoke test.

H1 and H2 add useful orthogonal evidence at that same boundary:

- H1 passed accepted-packet producer execution and a `0x9c` write/publication while consumers stayed elsewhere.
- H2 passed live slot-0 consumption at `0x01c46520`, produced the intended named sound, released normally, and did not reboot.

Together they defend the one-slot H2 construction against the specific immediate reboot previously attributed to R03.

### Why they are not an S1-C1 headroom discriminator

All three artifacts use the same `HEAP_BEGIN = 0x01c465c0`. None varies the boundary to `0x01c46660`, records maximum current break, inventories all successful/failed allocations, or stresses the second slot. H1 and H2 therefore cannot add evidence about the extra `0xa0` capacity loss.

The correct conclusion is:

- **PASS:** the existing `0xa0` H2 boundary survived its recorded smoke sequences.
- **BLOCK:** the additional `0xa0` needed for the two-slot boundary has no allocator-headroom proof.

A no-reboot observation is not a heap high-water measurement.

## 5. Required offline/live headroom gate

The matched official-v15 `sbrk` rejects a positive increment whose resulting endpoint is **at or beyond** `HEAP_END`. Let `Bmax` be the greatest H2 current-break endpoint reached by any successful positive `sbrk` increment in the admitted workload.

The exact mathematical admission condition for shifting H2 by another `0xa0` is:

```text
Bmax + 0x000000a0 < 0x01c7fd30
```

Equality does not pass.

### Offline PASS gate

PASS only if an exact H2 allocation trace or a complete allocator/allocation-lifetime model:

1. covers the admitted worst-case nonpersistent S1-C1 workload;
2. records or derives every positive `sbrk` request, endpoint, and success/failure result;
3. replays the same sequence with the initial break advanced by `0xa0`;
4. proves every H2-successful request remains successful in the same order;
5. proves the strict `Bmax + 0xa0 < HEAP_END` inequality;
6. accounts for allocator alignment, headers, fragmentation, concurrent task stacks, and failure handling.

A linker span, total free-byte count, absence of decoded xrefs, H0/H1/H2 no-reboot record, or one idle snapshot does not pass this gate.

Current status: **BLOCK.** No such max-break trace or complete model exists in the reviewed evidence.

### Paired live gate if offline proof remains incomplete

Before the selector itself, run a separate boundary-only discriminator with identical fixed, nonallocating telemetry in both arms:

- baseline: exact H2 boundary and H2 behavior;
- test arm: change only BSS size `0x3cbec -> 0x3cc8c` and `HEAP_BEGIN 0x01c465c0 -> 0x01c46660`;
- do not read or write slot 1 and do not add selector behavior.

Replay one deterministic workload covering boot/idle soak, USB reconnect, accepted and rejected packets, Ch1 controls, repeated and overlapping Ch10 Note On/Off, reversed release order, CC64, all-notes-off, and every nonpersistent S1-C1 guard path.

PASS requires all of the following:

1. identical successful allocation/`sbrk` result sequences in both arms;
2. no new failed allocation, null return, reboot, hang, audio guard failure, or reconnect failure;
3. measured H2 `Bmax + 0xa0 < 0x01c7fd30`;
4. strictly positive measured headroom at the boundary-only arm's worst point.

Any difference is **BLOCK/STOP**. Only after this boundary-only gate passes may the two-slot selector combine the already-reviewed RAM boundary with note selection.

## 6. Gate table

| Gate | Result | Exact reason |
|---|---|---|
| two `0xa0` slot placement | **PASS** | `0x01c46520..0x01c46660`, size `0x140`; arithmetic closes |
| constructive ownership | **PASS if paired changes are applied** | BSS zero ends exactly at new `HEAP_BEGIN`; allocator cannot return the prefix |
| H2 slot-0 compatibility | **PASS** | voice/state/lock addresses unchanged |
| smallest two-note map/state | **PASS** | state + lock + two note bytes = 4 bytes in slot-0 tail |
| H0/H1/H2 immediate smoke discriminator | **PASS_NARROW** | supports only the existing H2 `0xa0` boundary and recorded sequences |
| extra `0xa0` allocator headroom | **BLOCK** | no `Bmax`, exact replay, or complete allocation model |
| S1-C1 selector build/live admission | **BLOCK** | required offline/paired-live headroom gate has not passed |

## Reproduce

From the repository root:

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c1/ram/validate.py
cd baselines/v15/analysis/patch-set-ui/s1c1/ram
shasum -a 256 -c SHA256SUMS
```

The validator is read-only. It hashes exact inputs, checks official and H2 instruction bytes, recomputes every boundary, validates the embedded minimum metadata, and asserts the PASS/BLOCK conclusions.
