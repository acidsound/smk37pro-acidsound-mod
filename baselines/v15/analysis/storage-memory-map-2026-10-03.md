# Memory map — storage persistence tier (v15)

> Part of the map family. Integrates into `ADDRESS-SPACE-MAP-2026-10-02.md`
> (§7 storage, §5 RAM0) and closes the P0-4 question left open by
> `persistence-s3/bulk-path-2026-10-03.md`.
>
> Date: 2026-10-03 · **offline static analysis, no device contact.**
> Every address here is reproducible from the committed tooling.

## 0. What this adds

The 2026-10-02 map left three gaps. This closes the first and bounds the second:

| gap | status |
|---|---|
| §7 "STORAGE base itself is not fixed in this document" | **closed** — 6 pointer fields in `g`, all set in-app (§1) |
| §3.3 "layout closes at +0x9209" | **refuted as a global claim** — a proven write reaches `+0x0FF000` (§3) |
| §4.4 listing coverage 58.2% | **unchanged**, and now explicitly the limiter on every claim (§5) |

New in this pass, beyond closing the gap above:

- a 256-slot x 4 KiB persistent allocator spanning exactly the 1 MiB user
  partition (§3.1), whose slot index is a field of an existing record word (§3.2)
- **the S1C producer calls the record writer directly** — a call-level link,
  not merely a shared address (§3.3)
- `0x01C37FD0` identified as SysEx **staging**, which explains why the 4 KiB
  slot has no reader of that length (§3.3)
- `0x02005660` is the same function at the same address in v15 and v16, with
  uniform `+0x40/+0x48` field shifts (§3.4)
- the record index formula traced to the instruction and **confirmed** — the
  record array closes at `+0x9180` exactly, matching the flag and selection
  offsets byte for byte (§2.3)
- **the slot lifecycle traced end to end** (§3.4-§3.6): SysEx receive, 4 KiB
  checksum gate, descriptor write, S1C pack, record write, and a read-back that
  searches a 4-entry table and feeds a string formatter
- `g+0x1714` reclassified from "index byte" to a **record descriptor**, with
  all 6 referencing instructions accounted for (§3.5)
- a correction: handoff §8.1's "text setter `0x0201A6A0`" is **not an
  instruction boundary**; the real function is `FUN_0201A67C`, a string
  builder, not an LCD write (§3.5)
- **`--xref` was broken repo-wide and returned nothing for every query**
  (§3.7). Fixed; the write-wrapper census now reconciles against handoff §4.1
  and reveals **4 uncatalogued write sites** (§2.1a). Any earlier statement of
  the form "xref 0" in this project was produced by a broken tool and needs
  re-running.
- handoff §7-3 refuted: `FUN_02024E8C` has **6 callers**, all in-window (§3.7)
- **handoff §8.1's "dispatcher not found" resolved**: a **73-command-ID dispatch
  table**; `ID 0x19E -> 0x02058300` (§3.8)
- **the 11-entry callback vector itself decoded** (§3.9): 2 nulls + **10 code
  pointers** (slots 2..12, exactly as handoff §8.1 said), including a
  one-line `g[0x1672]=0` setter, a string-append pair
  (`0x020299CE` + clamp `0x020299F2`), and **entry 11 = the §2.1 bulk window
  accessor**, same base and stride, so that window has two entry points
- **`0x02005152` read: a 12-column field renderer**, 4 callers, two of which
  index **`g+0x16BC` by row** (§3.9) — the nearest artefact to the glass so far
- **`0x02005888` read: display-panel init** — `0x40` / `0x100` / `0x100` into
  three registers after a 1025-word fill, and it owns the unexplained
  `0x01C38FD0` overlap (§3.9)
- **an address overlap recorded, not resolved**: `0x01C38FD0` is both the end of
  the SysEx slot window and the display-init table destination (§3.9)
- a warning about `smk37_g_fields.py --field`: its hits are **not** proof of a
  `g` access; 7 hits for `0x418` were a different structure's offsets (§3.9)
- **handoff §8.1's renderer gap is now one hop from closed**: string pool →
  append → `g+0x418`; only the LCD MMIO write remains

New tool: `tools/smk37_persist_map.py` — resolves all 69 storage-ABI call
sites into (RAM range, storage base provenance, length) and emits the access
map of the `g` object at `0x01C33260`. `--selftest` pins 5 known answers.

## 1. Storage base fields — **확정** (closes the §7 gap)

There is not one storage base. `g = 0x01C33260` holds **six** pointer fields,
each written in-app:

| field | VA | set at | set from | role |
|---|---|---|---|---|
| `g+0x0000` | `0x01C33260` | `0x0201D1BE` | `*(g+0x1a8)` | data-buffer pointer; bulk base |
| `g+0x0160` | `0x01C333C0` | `0x02005EEE` | `0x0200464E` | **record write view** (§3) |
| `g+0x0164` | `0x01C333C4` | `0x02005EF2` | `0x0200463A` | **record read/map pointer** |
| `g+0x01D0` | `0x01C33430` | `0x02004F16` | literal `0x3CB60844` | boot const (not a pointer) |
| `g+0x01D4` | `0x01C33434` | `0x02004F7E` | `0x0200464E` | alt record base (len 0x224) |
| `g+0x0200` | `0x01C33460` | `0x02006148` | boot file handle | **alt storage base** (len 0x49E3) |
| `g+0x020C` | `0x01C3346C` | `0x02006144` | boot file handle | alt storage base (len 0x86) |

Evidence: `tools/smk37_g_fields.py --field 0x160|0x164|0x1d4|0x200|0x20c`.
Each shows exactly one 32-bit store, in the boot producer region
`0x02004F00..0x02006200`, plus readers.

**This is why the 2026-10-02 §3.3 "+0x9209 closes the layout" could not be
reconciled with the bulk path: they are different fields.**

## 2. Storage writes by provenance — what actually reaches flash

`tools/smk37_persist_map.py --table`, grouped by resolved storage base:

| storage base (provenance) | sites | lengths | meaning |
|---|--:|---|---|
| `mem[g+0x160] + 0x9180` | 3 | `0x80` | flag table (128 B) — **write + restore** |
| `mem[g+0x160] + 0x9200` | 2 | `0x9` | selection (9 B) — **write + restore** |
| `mem[g+0x160] + (idx<<12)` | 1 | `0x1000` | **256-slot 4 KiB allocator, §3** |
| `mem[g+0x1d4]` | 5 | `0x224`, `0x8` | alternate record base |
| `mem[g+0x200] + 0x0` | 1 | `0x49E3` | 18,915 B bulk |
| `mem[g+0x200] + 0x27FF8` | 2 | `0x8` | 8 B tag |
| `mem[g+0x20C]` | 3 | `0x86` | 134 B block |
| `mem[g+0x0] + 0x27FF8` | 1 | `0x8` | 8 B tag |
| `mem[g+0x0] + {0, 0x5000, …, 0x23000}` | 15 | `0x49E3` | **bulk window, write+read symmetric (§2.1)** |
| unresolved | 31 | 4 … `0xA3` | settings table is register-indexed (§5.6) |

### 2.1 The bulk window — write and read are provably symmetric

After fixing the `_lw` load prefix (see §5.6), 15 of the 16 bulk sites resolve:

```
write  0x020064ba  RAM 0x01c0de20  ->  mem[g+0x0] + 0x00000   len 0x49E3
write  0x020064c8  RAM 0x01c12803  ->  mem[g+0x0] + 0x05000
write  0x020064dc  RAM 0x01c171e6  ->  mem[g+0x0] + 0x0a000
write  0x020064f0  RAM 0x01c1bbc9  ->  mem[g+0x0] + 0x0f000
write  0x02006504  RAM 0x01c205ac  ->  mem[g+0x0] + 0x14000
write  0x02006518  RAM 0x01c24f8f  ->  mem[g+0x0] + 0x19000
write  0x0200652c  RAM 0x01c29972  ->  mem[g+0x0] + 0x1e000
write  0x02006540  RAM 0x01c2e355  ->  mem[g+0x0] + 0x23000

read   0x0200656c  RAM 0x01c0de20  <-  mem[g+0x0] + 0x00000   len 0x49E3
read   0x0200657a  RAM 0x01c12803  <-  mem[g+0x0] + 0x05000
read   0x0200658e  RAM 0x01c171e6  <-  mem[g+0x0] + 0x0a000
read   0x020065a2  RAM 0x01c1bbc9  <-  mem[g+0x0] + 0x0f000
read   0x020065b6  RAM 0x01c205ac  <-  mem[g+0x0] + 0x14000
read   0x020065ca  RAM 0x01c24f8f  <-  mem[g+0x0] + 0x19000
read   0x020065de  RAM 0x01c29972  <-  mem[g+0x0] + 0x1e000
read   0x020065f2  RAM 0x01c2e355  <-  mem[g+0x0] + 0x23000
```

Identical RAM window, identical 8 storage offsets, identical length, opposite
direction. **The save/restore pair for this window is now proven symmetric from
the listing.**

The RAM window is contiguous and exact:

```
0x01C0DE20 .. 0x01C32D38   =  8 x 0x49E3 = 0x24F18 = 151,320 B
```

which is what `persistence-s3/bulk-path-2026-10-03.md` measured by hand and
could not confirm the base of. It is `*(g+0x0)`.

The 8 storage offsets have stride `0x5000` against a payload of `0x49E3`, so
each slot wastes `0x61D` (1,565 B). That slack is a flash-block artefact, not
addressable space — do not plan on it.

Two of the sixteen remain unresolved: the first read (`0x0200656C`) and
`0x02024E5C` (a different function, base `mem[g+0x200]`, r0 unknown). The first
is the entry of the read sequence and most likely resolves once the preceding
branch is modelled.

### 2.1a Four write sites the handoff inventory missed

With `--xref` working, the v15 write-wrapper census reconciles exactly against
handoff §4.1:

```
handoff 4.1 write sites : 32
tool finds              : 36
handoff-only (missed)   : 0
tool-only (new)         : 4  ->  0x02037726 0x0203776C 0x02037AC6 0x02037ADA
read wrapper            : 30  (exact match, no change)
```

The handoff's 32 are all present; nothing it listed was wrong. Four more exist:

```
02037726  mov  r2,#0x4 ; call write        (source sp+0x18)
0203776c  mov  r2,#0x4 ; call write        (source sp+0x18)
02037ac6  mov  r2,#0x4 ; call write        (source sp+0x0)
02037ada  movz r0,#0xcef ; lw r0,[r8+r0<<2] ; add r1,r0,#0x4 ; mov r2,r4 ; call write
```

Three are `len=0x4`. The fourth reads `mem[0xCEF]` — **the same
register-indexed settings table** as §2.2, whose cluster was previously
attributed to `FUN_0202C6AC` and friends. So that cluster also reaches
`FUN_02037ADA`, in a different function, via the same `0xCEF` word.

The census is therefore **36 write / 30 read** in v15, and handoff §4.1's
"WRITE 32" undercounts by 4. Its "READ 30" is exact.

### 2.2 The `len=0x4` settings cluster is register-indexed

Ten sites write or read exactly 4 bytes, all inside `FUN_0202C616` /
`FUN_0202C6AC` / `FUN_0202CDF2` / `FUN_020378EA` and their neighbours — the
"R/W settings cluster" of handoff §4.2. Their storage address is
**runtime-selected**:

```
0202c6b0  movz r0,#0x33c2
0202c6ba  lb.z  r0,[r15 + r0]        ; r15 = g ; index by a g byte
0202c6c8  mul   r0,r0,#0xc
0202c6cc  add   r0,r15               ; r0 = g + slot*0xC
0202c6dc  lw    r1,[r0+r5]           ; storage address read from a table
0202c7e2  mov   r2,#0x4
0202c7e6  call  0x02004b02
```

So these are a **read-modify-write on table-selected settings slots**, not a
fixed region. Which 4-byte slot is touched depends on a `g` byte and a table
word. This is consistent with handoff §4.2's read+write classification and
adds the mechanism: the table at `r0+r5` supplies the storage address.

Not resolvable statically without the table's contents, which live in RAM.

### 2.3 The record index formula — traced, and **confirmed**

I set out to refute handoff §3.3 here and did not. It holds. The trace is
worth recording anyway, because the first two readings of it were both wrong
and the third only came out by computing.

handoff §3.3 states:

```
index = bank*32 + preset      (0<=bank<=3, 0<=preset<=31)
```

The official SAVE at `0x02026D6C` computes it as:

```
02026d80  add   r5,r8,#0x3a0        ; r5 = g+0x3A0  (selection block)
02026d84  lb.z  r0,[r5 + 0x4]       ; r0 = bank
02026d86  lb.z  r1,[r0 + r5]        ; r1 = preset, read at g+0x3A0+bank
02026d8a  lsl   r0,r0,0x5           ; r0 = bank << 5      <-- r0 here is bank
02026d8c  ldw   r2,r8,#0x160        ; r2 = *(g+0x160)
02026d90  add   r0,r1               ; r0 = (bank<<5) + preset
02026d92  uxtb  r0,r0               ; keep low 8 bits
02026d94  mul   r0,r0,#0xa3         ; record index
02026d98  add   r0,r2               ; + storage base
02026d9a  add   r1,r0,0x4000        ; + raw record area
02026d9e  add   r4,r8,0x1a14        ; source = g+0x1A14
02026da2  mov   r2,#0xa3
02026da6  call  0x02004b02
```

So the byte-level formula is

```
index      = ((bank << 5) + preset) & 0xFF
storage    = *(g+0x160) + 0x4000 + index * 0xA3
source     = g + 0x1A14
length     = 0xA3
```

For bank in 0..3 the term `bank << 5` contributes exactly `0, 32, 64, 96`, which
matches the handoff's `bank*32`. **So the handoff's multiplier is right and the
two documents do not actually disagree on that term.**

What the handoff does not carry is the `uxtb` — the truncation to 8 bits:

```
index_raw = (bank<<5) + preset          0..127   (no truncation)
index     = index_raw & 0xFF            0..127   -> never wraps
```

and then `* 0xA3`. With bank 0..3 and preset 0..31 the sum is at most 127, so
**the `uxtb` never truncates and all 128 combinations stay distinct.** My
earlier reading took `r0` at `0x02026D8A` to be the preset; it is the **bank**,
and the preset enters only at `0x02026D90`. Re-derived correctly:

```
for bank 0..3, preset 0..31:  distinct indices = 128, collisions = 0
```

**handoff §3.3's formula is confirmed, not refuted.** The record-index model
stands.

| bank | preset | index | storage offset |
|---:|---:|---:|---:|
| 0 | 0 | 0 | `+0x4000` |
| 0 | 1 | 1 | `+0x40A3` |
| 1 | 0 | 32 | `+0x5460` |
| 3 | 31 | 127 | `+0x90DD` |

The last row closes the layout exactly:

```
bank=3, preset=31  ->  3<<5 = 96 ; 96+31 = 127 ; 127*0xA3 = 0x7C61
                    ->  +0x4000 = 0x90DD ; +0xA3 = 0x9180
```

`0x9180` is precisely the flag-table offset in handoff §3.3, and
`0x9180 + 0x80 = 0x9200` is the selection offset. **The full record layout
closes with no slack and no gap.** This is the strongest single confirmation in
the whole map: three independently-derived offsets (`+0x9180` flags,
`+0x9200` selection, and the record array's own end) agree to the byte.

**Nothing here changes the 17-record plan (handoff §3.5).** The 128-entry
address space is real, the arithmetic closes the layout exactly, and the
reservation plan's *preconditions* are intact. What is still missing is
unchanged: which records are safe to write. This document says nothing about
that, and §3.5's own caveat (every record is a live library record) stands.

The real gain here is that the record write is now fully specified: source
`g+0x1A14`, destination `*(g+0x160) + 0x4000 + ((bank<<5)+preset & 0xFF)*0xA3`,
length `0xA3`. A patch that wants to read or write one record can compute the
address instead of guessing.

v16 cross-check (`v16-recursive-listing.tsv.gz`, `0x02005660`): the same
instruction sequence is present, with `g = 0x01C332A0`, storage view
`g+0x178`, and source `g+0x1A5C`.

```
02005686  lsl  r0,r5,0x5
02005688  add  r0,r6
0200568a  mul  r0,r0,#0xa3
0200568e  add  r0,r7
02005690  add  r1,r0,0x4000
```

Same formula, same `+0x4000` raw area, same `0xA3` length. The formula is not a
v15 quirk.

### 2.4 The bulk window does **not** cover the §3 slot

Checked, because it would change §3 if it did:

```
bulk window   0x01C0DE20 .. 0x01C32D38
4 KiB slot    0x01C37FD0 .. 0x01C38FD0   -> outside
slot index    g+0x1714 = 0x01C34974      -> outside
```

Neither the slot payload nor its index is inside the bulk window. So the two
mechanisms are independent: the bulk path cannot restore a slot, and the slot
path does not depend on the bulk path having run. **This weakens nothing in §3
and does not supply the missing §3 reader.**

## 3. ⭐ The 4 KiB SysEx slot — `0x0202556E`

The single most useful new fact for the persistence goal.

```
02025548  movz   r0,#0x1714
0202554c  sb     r9,[r8 + r0]          ; r8 = g ; g+0x1714 = low byte of slot index
02025550  ldw    r0,r8,#0x160          ; r0 = *(g+0x160)
02025554  and    r5,r9,#0xffff00ff     ; keep low byte, zero bits 8..23
02025558  lsl    r1,r5,0xc             ; x 0x1000
0202555a  add    r4,r0,r1              ; r4 = *(g+0x160) + (r9 masked)<<12
0202555c  mov    r0,#0x2
02025560  call   0x02004a54            ; sector lock/prepare
02025564  add    r0,r10,#0xfa0         ; RAM source
02025568  movz   r2,#0x1000            ; len = 4096
0202556e  call   0x02004b02            ; WRITE
```

with `r10 = 0x01C37030` (set at `0x02025532`), giving

```
RAM source   0x01C37FD0 .. 0x01C38FD0      (4,096 B)
storage dest *(g+0x160) + ((r9 & 0xFFFF00FF) << 12)
```

### 3.1 The mask, computed — it is an 8-bit slot index over 1 MiB

```
0xFFFF00FF  keeps bits 0..7 and 24..31, zeroes bits 8..23
=>  effective index = r9 & 0xFF          (8 bits, 256 slots)
=>  slot stride      = 256 * 0x1000       = 1 MiB
=>  reachable offsets = (0x00..0xFF) << 12 = 0x00000 .. 0xFF000
```

Reachable offsets from the three `r9` values assigned inside `FUN_02024E8C`:

| r9 | masked | offset | size |
|---|---:|---:|---|
| `0x01` | `0x000001` | `+0x001000` | 4 KiB |
| `0xFF` | `0x0000FF` | `+0x0FF000` | 4 KiB |
| `0x19BC` | `0x0000BC` | `+0x0BC000` | 4 KiB |

**The slot space is exactly the 1 MiB user region.** 256 slots x 4 KiB spans
`0x0 .. 0xFF000`, and the last slot ends at `0x100000` — the exact top of the
physical map's PRESERVE user area (`0x0009C000..0x00100000`, §3 of the
2026-10-02 map). The allocator's range and the partition boundary coincide to
the byte.

That is a strong structural signal: this is **the** user-data slot allocator
for the device, not an incidental write. 4 KiB granularity, 256 slots, one
index byte.

The index is persisted at `g+0x1714` (`0x0202554C`) — and **that store is the
one that makes the scheme self-describing**: firmware writes the slot number
into RAM so the next run can find the slot again. It stores an index, not an
address.

### 3.2 Where the slot index comes from — traced

The mask appears 9 more times in `FUN_02024E8C`, which initially looked like
"the same allocator repeated". **It is not.** Those 9 sites feed the masked
value into `ja r0,#N` comparisons — they are **command dispatch**, not slot
addressing:

```
02025614  and r0,r9,#0xffff00ff
02025618  je  r0,#0x4,0x02025ad8      ; command id 4
02025626  jne r0,#0x5,0x02025aea      ; command id 5
020256e8  and r4,r9,#0xffff00ff
020256ec  ja  r4,#0xf,0x020274a6      ; range check
```

All 9 branch to `0x020274A6`, a **common tail inside the same function**. That
tail is where the index is manufactured:

```
020274c2  lw   r6,[r10 + r1<<2]     ; r6 = a word from a table
020274d8  lsl  r9,r6,0x10           ; r9 = word << 16
020274dc  lsr  r0,r6,0x18           ; r0 = word >> 24  (a different field)
020274de  je   r1,#0x0,0x020255d0
020274e4  je   r0,#0x4,0x0202553c   ; -> the 4 KiB slot write
```

So the single 32-bit table word is **split into fields**: bits 24-31 become a
command/branch selector (`r0`), bits 16-23 become the **slot index** (`r9`).
`FUN_02024E8C` dispatches on one field and, for selector 4, writes the other.

**This is what makes the mechanism usable**: the slot index is a field of an
existing record word, not something a patch would have to invent. Reading the
record back and writing the 4 KiB are already wired.

### 3.3 The S1C producer calls the record writer directly

The reader hunt produced something better than a reader. `FUN_0201E254` — the
function handoff §2.5 names as the end of the S1C producer cave, live in stock
v15 — ends with:

```
0201e430..0201e444   validate five header bytes against 0x02..0x1B
0201e448  add  r8,r6,#0xfa0        ; r8 = 0x01C37FD0  (the slot window)
0201e44c  add  r1,r4,#0x6
0201e44e  add  r6,r9,#-0x6
0201e452  mov  r0,r8
0201e454  mov  r2,r6
0201e456  call 0x02048cce          ; ingest into 0x01C37FD0
0201e45c  add  r0,r4,r9
0201e460  lb.z r0,[r0 + -0x1]
0201e462  jne  r0,#0xf7            ; terminator check
0201e466  mov  r0,r8
0201e468  call 0x0201e13e          ; S1C packer
0201e46c  call 0x02005660          ; <-- THE RECORD WRITER
```

And `FUN_02005660` in v15 is, instruction for instruction, the record-write
function:

```
02005662  movz r0,#0x3a4
02005666  mov   r4,#0x1c33260
0200566c  lb.z  r5,[r4 + r0]        ; bank
02005676  movz r1,#0x3a0
0200567a  lb.z  r6,[r0 + r1]        ; preset
02005682  ldw   r7,r4,#0x164         ; *(g+0x164) storage base
02005686  lsl   r0,r5,0x5
02005688  add   r0,r6
0200568a  mul   r0,r0,#0xa3
0200568e  add   r0,r7
02005690  add   r1,r0,0x4000
02005694  add   r0,r4,#0x1a14        ; source
02005698  mov   r2,#0xa3
0200569a  call  0x02048cce          ; write
```

**So the persistence path is not merely adjacent to the S1C path — the S1C
producer calls the record writer.** `FUN_0201E254` ingests a SysEx payload into
`0x01C37FD0`, packs it via `0x0201E13E`, then persists it via `0x02005660`.

This is the measured connection between the two goals. It also means the
"missing reader" is not missing by accident: `0x01C37FD0` is **staging for
incoming SysEx**, filled on receive, and the same address is the source of the
§3 4 KiB slot write. Its reader is the UI/record path, not a boot loader.

Note this function writes via `*(g+0x164)` (the read/map pointer), not
`*(g+0x160)`. §1's two fields are genuinely both in use.

### 3.4 `FUN_0201E254` is a MIDI parser, and it drives the slot directly

Reading the function properly (I had called part of it "SysEx staging"
without checking what it dispatches) shows it is a **MIDI message parser**:
status `0xF8` timing clock at entry, `0xF0` SysEx at `0x0201E2EA`, and
channel-voice note-on at `0x0201E3C6` (velocity to `g+0x1E0`, channel × 2).

That matters because this one function contains the **whole slot lifecycle**:

```
; --- receive: validate a 6-byte header, then ingest the payload ---
0201e40e  lb.z r0,[r4 + 0x0]      ; status
0201e410  jne  r0,#0xf0,...       ; must be SysEx start
0201e414  lb.z r0,[r4 + 0x1]
0201e416  jne  r0,#0x43,...       ; manufacturer id 0x43
0201e41a  lb.z r0,[r4 + 0x2]      ; ...
0201e420  jne  r0,#0x9,...        ; device 0x09
0201e426  jne  r0,#0x20,...       ; ... 0x20
0201e42c  je   r0,#0x0,...        ; payload-length byte

0201e430  lb.z r0,[r4 + 0x2]  ; header form A
0201e432  jne  r0,#0x0,...
0201e436  lb.z r0,[r4 + 0x3]
0201e438  jne  r0,#0x0,...
0201e43c  lb.z r0,[r4 + 0x4]
0201e43e  jne  r0,#0x1,...       ; 00 00 01
0201e442  lb.z r0,[r4 + 0x5]
0201e444  jne  r0,#0x1b,...      ; 1B = the 6-byte header

0201e448  add  r8,r6,#0xfa0       ; dst = 0x01C37FD0
0201e44c  add  r1,r4,#0x6         ; src = payload, past the header
0201e44e  add  r6,r9,#-0x6        ; len = total - 6
0201e456  call 0x02048cce          ; memcpy the payload into staging
0201e460  lb.z r0,[r4 + r9 - 0x1]
0201e462  jne  r0,#0xf7           ; trailing SysEx end required
0201e468  call 0x0201e13e          ; S1C packer
0201e46c  call 0x02005660          ; persist

; --- checksum, then select the slot ---
0201e4de  lb.z r3,[r0 + r6 + r1]   ; running sum over 0x1000 bytes
0201e4e8  uxtb r2,r2
0201e4ec  jne  r0,#0x1000,...      ; full 4 KiB checksum
0201e4f6  and  r1,r2,#0xffffff7f   ; drop the high bit
0201e4fa  jne  r1,r0,...           ; must match the sent checksum

0201e4fe  mov  r0,#0x1
0201e500  sb   r0,[r7 + 0x2f]      ; mode <- 1
0201e504  movz r0,#0x1714
0201e508  mov  r1,#0xff
0201e50a  sb   r1,[r7 + r0]        ; ★ slot index <- 0xFF
0201e510  call 0x0201e06c          ; mode 0x18
```

**`0xFF` is the largest index the §3.1 mask can produce.** This is the producer
of the `+0x0FF000` offset observed in the §3.1 table — it is set here, on a
checksum-validated 4 KiB SysEx payload. The same address appears in
`FUN_02024E8C` at `0x0202554C` (`sb r9,[r8+0x1714]`) where `r9` came from a
record field.

So there are two writers of `g+0x1714`, and both are on real receive paths.

The 4 KiB is **checksummed over its full length** before the slot is selected.
That is a fail-closed guard the handoff's §3.5 plan explicitly asked for, and
the firmware already has one.

The 6-byte header is `F0 43 <00|09> <00|20> <01|00> <1B>` — manufacturer
`0x43`, two variant device codes, and a literal `0x1B`. The payload follows at
offset 6, so **a slot holds `len - 6` bytes of SysEx payload**, and the
trailing `0xF7` is mandatory.

### 3.5 The slot descriptor at `g+0x1714` — and the read-back path

I had been treating `g+0x1714` as a bare index byte. **It is the base of a
descriptor**, and there are exactly 6 instructions in our listing that name
`0x1714`. All 6 are now accounted for.

Writers:

```
0x0201E504  movz r0,#0x1714 ; mov r1,#0xff ; sb r1,[r7+r0]   ; slot = 0xFF
0x02025548  movz r0,#0x1714 ; sb r9,[r8+r0]                   ; slot from record
0x020255B6  movz r0,#0x1714 ; sb r11,[r8+r0]
0x02027E16  add  r1,r8,0x1714                                 ; descriptor fill
0x02027E62  movz r1,#0x1714 ; lb.z r1,[r8+r1]                 ; ★ READER
0x020280CA  movz r0,#0x1714 ; lb.z r4,[r8+r0]                 ; ★ READER
```

`0x02027E16` is the descriptor producer, and it is not a single byte:

```
02027e0e  movz r0,#0x3a4
02027e12  lb.z r0,[r8 + r0]        ; bank
02027e16  add  r1,r8,0x1714        ; r1 = &descriptor
02027e1a  add  r0,r8
02027e1c  _sb  r0,[r1 + 0x0]       ; [0] = bank
02027e1e  movz r2,#0x3a0
02027e22  lb.z r2,[r0 + r2]        ; preset
02027e26  movz r0,#0x1aae
02027e2a  _sb  r2,[r1 + 0x1]       ; [1] = preset
02027e2e  sb   r5,[r8 + r0]        ; g+0x1AAE = 0
02027e32  add  r3,r8,0x1aa5
02027e36  movz r0,#0x1e8
02027e3a  _sw  r3,[r1 + 0x4]       ; [4] = g+0x1AA5   (a POINTER)
02027e3c  lb.z r0,[r8 + r0]
02027e40  movz r1,#0x1ec
02027e44  _sb  r0,[r1 + 0x8]       ; [8] = g+0x1E8
```

So `g+0x1714` is a **record descriptor**, not an index:

| offset | content |
|---|---|
| `+0` | bank |
| `+1` | preset |
| `+4` | pointer to `g+0x1AA5` |
| `+8` | copy of `g+0x1E8` |

And the reader at `0x02027E5C` searches a **4-entry** table:

```
02027e5c  ldw  r0,r8,#0x234
02027e60  add  r0,#0x8
02027e62  movz r1,#0x1714
02027e66  lb.z r1,[r8 + r1]        ; current slot
02027e6a  lw   r0,[r0+r5<<2]       ; table[r5]
02027e6e  jne  r5,r1,0x02027e7a    ; match?
02027e72  mov  r1,#0x1
02027e74  call 0x0200b6c4          ; hit -> select
02027e7a  mov  r1,#0x1
02027e7c  call 0x0200b6d6          ; miss -> deselect
02027e80  add  r5,#0x1
02027e82  jne  r5,#0x4,0x02027e5c ; loop exactly 4 times
02027e86  movz r0,#0x171c
02027e8a  lb.z r0,[r8 + r0]
02027e8e  add  r5,r8,#0x234
02027e92  add  r6,r6,#0x950
02027e96  _lw  r2,[r5 + 0x0]
02027e98  lw   r1,[r6+r0<<2]
02027e9c  lw   r0,[r2 + 0x30]
02027e9e  call 0x0201a67c          ; see below
```

⚠️ **handoff §8.1's "text setter `0x0201A6A0`" is not a valid address.**
`0x0201A6A0` is not an instruction boundary — it falls in the middle of
`FUN_0201A67C`:

```
0201a696  _lb.z  r1,[r7 + 0x0]
0201a698  jmnz   r1,#0xd,0x0201a6b2
0201a69c  mov    r0,r6
0201a69e  call   0x02048eca
0201a6a4  add    r1,r0,#0x1         ; <- 0x0201A6A0 is mid-insn here
0201a6a6  mov    r0,r6
0201a6a8  call   0x0200a28c
0201a6ac  sw     r0,[r4 + 0x24]
```

The listing has no instruction at `0x0201A6A0`. The real function is
`FUN_0201A67C`, a **string/buffer manager**: it calls `0x02048ECA` (strlen-like,
result reused as both length and offset), `0x0200A28C`/`0x02009F98` (append-like),
`0x02009F70`, and stores a pointer at `[r4+0x24]`, with `0x0D` (carriage return)
special-cased at three points. It is a dynamic string builder, not a direct
LCD write.

So the handoff's one "confirmed UI entry point" is mis-addressed, and the
function it lands in is not a display call. **Do not treat `0x0201A67C` as the
final LCD write path** — §8.1's renderer gap is unchanged.

What `0x02027E9E` *does* establish: the slot descriptor's match result is
consumed by a **string builder**, which is consistent with a label being
formatted for the UI. That is one step closer to the display, not the
display.

**This closes the item handoff §7 listed first.**

1. A slot is **written** on a checksum-validated SysEx payload (§3.4), with the
   descriptor's `[4]` pointing at firmware RAM.
2. The descriptor is **read** back and matched against a 4-entry table.
3. The match result feeds `0x0201A67C`, a string builder.

So the read-back path exists and it **reaches a string formatter** — one step
short of the display. The slot mechanism is not write-only.

**Still not established:** whether the *4 KiB payload bytes* are read back, or
only the descriptor. The two readers load `[r8+r1]` at `+0` only. The payload
read would be a storage-ABI `read` of `0x1000`, and §2 still shows no such call.
What comes back is the **descriptor** (bank/preset), not the payload.

### 3.6 What this means for the persistence goal

The slot mechanism is now understood end to end at the descriptor level:

```
recv SysEx (6-byte header, F0 43 .. .. .. 1B, trailing F7)
  -> payload copied to 0x01C37FD0
  -> 4 KiB rolling checksum verified, high bit masked
  -> descriptor written: [0]=bank [1]=preset [4]=ptr [8]=flag
  -> S1C packer, then record writer
  -> on read: descriptor matched against a 4-entry table
  -> string builder formats the result
```

For storing our own state this tells us three things that matter:

1. **The guarded pattern already exists in firmware.** Checksum before commit,
   and a descriptor rather than a bare pointer. A patch should reuse the
   descriptor shape at `g+0x1714`, not invent a new one — matching what
   `0x02027E16` writes.
2. **The payload is checksummed over exactly 4096 bytes**, so any custom payload
   must be a full 4 KiB with a correct trailing checksum, or the firmware
   rejects it before the descriptor is touched.
3. **The round trip carries a descriptor, not the payload.** If the goal is to
   show UI state from persistent storage, the descriptor fields are what reach
   a formatter. Whether payload bytes can be read back is still unproven, and
   that is the single blocking unknown for a UI that displays stored values.

### 3.7 `FUN_02024E8C` has six callers — handoff §7-3 is refuted

handoff §7 item 3 and my own earlier note both said the slot function has no
`call` in our listing and "its caller lives outside the window". **That was an
artifact of a broken tool.**

`smk37_listing_query.py --xref` matched `<hex>\b` against the text column.
The listing writes `call 0x02024e8c`; `norm()` strips the `0x`, and since `x`
and `0` are both word characters there is no boundary to match against. **Every
xref in this repo had been silently returning nothing.** The write-wrapper
regression now returns 36 sites, so the tool is demonstrably live.

Fixed guard:

```python
pat = re.compile(r"(?<![0-9a-f])0?x?" + re.escape(target) + r"(?![0-9a-f])", re.I)
```

The first attempt used `[0-9a-z]`, which wrongly included `x` and kept
rejecting the text it was meant to match. The guard has to exclude hex digits
only.

With the tool working, the six real callers of `FUN_02024E8C`:

```
0x20286fe  call 0x02024e8c   [CONDITIONAL_CALL]     fn@0x2025bde
0x2029b46  call 0x02024e8c   [UNCONDITIONAL_CALL]   fn@0x02029b16
0x02029bb4 call 0x02024e8c   [UNCONDITIONAL_CALL]   fn@0x02029b82
0x0202b5b4 call 0x02024e8c   [UNCONDITIONAL_CALL]   fn@0x0202b472
0x0202b61c call 0x02024e8c   [UNCONDITIONAL_CALL]   fn@0x0202b472
0x0202ba1c call 0x02024e8c   [UNCONDITIONAL_CALL]   fn@0x0202b938
```

Two of them are in one function. What they pass is `r0`:

```
0x020286ee  lb.z r0,[r8 + 0x306]      ; g+0x306
0x020286f6  sb   r0,[r8 + 0x36]       ; g+0x36
0x02029ba6  call 0x0201bac2
0x02029baa  sb   r0,[r6 + r7]
0x0202b5ae  mov  r0,#0x6
0x0202b60c  movz r1,#0x1fc           ; g+0x1FC
0x0202ba16  lb.z r0,[r7 + 0x306]      ; g+0x306
```

So `g+0x306` and `g+0x36` feed the call, and `g+0x1FC` sits beside another call
site. **A checked scan of the 32 instructions before each call finds `g`-field
constants at only one of the six** (the `0x0202B61C` site, via `g+0x1FC`); the
other five take `r0` from further back, which this pass did not trace. **No UI
reachability is claimed here** — that was my assumption, and the check did not
support it.

The refutation stands on its own: the function has 6 callers, all inside our
window, at `0x0202_xxxx`. That is a fact independent of what they pass.

### 3.8 The UI command dispatcher — handoff §8.1's missing dispatcher

handoff §8.1 lists as open: "`0x02058248..0x02058314` callback vector (11
entries) — **dispatcher not found**". With `--xref` repaired, searching that
region turns up exactly one reference in the whole window:

```
0x02055a7a  jne r0,#0x19e,0x02058300
```

That is a **branch target**, not a data reference, and reading it in context
resolves §8.1:

```
0x02055a02  jne r0,#0xc9 ,0x02056b48
0x02055a0a  jne r0,#0xd3 ,0x020571d0
0x02055a12  jne r0,#0xe4 ,0x020571d8
0x02055a1a  jne r0,#0xf7 ,0x020571e0
0x02055a22  jne r0,#0x10a,0x020571e8
0x02055a2a  jae r0,#0x11b,0x020571f0
...
0x02055a42  jne r0,#0x154,0x02057208
0x02055a4a  jne r0,#0x167,0x020564d0
0x02055a52  jne r0,#0x16a,0x020564d8
0x02055a5a  jmnz r1,r0,0x02055d3a
0x02055a62  tbb r2                 <- table-branch (computed jump)
0x02055a72  tbb r2
0x02055a7a  jne r0,#0x19e,0x02058300   <- the one "vector" reference
0x02055a8a  je  r0,#0x1e2,0x02057410
0x02055a92  jne r0,#0x1f5,0x02057558
...
```

This is a **single large command-ID dispatch table**: `r0` is compared against
sparse IDs and each match branches to a handler. Measured over
`0x02055000..0x02058000`:

| quantity | value |
|---|---:|
| comparison-chain jumps | 87 |
| **distinct command IDs** | **73** |
| **distinct handler targets** | **84** |
| ID span | `0x0` … `0xF00` (3,841 wide, sparsely used) |
| targets inside `0x02058248..0x02058314` | 2 (`0x02058258`, `0x02058300`) |

So the handoff's "11-entry callback vector" is **two entries of a 73-command
table**, not a standalone vector. The dispatcher exists; §8.1 could not find it
because it looked for a *data* reference into the region and the region is only
ever a *branch* target.

`ID 0x19E -> 0x02058300` is the mapping that was missing.

⚠️ Two limits on this. First, the `tbb r2` instructions are **computed jumps
whose table Ghidra has not resolved**, and the bytes between them are being
shown as separate instructions (`lh.z r1,[r0 --= 2]`, `rep 0x2,r2`) — that is a
misdecode, so the ID set above is a **lower bound**. Second, `tbb` appears at
**178 sites** across the listing, so "table branch" is this compiler's switch
idiom generally, not a mark of this particular dispatcher. The 73 IDs and 84
targets are counted from the comparison chain only, which is the sound part.

Not claimed: that any of these handlers is the LCD renderer. What is now
established is the *shape* — a 73+ entry ID table in one place — which is what
a UI patch needs to hook a specific screen.

### 3.9 The callback vector — handoff §8.1 was right, and entry 9 is the bulk window

The §3.8 dispatcher sends `ID 0x19E -> 0x02058300`, and 56 of its 85 targets
have **no instruction rows**. Those targets cluster in
`0x02057168..0x02057FC8`. Dumping the raw bytes settles what they are:

```
02058240  00 00 00 00  00 00 00 00  12 99 02 02  36 99 02 02
02058250  74 99 02 02  ce 99 02 02  f2 99 02 02  16 9a 02 02
02058260  2e 9a 02 02  46 9a 02 02  78 9a 02 02  aa 9a 02 02
02058270  9e 43 02 02  ...
```

That is not code — it is a table of little-endian 32-bit code addresses.
**Table base `0x02058240`: two nulls, then exactly 11 code pointers**
`0x02029912 .. 0x0202439E`. So handoff §8.1's "callback vector (11 entries)"
was **accurate** — and these targets have no instruction rows precisely
because they are a **data table being branched into**, not instructions.

```
slot  addr        handler                                          role
  0   0x02058240  0x00000000                                      null
  1   0x02058244  0x00000000                                      null
  2   0x02058248  0x02029912   mov r1,#0 ; movz r0,#0x1672 ;
                               mov r2,#0x1c33260 ; sb r1,[r2+r0] ;
                               rts                    ->  g[0x1672] = 0
  3   0x0205824c  0x02029936   call 0x0201bac2 (r1,#0x18) ; sb r0,[r6+r5]
  4   0x02058250  0x02029974   goto 0x02029416 ; ldw r1,[r6,#0x15c] ;
                               sh #0xc8,[r6+0xc0]
  5   0x02058254  0x020299CE   sb r2,[r1+r0] ; add r0,#1 ;
                               sb 0,[r1+r0] ; rts        ->  string append
  6   0x02058258  0x020299F2   clamps a byte against a bound at 0x0205DDA0
  7   0x0205825c  0x02029A16   add r2,#-1 ; sb r2,[r1+r0]   (same clamp tail)
  8   0x02058260  0x02029A2E   call 0x0201bac2 ; and r0,#0xFFFF00FF ;
                               _sb r0,[r5+1] ; mul r1,#0xc
  9   0x02058264  0x02029A46   call 0x02005152               ->  field render
 10   0x02058268  0x02029A78   mov r1,#0x2057250 ; call 0x02005152
 11   0x0205826c  0x02029AAA   ★ see below  -> the section 2.1 bulk window
 12   0x02058270  0x0202439E   scroll/offset arithmetic (reads [r5+r6], +-0x3F)
```

Slot 12 (`0x0202439E`) is where the table ends; the word after it,
`0x01022406`, is not a code address.

Two of these are structurally identifiable and they matter.

**[slot 2] `0x02029912` is a one-line `g` setter** — the simplest handler in the
table:

```
02029914  mov   r1,#0
02029916  movz  r0,#0x1672
0202991a  mov   r2,#0x1c33260        ; g
02029920  sb    r1,[r2 + r0]         ; g[0x1672] = 0
02029924  rts
```

**[slot 5] `0x020299CE` is a string append** — write a byte, advance, NUL-terminate,
return. With [6]/[7] clamping it against a bound read from the string pool
(`0x0205DDA0`), and [9]/[10] handing buffers to `0x02005152`.

**`0x02005152` is a fixed-width field renderer, and it is the closest this map
has come to the display:**

```
02005154  mov   r2,#0x1c33260     ; g
0200515a  add   r3,r0,r2         ; r3 = g + column
0200515c  add   r4,r3,#0x418     ; r4 = g + 0x418 + column
02005160  sub   r3,#0xc,r0       ; field width = 12 - column
02005164  mov   r5,#0x0
02005168  lb.z  r6,[r1 + r5]     ; source byte
0200516c  add   r6,r0            ; + column offset
0200516e  sb    r6,[r4 + r5]     ; -> g[0x418 + column + i]
02005174  jl    r5,r3,...        ; loop to field width
02005178  add   r2,r2,#0x418     ; next row
0200517c  add   r3,#-0xc         ; next row's remaining width
0200517e  add   r0,#-0xc
02005182  add   r4,r1,r3
02005184  lb.z  r4,[r4 + 0xc]
02005188  sb    r4,[r2 ++= 1]    ; -> g[0x418 + row*12 + i]
0200518c  jnz   r3,0x02005182    ; rows until exhausted
```

This is a **12-column display buffer at `g+0x418`**, filled left-justified
from a source string, in rows of `0xC` (12) bytes. Entry [10] passes
`0x02057250` as the source — an address in the same data region as the string
pool — and entry [9] passes `r2`.

So the chain is now: **string pool → append (`0x020299CE`) → field render
(`0x02005152`) → a 12-column buffer.**

**There are four callers, and they disagree about which buffer is the
screen.** Two of them — and they are the ones outside the callback vector —
pass a row index in the same shape:

```
02006722  movz r1,#0x1634
02006726  lb.z  r1,[r11 + r1]      ; row count from g+0x1634
0200672a  mul   r1,r1,#0xc         ; row * 12
0200672e  add   r1,r12             ; + column
02006730  add   r1,r1,#0x16bc      ; -> g+0x16BC + row*12 + col
02006734  call  0x02005152

02025fd8  movz r1,#0x1635
02025fdc  sb    r0,[r8 + r1]       ; write g+0x1635 = r0
02025fe2  lb.z  r1,[r8 + r1]       ; read it back
02025fe6  mul   r1,r1,#0xc
02025fec  add   r1,r1,#0x16bc      ; same g+0x16BC
02025ff2  call  0x02005152
```

`g+0x16BC` is the one both non-vector callers compute, with a `* 0xC` row
stride, and `0x02025FF2` even round-trips a value through `g+0x1635` before
using it as the row. **`g+0x16BC` is the better LCD buffer candidate**, not
`g+0x418`.

Both are 12-column. `g+0x418` is the destination inside the renderer; `g+0x16BC`
is what the callers index by row. The relationship between them is **not
established** — the renderer's `add r2,r2,#0x418` walks its own buffer, and
whether it later blits to `g+0x16BC` or vice versa needs reading
`0x02005152`'s callers' continuation (`0x02006738` calls `0x02005888` right
after, which is worth a look).

The full caller set of `0x02005152`:

```
0x02029a4e  call 0x02005152   ; vector slot 9  (0x02029A46)
0x02029a86  call 0x02005152   ; vector slot 10 (0x02029A78)
0x02006734  call 0x02005152   ; row from g+0x1634, +g+0x16BC
0x02025ff2  call 0x02005152   ; row round-tripped via g+0x1635, +g+0x16BC
```

⚠️ Still missing, and it is the same missing hop as before: **nothing here
writes to LCD MMIO.** Both buffers are RAM. The row count of `g+0x16BC` is
also unknown — `g+0x1634` holds *a* row index, not obviously a height.

**`0x02006738` calls `0x02005888` immediately after the field render, and
that function is display-panel initialisation:**

```
0200588e  mov   r1,#0x4dbe23e8
02005898  mov   r2,#0x1c38fd0          ; ★ the 4 KiB slot window END
0200589e  mov   r3,#0x3f801630
020058ae  sw    r4,[r2+r0<<2]          ; fill 0x401 = 1025 words
020058b8  jne   r0,#0x401,...
020058be  mov   r0,#0x1c33260          ; g
020058c8  add   r9,r0,#0x168
020058cc  sb    r2,[r9 + 0x0]          ; g[0x168] = 0
020058d4  call  0x0206034c
020058e2  _sb   r4,[r5 + 0xc]          ; [12] = 0x0C
020058f0  sdw   r6_r7,[r5 + 0x0]
020058f4  sw    0x40,[r5 + 0x8]        ; ★ mode  = 0x40
020058fe  movz  r0,#0x100
02005902  _sw   r0,[r5 + 0x10]         ; ★ 0x100
0200590a  movz  r0,#0x100
0200590e  _sw   r0,[r5 + 0x18]         ; ★ 0x100
```

Three setup registers written with `0x40`, `0x100`, `0x100` after a 1025-word
table fill, each preceded by `call 0x0206034C` (an allocator). `0x01C38FD0` is
the **end of the §3 slot window**, and this function is the one place in the
listing that references it — the same address the SysEx path fills as staging.

So `0x01C38FD0` is **both** the end of the SysEx slot buffer **and** the
destination of a display-initialisation word table. That is an address overlap
between two unrelated-looking subsystems, and it is not explained. Flagged, not
resolved: §3 says the slot is SysEx staging, and this says the following
address is panel-setup scratch. One of the two readings is incomplete.

⚠️ Correction to my own reading this pass: I first took `g+0x418` as the
display buffer on the strength of 12-column geometry. Searching
`smk37_g_fields.py --field 0x418` returned 7 "accesses" that are **not `g`
fields at all** — they are `[r5+0x2c]`, `[r5+0x10]` and similar offsets on some
other structure, and the tool mislabelled them. `g+0x418` is real, verified in
the renderer itself (`add r3,r0,r2` with `r2 = 0x01C33260`, then `+0x418`), but
the 7 tool hits are noise. **A `--field` hit is not evidence until the base
register is checked.**

**[slot 11] `0x02029AAA` uses this map's own constants:**

```
02029aaa  mov   r2,#0x0
02029aac  movz  r3,#0x49e3      ; bulk window stride
02029ab0  mul   r3,r0           ; index * 0x49E3
02029ab2  mov   r4,#0x1c0de20   ; bulk window RAM base
02029ab8  movz  r5,#0xa84
```

`0x01C0DE20` and `0x49E3` are **exactly** the base and stride of the §2.1 bulk
window, byte for byte. So vector slot 11 is a **bulk-window accessor**, not a
UI handler: the same 151,320 B region of §2.1 is reachable through this
callback vector as well as through `FUN_02005FAC`.

That cross-reference is the useful part. It means the bulk window has **two
independent entry points**, and §2.1's symmetric write/read pair is not the
only way in or out. A patch that touches the bulk window must account for both.

Corrections to keep straight: §3.8's "73 commands / 84 handlers" counted
comparison-chain jumps, and 56 of those 85 targets are this data table rather
than code, so **the handler count for real code is 29, not 84**. The 73 IDs are
unaffected. On the entry count I was wrong twice before landing right: I read
10 populated entries first, because I unpacked from `0x02058248` instead of the
real base `0x02058240`. From the base: two nulls, then **11 code pointers,
`0x02029912..0x0202439E`** — **handoff §8.1's "11 entries" was correct and my
10 was not.** Align the unpack to the table base before counting entries.

Not claimed: that `0x02005152` or `0x020299CE` performs the LCD write. §8.1's
renderer gap is still open; this is the string-building step upstream of it.

### 3.10 The same function is at the same address in v15 and v16

`0x02005660` exists at that exact address in both listings, with the same
instruction sequence and only the `g`-relative offsets plus the call target
shifted:

| field | v15 | v16 |
|---|---:|---:|
| `g` | `0x01C33260` | `0x01C332A0` |
| selection | `0x3A4` / `0x3A0` | `0x3C8` / `0x3C4` |
| storage view | `g+0x164` | `g+0x178` |
| record source | `g+0x1A14` | `g+0x1A5C` |
| write wrapper | `0x02004B02` | `0x02049698` |

Byte-level, over `0x02005660..0x0200569C`: **12 instructions identical, 6
differ.** The six are exactly the field constants and the call target:

```
v15  40e0a403  movz r0,#0x3a4      v16  40e0c803  movz r0,#0x3c8
v15  c4ff6032c301  mov r4,#0x1c33260   v16  c4ffa032c301  mov r4,#0x1c332a0
v15  41e0a003  movz r1,#0x3a0      v16  41e0c403  movz r1,#0x3c4
v15  d1ec4476  ldw r7,r4,#0x164    v16  d1ec4877  ldw r7,r4,#0x178
v15  10e1144a  add r0,r4,0x1a14    v16  10e15c4a  add r0,r4,0x1a5c
v15  80ff2e360400 call 0x02048cce  v16  80fff83f0400 call 0x02049698
```

Note the last line: **the storage wrapper itself moved**, `0x02004B02` →
`0x02049698`. That is handoff §4.4's warning in concrete form, and it means
**no v15 write/read address in this document can be reused in v16 without
re-mapping.** The `mul #0xA3` / `add #0x4000` / `mov r2,#0xA3` core is
untouched, so the *layout* is stable across versions even though the *entry
points* are not.

Within this function every field delta is `+0x40` or `+0x48`. Across objects it
is not uniform (handoff §5.2).

⚠️ **Tool trap hit while verifying this.** `smk37_listing_query.py --exh <file>`
does not replace the default recursive listing; it *adds* it, and the loader
returns the first match per address. So a "v16 cross-check" run that only set
`--exh` silently dumped **v15 rows labelled v16** — I got byte-identical
dumps for two builds that are demonstrably different, and had to re-run with
`--rec none --exh <v16>` to see the real values. Identical bytes for a
cross-version check is a **failure signal**, never a pass.

### 3.11 The table base `0x01C37030` touches the S1C producer

`0x01C37030` is loaded in exactly 5 places:

```
0x02008b7e  mov r5,#0x1c37030   FUN_02008ae0
0x0201bed2  mov r5,#0x1c37030   FUN_0201be96
0x0201c2de  mov r5,#0x1c37030   FUN_0201c2a2
0x0201e3fc  mov r6,#0x1c37030   FUN_0201e254   <-- S1C producer
0x02025528  mov r10,#0x1c37030  FUN_02024e8c  <-- the slot writer
```

`FUN_0201E254` is the address the 2026-10-03 handoff §2.5 names as the **end of
the S1C producer cave** (`0x0201E13E..0x0201E254`), and it is a live function
in stock v15. It reads `*(g+0x1D8)` and compares a byte against `0xF8`.

The address-level observation in §3.11 is backed by the call-level one in
§3.3: the SysEx/S1C path invokes the record writer directly. The 5 sites that
load `0x01C37030` are the S1C/storage region as a whole.

Two readings of that, not yet separated:

- the index is a slot number the UI selects, or
- the index is a key (e.g. a category id) and the firmware maps key -> slot.

`g+0x1714` being written by the same routine that consumes it is consistent
with both. **Not claimed.**

> Correction trail, kept because it is the failure mode to watch: this mask was
> first read as `~0xFF` (a low-byte clear), then as zeroing byte 2 only. Both
> were wrong; the third read is what the arithmetic gives. Two of three
> readings were made by eye and only the third was computed. Run it.

**No matching `read(dst, slot, 0x1000)` exists** — all 33 `#0x1000` sites were
enumerated and the only ABI call with that length is this write.

**Why, per §3.3:** `0x01C37FD0` is SysEx **staging**. It is written when a
packet arrives (`FUN_0201E254` -> `0x02048CCE`) and flushed to the slot by the
save path. It is not a boot-time restore buffer, so the absence of a
`0x1000`-length read is expected rather than a gap in our coverage.

That resolves this item on the mechanism, not on a reader:

- the slot holds **received SysEx payloads**, not a persisted settings blob;
- the index selects which slot a payload went to;
- the 4 KiB is enough for a payload plus slack.

**Still not established:** what reads a slot back, or whether the firmware ever
does. A UI that wants to show stored payloads would need that path, which we
have not found. Do not claim a round trip.

## 4. `g` object access map — scale

*(§4 and §5 are unchanged from the first pass; see below for the one item that
this pass did not close.)*

`tools/smk37_persist_map.py --gfield`:

- **686 fields** of `g` are touched by the listing (685 positive, 1 artifact).
- Combined with `smk37_g_fields.py`, `g+0x0000..0x03E8` is densely used; the
  read/write split is strongly asymmetric in `g+0x0001..0x0040` (write-only
  byte flags), consistent with a little-endian 32-bit pointer at `g+0x0000`
  whose bytes are individually used as flags.

Never-touched 4-byte words in `g+0x0000..0x0400` (the only evidence-backed
"unreferenced" statement in this document — see §5 caveat):

```
g+0x0184  g+0x0198..0x019C  g+0x01AC..0x01B0  g+0x01C8..0x01D0
g+0x01DC  g+0x01F4  g+0x0208  g+0x0210..0x0218  g+0x0278
g+0x0284..0x0288  g+0x02DC..0x031C  g+0x0324..0x034C  g+0x0354
g+0x036C  g+0x0374..0x0388  g+0x0394  g+0x039C..0x03A4
g+0x03C4  g+0x03D0  g+0x03E8
```

**These are not candidates for reuse.** See §5.

## 5. Limits — read before using any row

1. **Listing coverage is 58.2%.** Everything above is "not seen in the
   listing", not "not referenced". `0x02060E2C` (allocator) is already known
   to exist outside our window. A never-touched field may be written from code
   we cannot see. **This is the M09 lesson and it applies verbatim to §4.**
2. **UNRESOLVED is not ABSENT.** 46 of 69 ABI sites have unresolved r1.
   The tracker is a linear replay with no unrolling.
3. **A known false-positive class.** `lw r6,[r6+0x0]` (a linked-list walk)
   redefines r6, but the tracker keeps it g-relative. This produced the one
   negative "field" at `g-0xA` (site `0x020441FC`), hand-verified as a walk
   of a linked list, not a `g` access. So **positive offsets can also be
   wrong**, and the tool reports no way to tell them apart.
4. **No byte-level occupancy claim is made for any RAM range**, including the
   4 KiB of §3. That requires the static occupancy prover that does not exist
   yet.
5. **v16 addresses are not mapped.** Everything is v15.
6. **⚠️ The tool invented a storage pointer, and I nearly published it.**
   Chasing the 10 unresolved `len=0x4` sites, the table showed
   `r1 = ptr(mem[0xc55])` — an *absolute* storage address in the low region,
   which would have been a clean new finding. It was an artifact.
   `lw r2,[r0+r1<<2]` is register-indexed: the base is `r0`, `r1` is a scaled
   index. My fallback took the last register and produced a pointer out of an
   index. A second instance, `lw r1,[r0+r5]`, had no `<<` at all and slipped
   past the first fix.

   Fixed properly: if the brackets contain **two** registers the offset is
   dynamic, and the function returns UNRESOLVED rather than a guess. The rule
   is now "the base is the first register in the brackets; a second register
   means do not fold an address."

   **Two near-miss "discoveries" in one session, both from the same class of
   bug.** The tell was that a synthetic address appeared at all — no firmware
   pointer should look like `0xC55`. Treat any absolute address that small as
   suspect and go read the instruction.
7. **A load-prefix class of bug, found and fixed this pass.** quarkslab
   prefixes some forms with `_` (`_lw`, `_lb.z`, `_sw`). `_lw` is a plain
   load. It was missing from the `LD` set, and `FUN_02005FAC` reloads the
   storage base with `_lw r1,[r4+0x0]` immediately before its 8 bulk writes —
   so r1 died at the write and 16 of 69 sites went unresolved. Fixing one set
   membership took unresolved from 46 to 30 and resolved the whole bulk
   window. **Any mnemonic-prefix assumption in these tools is suspect.**

## 6. Next steps, in order

0. **Find the LCD MMIO write.** §3.9 now has string pool → append → 12-column
   render → `g+0x418` / `g+0x16BC`, plus panel init at `0x02005888`. The one
   missing hop is the store to LCD MMIO. Everything else needed for a UI patch
   is in place; this is now the highest-value item.
1. ~~**Find the reader for the §3 4 KiB slot.**~~ → **answered by mechanism,
   not by a reader** (§3.3). `0x01C37FD0` is SysEx staging: written on packet
   receive, flushed to a slot on save. A `0x1000`-length read is not expected.
   → **closed at the descriptor level** (§3.5, §3.6). A reader exists:
   `0x02027E62` and `0x020280CA` both read `g+0x1714`, and `0x02027E5C`
   searches a 4-entry table then feeds a string formatter.
   Still open: whether the **4 KiB payload bytes** are ever read back, only
   the descriptor. No storage-ABI `read` of length `0x1000` exists in our
   window. **That is the single blocking unknown for a UI that displays
   stored values** (§3.6).
2. ~~**Resolve `r9`'s index on the save path.**~~ → **done** (§3.1, §3.2).
   `r9` = bits 16-23 of a table word loaded at `0x020274C2`; the same word's
   bits 24-31 select the command. The index is persisted at `g+0x1714`.
   Remaining: **who owns the table at `r10 = 0x01C37030`** — that is the
   record whose field selects the slot, and it is the thing a patch must
   understand.
3. ~~**Close the unresolved r1 sites**, prioritising len `0x49E3`.~~
   → **done for the bulk window** (46 → 31, §2.1). The remainder is 31:
   13 are register-indexed settings slots (§2.1a, §2.2, needs RAM table contents),
   10 have unknown length, and the rest are small reads. The `0xA3` raw-record
   index chain (`0x02026DA6`) is still unresolved and is now the most
   interesting single site, because it is the official SAVE's record write.
4. **Build the static occupancy prover.** Required before any claim about
   free RAM. Do not skip it on the strength of §4's list.
5. **Extend listing coverage past `BASE+0x58000`.** Everything in §5.1 is
   capped by this; until it moves, treat every row as provisional.

## 7. Reproduce

```bash
python3 tools/smk37_persist_map.py --selftest      # 5 known answers
python3 tools/smk37_persist_map.py --table          # 69 ABI sites
python3 tools/smk37_persist_map.py --gfield         # g access + persistence
python3 tools/smk37_persist_map.py --json out.json  # machine-readable
python3 tools/smk37_g_fields.py --field 0x160       # per-field access
python3 tools/smk37_listing_query.py --range 02025548:0202556e
```

## 8. Not claimed

- That the §3 path runs on hardware. Static only.
- That the bulk window (§2.1) round-trips correctly at runtime. Its two halves
  are **statically** symmetric; symmetry of code is not proof that the bytes
  written equal the bytes restored, and no readback check exists.
- That the §3 4 KiB write is ever read back. No reader is in our window.
- That `FUN_02024E8C` is reachable, or who calls it. No `call` to it exists in
  our listing; entry is by a path we cannot see.
- That a slot written at `0x0202556E` is ever read back. The descriptor is read
  (§3.5); the payload is not, in our window.
- That `FUN_0201A67C` reaches the LCD. It is a string builder with a `0x0D`
  special case; the renderer gap in handoff §8.1 is unchanged.
- That the SysEx payload format inside the 4 KiB slot is understood. Only the
  staging address and length are established.
- That the table at `0x01C37030` is what I think it is. Only its role as a
  32-bit word source is established.
- That `0x01C37FD0..0x01C38FD0` is safe to write. It is a *persisted* range,
  which makes it more contended than ordinary BSS, not less.
- That the §4 never-touched words are free. Coverage is 58.2%.
- That the record layout ends at `+0x9209` **for the record path**. §2.3 closes
  the record array exactly at `+0x9180`, but a separate write reaches
  `+0x0FF000` (§3) and the bulk window (§2.1) is a third region entirely.
  So: the record array is exact, the *partition* is not thereby closed.
- That `0x01C0DE20..0x01C32D38` is safe for our own state. It is a live
  persisted window; using it means contending with the firmware for it.
- That the `len=0x4` settings cluster has a fixed storage region. Its address
  is table-derived and RAM-dependent (§2.2).
- That any handler in the §3.8/§3.9 tables is the LCD renderer. §3.9 reaches a
  string builder that consumes the string pool, which is one step upstream of a
  display, but `0x02005152` and `0x020299CE` are not shown to be the renderer.
- That `g+0x418` or `g+0x16BC` is the LCD buffer, or that either reaches the
  display. Both are RAM, both 12-column, and **neither is shown to be written to
  LCD MMIO** (§3.9). This remains the nearest-to-the-glass artefact found, and
  the LCD MMIO write is still missing.
- The row count of either buffer. `0xC` stride is asserted by the loops;
  `g+0x1634` holds an index, not a proven height.
- The relationship between `g+0x418` and `g+0x16BC`. Whether one blits into the
  other is unread.
- Why `0x01C38FD0` is both the end of the SysEx slot window and the destination
  of the display-init word table in `0x02005888` (§3.9). Recorded as an
  unexplained overlap.
- A complete command-ID list. 73 is a lower bound — the `tbb` jump tables are
  misdecoded by Ghidra and were not enumerated.
- Anything about v16 beyond the one-function comparison in §3.9. The
  `0x02004B02` -> `0x02049698` wrapper move means every other v15 ABI address
  here needs re-mapping before v16 use; only the record layout constants
  (`0xA3`, `0x4000`) are known to survive.
