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
- the first measured address-level link between the persistence path and the
  S1C producer path (§3.3)
- an honest negative: no reader for that 4 KiB slot exists in our window (§3)

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

### 2.3 The bulk window does **not** cover the §3 slot

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

## 3. ⭐ The 4 KiB persistent slot — `0x0202556E`

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

### 3.3 The table base `0x01C37030` touches the S1C producer

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

So the same RAM base that supplies the 4 KiB slot index is read by the code
that produces S1C state. That is the first **measured** link between the
persistence path and the S1C path — previously they were separate tracks.

What this does **not** establish: that the slot write and the S1C read are
related. They share a base address; whether they share a data structure is
unproven. Both are stated here as facts about which functions touch the
address, and no causal link is claimed.

Two readings of that, not yet separated:

- the index is a slot number the UI selects, or
- the index is a key (e.g. a category id) and the firmware maps key -> slot.

`g+0x1714` being written by the same routine that consumes it is consistent
with both. **Not claimed.**

> Correction trail, kept because it is the failure mode to watch: this mask was
> first read as `~0xFF` (a low-byte clear), then as zeroing byte 2 only. Both
> were wrong; the third read is what the arithmetic gives. Two of three
> readings were made by eye and only the third was computed. Run it.

**Searched and not found (this session):** a matching `read(dst, slot, 0x1000)`.
All 33 `#0x1000` sites in the listing were enumerated; the only ABI call using
length `0x1000` is this write. The three near-misses at `0x0201D804`,
`0x0201D81C`, `0x0201E4EC` decode as `_sw`/`sb`/branch — misdecodes, not calls.

So the 4 KiB slot is **write-only inside our 58.2% window**. Two readings, and
the listing cannot distinguish them:

- it is restored by code outside our window (plausible — a restore routine may
  live past `BASE+0x58000`), or
- it is genuinely write-only and something else owns that flash.

**Do not call this a round trip until the reader is found.** The read side is
step 1 of §6 for exactly this reason.

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

1. **Find the reader for the §3 4 KiB slot.** Partly answered this session:
   the writer's structure is fully traced (§3.2) but **no reader is in our
   58.2% window** — searched all 33 `#0x1000` sites. Either extend coverage
   past `BASE+0x58000` or find `FUN_02024E8C`'s caller, which likely calls
   both halves. Highest value remaining.
2. ~~**Resolve `r9`'s index on the save path.**~~ → **done** (§3.1, §3.2).
   `r9` = bits 16-23 of a table word loaded at `0x020274C2`; the same word's
   bits 24-31 select the command. The index is persisted at `g+0x1714`.
   Remaining: **who owns the table at `r10 = 0x01C37030`** — that is the
   record whose field selects the slot, and it is the thing a patch must
   understand.
3. ~~**Close the unresolved r1 sites**, prioritising len `0x49E3`.~~
   → **done for the bulk window** (46 → 31, §2.1). The remainder is 31:
   10 are register-indexed settings slots (§2.2, needs RAM table contents),
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
- That the table at `0x01C37030` is what I think it is. Only its role as a
  32-bit word source is established.
- That `0x01C37FD0..0x01C38FD0` is safe to write. It is a *persisted* range,
  which makes it more contended than ordinary BSS, not less.
- That the §4 never-touched words are free. Coverage is 58.2%.
- That the record layout ends at `+0x9209`. One confirmed write reaches
  `+0x0FF000`, and the bulk window (§2.1) is a third region entirely.
- That `0x01C0DE20..0x01C32D38` is safe for our own state. It is a live
  persisted window; using it means contending with the firmware for it.
- That the `len=0x4` settings cluster has a fixed storage region. Its address
  is table-derived and RAM-dependent (§2.2).
- Anything about v16.
