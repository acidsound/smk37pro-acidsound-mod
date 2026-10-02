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
| unresolved | 46 | 4 … `0x49E3` | needs the §5 work |

Raw records (`+0x4000 + index*0xA3`, len `0xA3`) resolve in **r0** but not r1
on this pass; the index chain (`uxtb` → `mul #0xA3` → `add`) is modelled but
`lsl r0,r0,0x5` upstream of it is not. That is site `0x02026DA6`.

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

The index is persisted at `g+0x1714` (`0x0202554C`), so the scheme stores an
index, not an address.

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

## 6. Next steps, in order

1. **Find the reader for the §3 4 KiB slot.** Searched this session: absent
   from our window. Either extend coverage past `BASE+0x58000` or locate the
   restore path. Until then §3 is a proven write with no proven read.
2. ~~**Resolve `r9`'s index on the save path.**~~ → **done** (§3.1). The index
   is persisted at `g+0x1714`; the mask is `0xFFFF00FF` and slots are 1 MiB
   apart. Remaining: what *value* the UI writes into `g+0x1714`.
3. **Close the 46 unresolved r1 sites**, prioritising len `0x49E3` and
   `0xA3`. Each one that lands shrinks the unknown surface of §2.
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
- That the §3 4 KiB write is ever read back. No reader is in our window.
- That `0x01C37FD0..0x01C38FD0` is safe to write. It is a *persisted* range,
  which makes it more contended than ordinary BSS, not less.
- That the §4 never-touched words are free. Coverage is 58.2%.
- That the record layout ends at `+0x9209`. One confirmed write reaches
  `+0xFF000`.
- Anything about v16.
