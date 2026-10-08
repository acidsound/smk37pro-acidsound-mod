# S1-C1 guarded host ingress, official v15 and H2 only

Date: 2026-08-02 UTC
Scope: read-only design and audit. No firmware was built, no device was accessed, no flash operation was performed, no v12 evidence was used, and no unverified handler or code-cave address is proposed.

## Decision

**Protocol and two-slot publication design: PASS. Firmware implementation: BLOCK.**

The smallest race-free S1-C1 load is two private, self-checking complete SysEx messages:

1. `LOAD0`, 173 bytes, carries arbitrary Note A and the first exact 156-byte runtime voice.
2. `LOAD1_COMMIT`, 176 bytes, carries arbitrary distinct Note B, the second exact 156-byte runtime voice, and a checksum binding both messages into one transaction.

Consumers remain on H2/stock behavior until `state == ARMED`. `ARMED` is written last, after both packet CRCs, transaction/state checks, note bounds, full-set CRC, both copies, and both valid bytes have passed. No producer is allowed after `ARMED`, so Note On and Note Off cannot select different generations.

Implementation remains blocked by executable placement, an exact instruction/branch budget, heap high-water evidence for the additional 160-byte reservation, and the still-static-only Note On `r6` / Note Off `r5` hook ABI. A host-visible ACK/NAK path is also not audited.

## Evidence boundary

Exact inputs are SHA-gated by `validate.py` and recorded in `evidence.json`:

- official v15 app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- official v15 FWSC: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- H2 app: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- live-proven R02/H2 packet: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
- Quarkslab v15 listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347`
- Kagaimiq v15 listing: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`

All runtime addresses below are decoded official-v15 or exact H2 addresses. None is a guessed handler address.

## 1. Existing 163-byte accepted packet audit

The live-proven packet is exactly:

```text
F0 43 00 00 01 1B || runtime_voice[156] || F7
```

- total length: `0xa3` / 163 bytes
- runtime payload: 156 bytes, all `< 0x80`
- packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
- observed H2 result: intended Mooger #1 sound, normal Note Off, no reboot

### Exact complete-message parser path

The upstream completed-message call is verified at `0x0202d202`:

```text
0x0202d1b4  accumulated_length = prior_length + final_chunk_length
0x0202d1bc  message[0]
0x0202d1be  special-case only when accumulated_length == 7
0x0202d200  r0 = assembled_message
0x0202d202  call 0x0201e254
```

At official handler entry `0x0201e254`:

```text
0x0201e254  push saved registers
0x0201e256  r4 = r0     // message pointer
0x0201e258  r9 = r1     // message length
0x0201e25a  read message[0]
```

The accepted direct Yamaha voice path then proves:

```text
0x0201e3ee  require obj+0x206 != 0
0x0201e3f8  state = obj+0x104
0x0201e40a  direct path only when state == 0
0x0201e410..0x0201e444  require F0 43 00 00 01 1B
0x0201e448  stage = 0x01c37030 + 0x0fa0 = 0x01c37fd0
0x0201e44e  copy_length = r9 - 6
0x0201e456  memcpy(stage, message+6, copy_length)
0x0201e462  require message[r9-1] == F7
0x0201e468  stock: packer; H2: accepted-packet producer
0x0201e46c  reload selected stock snapshot
```

The segmented final path at `0x0201e472..0x0201e4a0` checks final `F7` and accumulated length `0x9e`, appends `r9-2` bytes into the same stage, then calls the same packer/producer and reload sequence.

### Critical negative findings

1. **The direct path does not prove `r9 == 0xa3`.** It copies `r9-6` bytes before checking only the final byte. The live packet is exactly 163 bytes, but exact direct-path length acceptance must not be generalized from that successful packet.
2. **The direct path does not prove a Yamaha checksum check.** The live R02 payload is a raw 156-byte expanded runtime object produced by `unpack_voice()`. Its final byte is runtime data `0x3f`; the full payload does not satisfy the commonly assumed 7-bit Yamaha sum-to-zero equation. An implementation must not invent such a gate and reject the live-proven representation.
3. **The handler reads `message[0]` before a local length gate.** The custom parser must run only where the upstream assembler already supplies pointer plus length, and it must check exact length before reading command-specific offsets.
4. **The stage is not durable storage.** `0x01c37fd0..0x01c38fd0` is a shared 4 KiB stock staging object used by single-voice, segmented, larger bulk, and default-load paths.

The custom protocol therefore uses CRC-16 over the full 156 runtime bytes and copies directly from the completed host message into owned RAM. It does not use the stock stage and does not claim Yamaha payload-checksum semantics.

## 2. Exact ingress point and stock preservation

### Selected ingress point

Use a future wrapper at the exact H2-preserved completed-message callsite `0x0202d202`, whose original bytes are `bfea2788` (`call 0x0201e254`). The wrapper ABI is the decoded caller ABI:

```text
r0 = completed/assembled message pointer
r1 = accumulated message length
```

Do not hook or replace the official parser entry by an assumed address. Do not hook the short/direct MIDI call at `0x0202d1fa`; ordinary MIDI remains outside the private parser.

### Dispatch rule

```text
if len >= 7 and bytes[0..6] == F0 7D 53 4D 4B 0F 01:
    consume in the private S1-C1 parser
else:
    tail-call the unchanged exact H2 0x0201e254 handler with original r0/r1
```

This prefix is disjoint from Yamaha manufacturer ID `0x43`. Every `F0 43 ...` packet, including the live-proven 163-byte packet and segmented/larger Yamaha product traffic, bypasses the private parser and enters the unchanged H2 handler.

**Preservation PASS is relative to the exact H2 parent.** H2 already replaces the official packer body, redirects accepted product callsites to its load-once producer, and blocks SAVE. This ingress does not restore official persistent pack/SAVE semantics. If “stock preservation” means exact official-v15 persistence and SAVE rather than unchanged H2 behavior, that is a separate **BLOCK** requiring restoration or relocation of the original packer.

### Why two messages are minimal

A one-message transaction needs at least:

```text
16 envelope bytes + 2 note bytes + 2*156 voice bytes + 3 set-CRC bytes = 333 bytes
```

The upstream assembler invokes the handler when accumulated length reaches `0xfe` / 254 bytes (`0x0202d182`) and uses the stock segmented state machine for larger traffic. A 333-byte private message would therefore require a new, separately audited segmented parser and assembly state.

The selected 173-byte and 176-byte messages are each below `0xfe`, arrive at the verified completed-message call, and require no private segmentation state. One message cannot carry both voices under that bound, so two is the minimum complete-message count.

## 3. S1-C1 wire contract

Common envelope, fixed 16-byte overhead excluding `BODY`:

```text
F0 7D 53 4D 4B 0F 01 CMD TX FLAGS LEN_LO7 LEN_HI7 BODY CRC0 CRC1 CRC2 F7
```

Rules:

- private prefix: `F0 7D 53 4D 4B 0F 01`
- `TX`: `1..127`; zero rejected
- `FLAGS`: exactly zero
- all bytes except `F0` and `F7` must be `< 0x80`
- `LEN`: 14-bit little-endian 7-bit pair and must equal the command's exact body length
- packet CRC: CRC-16/CCITT-FALSE, init `0xffff`, polynomial `0x1021`, no reflection, xorout zero
- packet CRC range: byte `0x53` at offset 2 through the final body byte
- CRC wire form: `(crc & 0x7f), ((crc >> 7) & 0x7f), ((crc >> 14) & 0x03)`; third byte greater than 3 rejected
- exact total length and terminal `F7` are checked before body indexing or owned-state mutation

### `CMD 0x11 LOAD0`

```text
BODY = NOTE0 || VOICE0[156]
body length = 157
exact packet length = 173
allowed state = EMPTY only
```

Checks before mutation: exact framing/length, byte ranges, `TX`, flags, packet CRC, `NOTE0 <= 127`, command, `state == EMPTY`, `valid0 == 0`, and `valid1 == 0`.

Under the shared nonblocking H2 producer lock:

1. recheck state and valid bytes;
2. write `state = LOADING`, then `csync`, so consumers cannot select owned RAM before the copy;
3. store `TX` and `NOTE0`;
4. copy exactly 156 bytes to slot 0;
5. `csync`, then set `valid0 = 1` last;
6. unlock.

A failed try-lock returns BUSY immediately with no persistent state change. No spin is allowed.

### `CMD 0x12 LOAD1_COMMIT`

```text
BODY = NOTE1 || VOICE1[156] || SETCRC0 SETCRC1 SETCRC2
body length = 160
exact packet length = 176
allowed state = LOADING only
```

Before any slot-1 or publication mutation, acquire the same nonblocking lock and verify:

- `TX` matches the stored transaction;
- `valid0 == 1`, `valid1 == 0`;
- `NOTE1 <= 127` and `NOTE1 != NOTE0`;
- full-set CRC matches the canonical bytes below.

Canonical set checksum input:

```text
01 || TX || NOTE0 || VOICE0[156] || NOTE1 || VOICE1[156]
```

After all checks pass:

1. store `NOTE1`;
2. copy exactly 156 bytes to slot 1;
3. `csync`, then set `valid1 = 1`;
4. `csync`, then set `state = ARMED` last;
5. unlock.

After `ARMED`, both commands and every other private mutating command are rejected until reboot/BSS zero. There is no ABORT, replacement, remap, or generation change in S1-C1.

### Rejection isolation

- Not the full private prefix: delegate unchanged to H2.
- Full private prefix but wrong total/body length, flags, command, state, transaction, bounds, byte range, delimiter, packet CRC, set CRC, duplicate note, or lock busy: consume/reject with no slot/map/state mutation.
- A lock byte may change transiently while a state/checksum recheck is performed, but it is released on every reject path and no published data changes.
- No stock stage, current snapshot, persistent patch record, SAVE metadata, or stock SysEx state is written by the private parser.

No return-message path is included. A production-quality host-visible ACK/NAK remains blocked until an official-v15 transmit path and its scheduling/buffer ownership are audited.

## 4. Minimal owned RAM

Two aligned `0xa0` records preserve the exact H2 slot-0 addresses and need no 128-byte map:

```text
base 0x01c46520
end  0x01c46660 exclusive
total reservation 0x140 = 320 bytes
additional reservation beyond H2 0xa0 = 160 bytes
```

| Address/range | Size | Purpose |
|---|---:|---|
| `0x01c46520..0x01c465bc` | 156 | slot 0 runtime voice, exact H2 range |
| `0x01c465bc` | 1 | `valid0`, exact H2 address |
| `0x01c465bd` | 1 | global H2 nonblocking producer lock |
| `0x01c465be` | 1 | `note0` |
| `0x01c465bf` | 1 | state: 0 EMPTY, 1 LOADING, 2 ARMED |
| `0x01c465c0..0x01c4665c` | 156 | slot 1 runtime voice |
| `0x01c4665c` | 1 | `valid1` |
| `0x01c4665d` | 1 | transaction ID |
| `0x01c4665e` | 1 | `note1` |
| `0x01c4665f` | 1 | reserved zero |

Boundary arithmetic:

- official heap: `0x01c46520..0x01c7fd30`, `0x39810` bytes
- H2 heap begin: `0x01c465c0`, remaining `0x39770` bytes
- proposed S1-C1 heap begin: `0x01c46660`, remaining `0x396d0` bytes
- H2-to-S1-C1 heap reduction: exactly `0xa0` bytes

This is the smallest aligned model that preserves the H2 voice/valid/lock addresses, holds two immutable 156-byte voices, and stores two arbitrary note identities plus transaction state. It does not prove allocator headroom.

## 5. Consumer contract

Keep separate wrappers because the decoded note registers differ:

- Note Off call `0x0201c63e`: note candidate `r5 = msg[1]` from `0x0201c62e`
- Note On call `0x0201c67c`: note candidate `r6 = msg[1]` from `0x0201c670`

Policy for Ch10 only:

```c
if (state == ARMED && note <= 127) {
    if (note == note0 && valid0 == 1) source = slot0;
    else if (note == note1 && valid1 == 1) source = slot1;
    else source = stock;
} else if (state == EMPTY && valid0 == 1) {
    source = slot0;  // exact H2 load-once compatibility before S1-C1 begins
} else {
    source = stock;
}
```

Non-Ch10 always uses stock. Every stock fallback restores original destination `r0` immediately before stock `memcpy` and preserves original `r1/r2`, exactly as corrected H2. Both paths copy exactly `0x9c` bytes.

The `EMPTY && valid0` compatibility branch preserves H2's accepted-product-packet behavior when no S1-C1 transaction has begun. If an H2 Yamaha product packet claims slot 0 first, `LOAD0` rejects until reboot rather than overwriting that generation. During `LOADING`, all consumers use stock. During `ARMED`, the two private slots are immutable and H2's existing producer observes `valid0 == 1`, so it cannot replace slot 0.

## 6. Code audit

### Proven space

The exact H2 replacement region is `0x0201e13e..0x0201e254`, 278 bytes. H2 occupies `0x0201e13e..0x0201e1ec`, 174 bytes, leaving only `0x68` / 104 bytes before the untouched handler entry.

The remaining 104 bytes are not sufficient evidence for:

- two expanded note-aware consumer wrappers;
- a completed-message ingress multiplexer;
- exact two-command parsing and all rejection branches;
- CRC-16 packet and set loops;
- nonblocking lock/state publication;
- calls to the existing 156-byte `memcpy`;
- stock-tail delegation and all return paths.

No verified callable CRC-16 routine is identified in current official-v15 evidence. The parser therefore needs either a new reviewed CRC body or an independently proven official helper. No second executable region is authorized by this audit.

### Required exact sizing pass

Before implementation, assemble or compile only the proposed routines against the pinned PI32v2 toolchain, decode every instruction independently, and produce:

1. exact byte count for both consumers, ingress mux, parser, and CRC helper;
2. exact call/branch reach and relocation values;
3. exact overwritten parent bytes and all direct callers;
4. proof that the original H2 handler and non-private path remain byte-for-byte reachable;
5. a non-overlapping executable placement with an ownership argument, not an absence-of-xrefs guess.

This analysis intentionally does not build those routines or firmware.

## 7. PASS and BLOCK gates

| Gate | Status | Requirement/evidence |
|---|---|---|
| Official-v15/H2 provenance | **PASS** | Exact app/package/listing/H2 hashes validate. No v12 input. |
| Accepted 163-byte packet shape | **PASS** | Exact header, 156-byte runtime payload, `F7`, length 163, live H2 result. |
| Exact stock direct length gate | **BLOCK as inherited guard** | Direct handler does not prove `r9 == 0xa3`; private parser must enforce its own exact lengths. |
| Yamaha runtime-payload checksum assumption | **BLOCK** | Live payload does not satisfy the guessed Yamaha sum equation; use defined CRC over all 156 bytes. |
| Complete-message ingress ABI | **PASS static** | `0x0202d202` supplies assembled pointer in `r0` and length in `r1`; H2 bytes unchanged. |
| Private/Yamaha namespace separation | **PASS design** | Private `F0 7D 53 4D 4B 0F 01`; all `F0 43` delegates unchanged to H2. |
| Smallest nonsegmented transaction | **PASS design** | 173 + 176 bytes; one 333-byte message crosses verified `0xfe` threshold. |
| Exact rejection/state machine | **PASS model** | Reproducible validator covers length, framing, 7-bit bounds, state, TX, note bounds, CRCs, duplicate note, replay, and immutability. |
| Publication race | **PASS design** | Shared H2 nonblocking lock, `LOADING` plus `csync` hides partial data, `valid` and `ARMED` are published last, and no mutation occurs after `ARMED`. |
| H2 behavior before private load | **PASS design** | `EMPTY && valid0` retains H2 single-source behavior; private load rejects if H2 claimed slot 0 first. |
| Exact official-v15 stock pack/SAVE semantics | **BLOCK on H2 parent** | H2 already replaced packer behavior and blocks SAVE; not restored here. |
| Two-slot RAM arithmetic | **PASS static** | Exact `0x140` reservation, `0xa0` beyond H2, heap end unchanged. |
| Heap headroom | **BLOCK** | Allocation high-water under worst observed operation is not proved for heap begin `0x01c46660`. |
| Note register ABI | **BLOCK for firmware** | Independent static decoders agree on Off `r5` and On `r6`, but no live register trace or instruction-accurate release signoff exists. |
| Executable placement and exact code size | **BLOCK** | Only 104 unused bytes remain in the audited H2 region; no second owned executable region or exact routine size exists. |
| Host ACK/NAK | **BLOCK** | No official-v15 transmit/response path audited. |
| Firmware build/flash/live authorization | **BLOCK** | Requires every preceding firmware gate, deterministic child build, binary diff, rollback bundles, independent reviews, then explicit device authorization. |

## 8. Implementation stop conditions

Stop before building a candidate if any of these remains unresolved:

- parser placement depends on an unproved cave or guessed address;
- non-private `r0/r1` cannot tail into exact H2 handler semantics;
- CRC or exact-length checks occur after owned-state mutation;
- a private packet can overwrite stock staging/current/persistent state;
- a producer can mutate either slot after `ARMED`;
- Note On and Note Off do not use the same note-to-slot rule;
- any fallback fails to restore H2's original `r0` and preserve `r1/r2`;
- heap high-water cannot tolerate the exact additional `0xa0` reservation;
- exact official stock pack/SAVE behavior is claimed without separately restoring it;
- a host-visible success result is required but ACK/NAK remains unaudited.

`validate.py` is the reproducible offline evidence check for this report. It only reads and hashes existing artifacts, exercises the protocol model, and writes no firmware or device state.
