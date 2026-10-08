# S1-C2 two-slot selector controlled checkpoint

Date: 2026-08-02 UTC  
Status: **BLOCK, no flash candidate created**

## Scope and non-action statement

This checkpoint was evaluated on top of the exact live-PASS S1-C1 boundary-only parent. No device was accessed. No OTA, flash, reset, live MIDI command, or persistence operation was performed. No app or FWSC child was created for S1-C2.

The requested discriminator is valid: prove two resident `0xa0` slots and deterministic Channel 10 Note On/Off selection between two distinct runtime patch objects, with no UI and no persistence. The current evidence is not sufficient to build that discriminator safely because the atomic host transaction cannot be placed in owned executable code.

## Exact parent boundary

S1-C2 may only start from the exact S1-C1 boundary-only parent:

- S1-C1 app SHA-256: `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e`
- S1-C1 FWSC SHA-256: `ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d`
- H2 parent app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- H2 parent FWSC SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`

The S1-C1 live report is a narrow PASS for the extra `0xa0` reservation through `0x01c46660`. It proves that the boundary-only heap shift did not reboot under the tested H2 workload and preserved live H2 Channel 10 owned-source behavior. It does not prove slot-1 consumption, a two-slot producer, a parser, UI, persistence, or long-duration allocator headroom.

## Admitted RAM and mapping model

The only admitted S1-C2 volatile RAM boundary is the live-PASS S1-C1 boundary:

| Address/range | Size | Purpose |
|---|---:|---|
| `0x01c46520..0x01c465bc` | `0x9c` | slot 0 runtime voice, exact H2 source range |
| `0x01c465bc` | 1 | `valid0`, exact H2 valid address |
| `0x01c465bd` | 1 | global nonblocking producer lock |
| `0x01c465be` | 1 | explicit note 0 |
| `0x01c465bf` | 1 | transaction/set state |
| `0x01c465c0..0x01c4665c` | `0x9c` | slot 1 runtime voice |
| `0x01c4665c` | 1 | `valid1` |
| `0x01c4665d` | 1 | transaction ID |
| `0x01c4665e` | 1 | explicit note 1 |
| `0x01c4665f` | 1 | reserved zero |

The mapping must be explicit and bounded. For the controlled checkpoint, only two known live-observed Channel 10 notes are admitted:

```text
note 36 -> slot 0
note 45 -> slot 1
all other notes -> H2/stock fallback
all non-Ch10 -> H2/stock fallback
```

No contiguous Pad sequence, `note - 36` arithmetic, UI grid identity, or physical Pad ordinal is admitted.

## Admitted transaction design, if executable placement later passes

The only host transaction model that satisfies all-or-none publication is the private two-message contract from the S1-C1 ingress audit. It is restated here as the S1-C2 admission requirement, not as implemented firmware.

Common envelope:

```text
F0 7D 53 4D 4B 0F 01 CMD TX FLAGS LEN_LO7 LEN_HI7 BODY CRC0 CRC1 CRC2 F7
```

Mandatory rules:

1. Private prefix is `F0 7D 53 4D 4B 0F 01`, disjoint from Yamaha `F0 43` product traffic.
2. Exact total length and terminal `F7` are checked before body indexing or mutation.
3. All data bytes other than `F0` and `F7` are `< 0x80`.
4. `TX` is `1..127`; `FLAGS` is exactly zero.
5. Packet CRC-16/CCITT-FALSE covers byte `0x53` through the final body byte, wire-encoded as three 7-bit bytes.
6. The set CRC binds `01 || TX || NOTE0 || VOICE0[156] || NOTE1 || VOICE1[156]`.
7. `NOTE0` and `NOTE1` must be bounded to `0..127` and must be distinct. For this controlled checkpoint the host must use exactly notes `36` and `45`.
8. The nonblocking H2 lock is used. Lock busy rejects without slot or state mutation.
9. `state = LOADING` hides partial data from consumers. `valid0` is written last after slot 0 copy. `valid1` and then `state = ARMED` are written last after slot 1 copy and full-set verification.
10. After `ARMED`, every producer mutation is rejected until reboot.

This design never exposes a partial two-slot set to consumers. During `LOADING`, all consumers use stock fallback. During `ARMED`, both Note On and Note Off use the same two-note selector and all other notes fall back.

Sequential official product packets are not an admitted implementation route. They would publish slot 0 through H2 before slot 1 is known complete, and current evidence does not prove all-or-none two-slot safety for such a sequence.

## Gate assessment

| Gate | Result | Evidence |
|---|---|---|
| Official-v15-only lineage | PASS | S1-C1 boundary-only manifests and live report are exact H2/official-v15 lineage. |
| S1-C1 memory boundary | PASS | Live S1-C1 boundary-only report records no reboot and preserved H2 Channel 10 behavior after the additional `0xa0` reservation. |
| Two `0xa0` resident RAM layout | PASS for boundary only | `0x01c46520..0x01c46660` is reserved and live-smoked, but slot 1 has not been consumed. |
| Note register ABI | PASS static | S1-C1 code report proves Note Off `r5 = msg[1]` and Note On `r6 = msg[1]` at the H2 hook callsites. |
| Consumer selector placement | PASS static | The current S1-C1 code audit uses the 96-byte selector ending at `0x0201e19e`, leaves a 4-byte gap before the unchanged H2 producer, explicitly rechecks `valid0` and `valid1` on matched ARMED slots, and derives pointers with official add-immediate encodings. The earlier 92-byte draft is obsolete and is not an implementation basis. The BLOCK decision remains because the selector still does not provide a private transaction parser placement. |
| Corrected fallback preservation | PASS static | The selector design restores original `r0` immediately before fallback memcpy and leaves `r1/r2` untouched, preserving H2 behavior for Ch1 and all non-Ch10. |
| Exact Note Off pairing | PASS static for immutable set | Because no mutation is allowed after `ARMED`, Note Off uses the same note-to-slot rule as Note On without generation races. This still needs live proof after a safe producer exists. |
| Atomic host transaction framing | PASS design only | The private two-message CRC/state machine is explicit and rejects malformed or partial loads before publication. |
| Atomic host transaction executable placement | **BLOCK** | No owned executable region is proven for ingress mux, exact length/CRC parser, state machine, rejection paths, and unchanged H2 delegation. |
| Firmware candidate | **BLOCK** | Creating bytes would require guessing placement or deleting required safety gates. |

## Blocking reason

S1-C2 cannot create a flash candidate yet because the consumer selector alone is not enough to prove two distinct runtime patch objects. A safe checkpoint needs a producer/parser that populates both resident slots as one guarded transaction.

The S1-C1 ingress report still blocks implementation for executable placement and exact code size. The H2 replacement area is already responsible for consumers, the H2 producer, and preservation of the stock handler tail. The remaining audited space is not proven sufficient for:

- completed-message ingress multiplexing at `0x0202d202`;
- exact private prefix and length gates;
- packet CRC and full-set CRC checks;
- nonblocking lock/state publication;
- every rejection path with no mutation;
- unchanged delegation of all non-private traffic to the H2 handler.

No second executable region is currently owned by evidence. An absence of cross-references is not ownership proof. Therefore a candidate would violate the user's stop condition for executable placement and transaction framing.

## Changed bytes and sectors

Because this is a BLOCK report, no S1-C2 binary exists.

- S1-C2 app bytes changed: `0`
- S1-C2 FWSC bytes changed: `0`
- S1-C2 changed Flash sectors: none
- S1-C2 rollback bundle: not generated because there is no child image

The exact S1-C1 boundary-only parent remains the latest live-PASS boundary. Its changed sectors versus official v15 are inherited evidence only: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`.

## Test protocol that would be required after unblocking

After executable placement and parser bytes are proven offline, the next candidate must include this deterministic no-UI, no-persistence protocol:

1. Build exact child from the S1-C1 boundary-only app hash above.
2. Generate parent rollback for every candidate-vs-S1-C1 differing 4 KiB managed Flash sector and official rollback for the full official-v15 return path.
3. Dry-run the private two-message sender and verify exact message bytes, lengths, CRCs, notes 36 and 45, and two distinct 156-byte runtime payload hashes.
4. Reject malformed length, duplicate note, out-of-range note, wrong CRC, replayed `TX`, and mutation after `ARMED` in offline protocol tests.
5. Only with later explicit device authorization: install candidate, send the two private messages, then test Ch10 note 36 and note 45 in fixed order with matching Note Offs.
6. Guard observations must include Ch1 before and after, Ch10 unknown notes falling back, non-Ch10 fallback, no reboot/hang, no stuck notes, and no persistence/SAVE behavior.

## Remaining risks

- Parser/CRC executable placement is unresolved and is the hard blocker.
- Host-visible ACK/NAK is not audited. A later live test would need a defended verification plan if no response path is added.
- Note-register evidence is static and strong, but final live proof of Note On/Off pairing awaits a safe producer.
- S1-C1 boundary live proof is narrow. It does not prove long-duration allocator headroom beyond the tested workload.
- SAVE remains H2-blocked because the stock packer body is replaced. This checkpoint does not restore official persistence.

## Validation

Run:

```sh
python3 baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/validate.py
shasum -a 256 -c baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector/SHA256SUMS
```

The validator is intentionally read-only for S1-C2 artifacts. It fails if `app.bin`, an S1-C2 FWSC/ZIP, or candidate package manifest appears in this directory.
