# S1-C2 protocol alternatives: can exact official product SysEx replace a new parser?

Date: 2026-08-02 UTC  
Status: **BLOCK for a no-new-parser S1-C2 candidate**  
Scope: read-only analysis. I did not build firmware, access a device, flash, run OTA, or send traffic.

## Decision

S1-C2 **cannot safely avoid a new parser entirely** using the currently proven official v15 complete-message handler plus H2 producer ABI.

A two-packet official-product scheme can be made atomic on paper by treating the first accepted product packet as an invisible shadow copy and the second as activation, but the current firmware evidence does not let that be a safe implementation. The producer reached from the official product paths receives only a staging pointer, not the original complete-message length, route, transaction, note, or slot identity. The direct official product path also does not prove `r9 == 0xa3` before producer entry. Therefore sequential official product packets remain **BLOCK** unless and until exact firmware-side evidence proves partial, malformed, duplicate, replayed, or wrong-route states cannot become consumable.

This preserves the fb2095e S1-C2 BLOCK conclusion for firmware creation, but narrows the reason: the no-parser alternative removes the private-prefix/CRC parser, yet still needs an exact stateful accepted-product producer plus route/length discrimination that is not currently proven and may not fit the owned cave.

## Evidence read

Pinned source evidence is SHA-recorded in `evidence.json`. The key facts used here are:

- Prior S1-C2 BLOCK: no flash candidate was created because atomic host transaction executable placement was unproved.
- S1-C1 ingress: the private two-message design hides partial state with `LOADING`, publishes `ARMED` last, and blocks because parser/CRC placement is not owned.
- Architecture: first implementation is load-once and immutable until reboot, avoiding Note On/Off generation races.
- Runtime-source lifecycle: stock consumption uses the current runtime snapshot and the `0x9c` Note On/Off copy, not transient SysEx staging as durable storage.
- SysEx staging lifecycle and R02: `0x01c37fd0` is official transient staging and is safe only under strict no-intervening-SysEx conditions.
- H1/H2 live evidence: accepted official product packet producer execution, copy/publication into `0x01c46520`, and Ch10 consumption are live-proven when H2's corrected fallback restores `r0`.

## Exact relevant hooks and addresses

| Item | Exact evidence |
|---|---|
| Completed-message callsite | `0x0202d202` calls `0x0201e254` with `r0 = assembled message`, `r1 = accumulated length` |
| Official handler entry | `0x0201e254` |
| Direct product header gates | `0x0201e410..0x0201e444` require `F0 43 00 00 01 1B` |
| Direct product stage | `0x0201e448` computes `0x01c37030 + 0x0fa0 = 0x01c37fd0` |
| Direct product copy | `0x0201e456` copies `message+6` to stage with length `r9 - 6` |
| Direct product final gate | `0x0201e462` checks `message[r9-1] == F7`, after the copy |
| Direct product H2 producer call | `0x0201e468` |
| Direct product reload | `0x0201e46c` calls `0x02005660` |
| Segmented final gates | `0x0201e480` final `F7`, `0x0201e484` accumulated length `0x9e` |
| Segmented final H2 producer call | `0x0201e49c` |
| Segmented final reload | `0x0201e4a0` calls `0x02005660` |
| H2 producer | `0x0201e1a2..0x0201e1ec`, called with `r0 = accepted staging pointer` |
| H2 lock and slot0 | lock `0x01c465bd`, voice `0x01c46520..0x01c465bc`, valid `0x01c465bc` |
| S1-C1 two-slot RAM | `0x01c46520..0x01c46660` |
| Note Off hook | `0x0201c63e`, note is `r5 = msg[1]` |
| Note On hook | `0x0201c67c`, note is `r6 = msg[1]` |

## The strongest no-parser design, in C-level pseudocode

This is the best possible shape if fixed notes `36` and `45` are accepted for a narrow discriminator and official product packets are used only as 156-byte voice carriers:

```c
#define SLOT0       ((volatile uint8_t *)0x01c46520)
#define VALID0      (*(volatile uint8_t *)0x01c465bc)
#define LOCK        (*(volatile uint8_t *)0x01c465bd)
#define NOTE0       (*(volatile uint8_t *)0x01c465be)
#define STATE       (*(volatile uint8_t *)0x01c465bf)
#define SLOT1       ((volatile uint8_t *)0x01c465c0)
#define VALID1      (*(volatile uint8_t *)0x01c4665c)
#define TX          (*(volatile uint8_t *)0x01c4665d)  /* sequence counter if any */
#define NOTE1       (*(volatile uint8_t *)0x01c4665e)

#define EMPTY       0
#define LOADING     1
#define ARMED       2

/* Hypothetical replacement for H2 producer at 0x0201e1a2.
 * Entry ABI proven for H2 product callsites: r0 == official staging pointer.
 * Missing ABI: no exact original message length, no caller route, no note, no tx.
 */
void product_producer_two_slot_no_parser(uint8_t *stage)
{
    if (!try_lock_nonblocking(&LOCK))
        return;

    csync();

    if (STATE == EMPTY && VALID0 == 0 && VALID1 == 0) {
        STATE = LOADING;          /* hide slot0 before copy or valid publication */
        csync();
        NOTE0 = 36;               /* fixed discriminator note, not host-selected */
        memcpy((void *)SLOT0, stage, 0x9c);
        csync();
        VALID0 = 1;               /* not consumable because STATE == LOADING */
        unlock(&LOCK);
        return;
    }

    if (STATE == LOADING && VALID0 == 1 && VALID1 == 0) {
        NOTE1 = 45;               /* fixed discriminator note, not host-selected */
        memcpy((void *)SLOT1, stage, 0x9c);
        csync();
        VALID1 = 1;
        csync();
        STATE = ARMED;            /* activation-last token */
        unlock(&LOCK);
        return;
    }

    /* ARMED, busy-looking, replay, duplicate, or inconsistent state: no mutation. */
    unlock(&LOCK);
}

void ch10_selector(uint8_t channel, uint8_t note,
                   void *original_dst, const void *stock_src)
{
    const void *src = stock_src;

    if (channel == 9 && STATE == ARMED) {
        if (note == NOTE0 && VALID0 == 1)
            src = (const void *)SLOT0;
        else if (note == NOTE1 && VALID1 == 1)
            src = (const void *)SLOT1;
    }

    /* H2 invariant: every fallback/owned copy restores original destination. */
    memcpy(original_dst, src, 0x9c);
}
```

The atomicity idea is sound only for interrupted host sequencing:

1. Boot/BSS zero gives `EMPTY`, `valid0 = 0`, `valid1 = 0`.
2. First accepted packet writes `LOADING` before copying slot 0.
3. Consumers fall back during `LOADING`, so stopping after packet 1 does not expose slot 0.
4. Second accepted packet copies slot 1, writes `valid1`, then writes `ARMED` last.
5. After `ARMED`, both Note On and Note Off use the same immutable note-to-slot rule.

However, this pseudocode is **not viable as firmware evidence** because the missing official-handler invariants below are safety blockers.

## Why Sequential official product packets are still BLOCK

### 1. The direct official product path lacks an exact-length proof at producer entry

The direct path copies `r9 - 6` bytes to `0x01c37fd0` at `0x0201e456`, then checks only the final byte for `F7` at `0x0201e462`, then calls the replacement producer at `0x0201e468`. The S1-C1 ingress audit explicitly warned that this path does not prove `r9 == 0xa3`.

H2 was live-proven with one exact 163-byte host packet. That proves the exact packet can work. It does not prove a two-slot production rule where any accepted direct product-like message may become one half of an atomic set.

For a strict S1-C2 scheme, the firmware must reject a short, oversized, stale-stage, duplicate, or replayed packet before it can influence an eventual `ARMED` set. The H2 producer ABI at `0x0201e1a2` has only `r0 = stage`, so it cannot re-check the original direct message length without additional hook/parser work.

### 2. Official product SysEx carries no slot or note identity

The exact live product packet is:

```text
F0 43 00 00 01 1B || runtime_voice[156] || F7
```

Those bytes identify a Yamaha single-voice product payload. They do not say “slot 0”, “slot 1”, note `36`, note `45`, transaction ID, set checksum, or activation token. Without a private parser, the only available slot selector is implicit call count. That makes fixed notes possible for a narrow discriminator, but not arbitrary host-selected notes, and it does not bind packet 2 to packet 1.

Using bytes inside the 156-byte runtime voice as token bytes would corrupt or constrain the voice payload unless a new payload parser/encoder proves those bytes are semantically safe. No such proof exists.

### 3. Host-side sequencing is not a firmware invariant

A host script can promise “send exact packet A, then exact packet B, then play notes”. That is not enough for firmware admission. R02 was only a constrained live checkpoint because any intervening SysEx could overwrite transient staging. The two-slot design must be stricter: any partial or interrupted sequence may leave private RAM changed, but cannot leave it consumable.

`LOADING` plus `ARMED` last handles “only packet A arrived”. It does not handle “packet A was short but final-F7 accepted”, “packet B was stale/duplicate”, “direct packet took the wrong route”, or “a segmented final packet and direct packet are mixed” because the producer cannot identify those conditions from the proven ABI.

### 4. The existing handler targets staging, not slots

The official handler writes to `0x01c37fd0`, a transient staging workspace. It does not natively target `0x01c46520` or `0x01c465c0`. H2's producer then copies from staging to slot 0. Extending that producer to choose slot 0 or slot 1 is new stateful producer code, not “existing official handler safely targeting each slot”.

The segmented final path has a better length gate (`offset + len == 0x9e`), but current evidence still leaves both product caller routes active. A segmented-only no-parser discriminator would first need to prove the direct route cannot publish private state, or that the producer can reliably identify caller route/length. That exact ABI proof is not present.

### 5. Code placement remains unproved even without a parser

The S1-C1 selector audit uses `0x0201e13e..0x0201e19e` and leaves the H2 producer at `0x0201e1a2..0x0201e1ec`. The gap before the producer is 4 bytes. Replacing H2's 74-byte producer with a two-slot state machine needs, at minimum:

- nonblocking `testset` and unlock-on-every-reject path;
- `EMPTY`/`LOADING`/`ARMED` branches;
- two destination choices;
- two 156-byte copies through `0x02048cce` or equivalent;
- fixed-note stores or another note source;
- `valid0`, `valid1`, and `ARMED` store ordering;
- rejection after `ARMED`;
- preservation of the official reload calls after producer return.

No exact byte budget, instruction encoding, or branch reach proof exists for that producer. This is smaller than the full private parser, but it is not zero code and it is not currently owned.

## Evaluation of requested mechanisms

| Mechanism | Finding |
|---|---|
| Staging shadow copies | Useful only if consumers ignore them until `ARMED`. Does not validate exact packet shape or bind both voices. |
| Activation-last token | Required. `STATE = ARMED` last prevents consumption after one accepted packet or mid-copy interrupt. It cannot repair missing length/route/slot identity. |
| Generation counters | Not needed for load-once immutable S1-C2. They do not validate packet exactness and cannot bind two official product messages without more protocol. |
| Double buffering | BLOCK under current RAM. Active plus inactive two-slot sets need at least another `0x140` bytes and still need an ingress selector. |
| Host-side sequencing | BLOCK as sole guarantee. It can be a test harness rule, not the safety invariant. Firmware must make interrupted or malformed sequences non-consumable. |
| Interrupt/lock behavior | H2's nonblocking lock is the correct producer primitive. Consumers should not lock. Store ordering works only if `LOADING` is visible before copies and `ARMED` is visible after both valid bytes. Exact implementation bytes are unproved. |
| Existing official complete-message handler targeting each slot | BLOCK. It targets `0x01c37fd0` staging. Slot choice would be in a new producer state machine, and the current producer ABI lacks original length/route/note identity. |

## Precise invariants for any future no-parser discriminator

A future no-parser discriminator must prove all of these before firmware bytes are created:

1. The first private publication state visible to consumers is `LOADING`, not `valid0`.
2. While `STATE != ARMED`, Ch10 consumers never read slot 0 or slot 1 for the two-slot scheme.
3. `valid0` is written only after a complete 156-byte slot0 copy.
4. `valid1` is written only after a complete 156-byte slot1 copy.
5. `STATE = ARMED` is written last, after a barrier/order primitive, and only after both slots are complete.
6. After `ARMED`, every later accepted product producer entry rejects without mutation until reboot, unless a separately proven inactive double buffer exists.
7. The firmware can distinguish exact admitted product packets from short, oversized, stale, duplicate, replayed, wrong-route, or mixed direct/segmented traffic before any eventual `ARMED` state.
8. Note On and Note Off use the same immutable note-to-slot map.
9. Every fallback restores the H2-correct original memcpy destination and preserves the stock source/count ABI.
10. Official reload calls at `0x0201e46c` and `0x0201e4a0` remain safe under the new producer return behavior.

Current evidence satisfies the publication-order concept only. It does not satisfy invariant 7 or the exact code-placement proof.

## Smallest discriminator

The smallest next discriminator is **offline only** and does not require a firmware build, device, flash, OTA, or traffic:

1. At `0x0201e468` and `0x0201e49c`, prove whether a replacement producer can know exact accepted payload length and caller route from registers or stable official object state.
2. If not, prove direct `0x0201e468` can be neutralized for private publication while segmented `0x0201e49c` remains exact and H2-compatible.
3. Prove how slot identity is obtained without corrupting the 156-byte runtime voice. For a narrow discriminator, firmware constants `note0 = 36`, `note1 = 45`, first accepted exact packet to slot0, second to slot1 are acceptable, but must be explicitly non-general.
4. Assemble or otherwise byte-prove the no-parser producer state machine, including every branch, call, unlock path, and overwritten parent byte, inside owned executable space.

If step 1 fails and step 2 is not proven, the no-parser route is impossible under the current safety rules. If step 4 does not fit, the route remains blocked even with segmented-only packet acceptance.

## Final blocker statement

No S1-C2 firmware candidate should be built from sequential official product packets at this time. The existing official handler plus H2 producer semantics prove a one-slot live checkpoint, not a two-slot atomic set. Without new validation logic at or before the product producer, the second accepted packet can activate bytes whose exact origin, length, route, and relationship to the first packet are not firmware-proven. That violates the strict rule that sequential packets are BLOCK unless partial or interrupted states cannot be consumed.
