# S1-C2 two-slot selector live candidate BLOCK

Date: 2026-08-02 UTC  
Status: **BLOCK, no candidate built**  
Scope: exact official v15 plus exact live-PASS S1-C1 parent only. No device access, flash, OTA, reset, app candidate, FWSC candidate, rollback bundle, or live MIDI traffic was produced.

## Decision

The requested actual official-v15-only S1-C2 candidate is blocked by the critical producer ingress invariant.

The producer must accept private publication only when **both** conditions are true before any lock/state/slot mutation:

1. `LR/rets == 0x0201e46c`, the exact direct route return address after the accepted 163-byte direct product packet callsite.
2. `r9 == 0x000000a3`, the exact direct complete-message length.

Commit `d9a97d9` proves that LR/rets is the route discriminator and that the first H2/S1-C1 owned mutation is the later `testset b[0x01c465bd]`. Commit `66d301d` proves the enlarged two-slot producer body fits the byte range at 134 bytes, but that producer explicitly omits the route/length gate. The current exact PI32 evidence set in this repo does not contain a validated instruction sequence to read or compare the special `rets` register before `testset`. A candidate that checks only `r9 == 0xa3` would violate the required `LR AND r9` gate, so no app/FWSC candidate was built.

## What was validated offline

- Exact live-PASS S1-C1 parent app: `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e`.
- Existing 96-byte selector design: `0x0201e13e..0x0201e19e`, SHA-256 `adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35`.
- Existing extended producer evidence: 134 bytes at `0x0201e1a2..0x0201e228`, SHA-256 `d989d7e852102126ae8dc2e4025b2717808e4f808bc2bf7885cb9c77ddeb05f7`.
- Requested producer owned range remains `0x0201e1a2..0x0201e254` (178 bytes), preserving official handler `0x0201e254` and caller reload behavior.
- The required state machine was modeled: first exact direct packet publishes slot0/note36 and enters LOADING, second exact direct packet publishes slot1/note45 then ARMED last, later exact packets reject, segmented and all other callers reject without mutation.

## Dry-run sender plan, not a sender

The blocked dry-run plan pins two distinct official factory-derived 156-byte runtime objects into exact 163-byte direct product packet hashes. It is not allowed to send traffic.

| Order | Slot | Fixed note | Factory source, 1-based | Runtime SHA-256 | Packet SHA-256 |
|---:|---:|---:|---|---|---|
| 1 | 0 | 36 | Bank D (4), patch 14, Mooger #1 | `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` | `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` |
| 2 | 1 | 45 | Bank D (4), patch 12, HAND DRUM | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` | `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d` |

Confirmation token recorded for review only: `BLOCKED-S1C2-LR-GATE-NOT-PROVEN`.

## Blocker to clear before a candidate

Produce exact PI32v2 bytes, independently decoded and preferably compiler-backed, for one of these before any `testset` or state/slot write:

- move/copy `rets` into a GPR and compare against `0x0201e46c`, or
- compare `rets` directly against `0x0201e46c`, or
- otherwise prove an exact route discriminator equivalent to `LR/rets == 0x0201e46c` without mutating lock/state/slots.

Then rebuild producer, verify `LR == 0x0201e46c && r9 == 0xa3` before mutation, reject segmented `LR == 0x0201e4a0`, preserve `0x0201e254`, build app/FWSC/rollback, and rerun offline tests.
