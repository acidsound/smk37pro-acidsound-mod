# Official PI32v2 nonblocking publish primitive

Date: 2026-08-02

## Decision

**Offline concurrency gate: PASS.** R03 uses one atomic `testset` attempt and
returns immediately if the lock is already held. It does not embed the SDK's
blocking spin loop.

This distinction is required because the pinned SDK's public `spin_lock()` calls
`preempt_disable()` before `arch_spin_lock()`. An isolated raw spin loop without
that scheduler contract could deadlock on same-core interrupt or preempting
reentry. The earlier blocking R03 implementation is superseded and must not be
flashed.

## Exact evidence

Pinned public AC79 SDK commit:
`e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`

Local checked evidence:

- `pinned-sdk-spinlock-contract.txt` records `cpu.h` and `spinlock.h` excerpts.
- `r03-trylock.c` SHA-256:
  `2e82edb679ceb2e2c4e66903ceb96310ad4eb3f18aa24dd0b802fddd1bd8b3be`
- `r03-trylock.pi32.o` SHA-256:
  `e12ebf05608c78c4ba81cbea8eded0230ddd26febb89a2412174c694744c22c6`
- `official-objdump.txt` SHA-256:
  `faaf49e7fdd8a85c6cf79246a00c48678e3a96688d452a545fbc137200c6fb04`
- `reproduce_trylock.sh` rebuilds the object with the official PI32v2 clang and
  compares it byte-for-byte.

The official object proves:

```text
csync
testset b[r0]
ifeq goto failure
csync
r0 = 1
rts
failure: r0 = 0
rts
```

R03 embeds the same `csync; testset` opcode sequence. Its displacement-adjusted
failure branch at `0x0201e1ac` is `40 e8 1b 00` and targets the producer return
at `0x0201e1e6`. Therefore a failed attempt neither spins nor unlocks another
producer's lock.

## Publication protocol

- owned voice: `0x01c46520..0x01c465bc`
- valid byte: `0x01c465bc`
- lock byte: `0x01c465bd`
- successful producer: lock, recheck valid, copy 156 bytes, set valid, unlock
- concurrent producer: immediate return
- consumers: use owned voice only when valid is 1, otherwise use stock source

`valid` stays zero for the full copy, so Note On/Off consumers cannot observe a
partially published voice.

## Remaining live gates

This proves instruction and concurrency structure, not runtime scheduling or
heap headroom. Normal boot, staging, Note On/Off, channel independence, UI,
SEQ, reconnect, and polyphony stress remain live checks. The exact rollback v4
bundle must remain available.
