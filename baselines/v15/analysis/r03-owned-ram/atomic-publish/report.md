# Official PI32v2 atomic publish primitive

Date: 2026-08-02

## Result

The R03 producer concurrency blocker is addressed with the exact PI32v2 atomic
byte spinlock primitive documented by the pinned public AC79 SDK and reproduced
with the official Jieli PI32v2 clang toolchain.

The producer lock byte is `0x01c465bd`, inside the allocator-excluded R03 prefix.
Consumers do not need the lock because `valid @ 0x01c465bc` remains zero until
the entire 156-byte voice copy finishes. Concurrent consumers therefore fall
back to the stock source rather than reading a partial snapshot.

## SDK evidence

Pinned SDK commit: `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`

`include_lib/driver/cpu/wl82/asm/cpu.h` defines `arch_spin_lock` as:

```c
csync
1: testset b[lock]
ifeq goto 1b
csync
```

and unlock as a synchronized zero store. `testset b[...]` is the architecture's
atomic byte test-and-set operation, so two producer invocations cannot both
enter the critical section.

## Official-toolchain reproduction

- source: `r03-spinlock.c`
- source SHA-256: `9a19e5b85b37c1b7c6e0efafbf86e6847791d4e38db1172fee5cb1e1be8b4b9b`
- object: `r03-spinlock.pi32.o`
- object SHA-256: `754ae849bed042a05294bfa9d5cab2e2b7045b107e91da1cbee1b0e80adfdd32`
- official toolchain archive SHA-256: `f686586bcfb45e0f0bb27fd2b39c7a7f313cb4f0e88a66a14da621ffa8225958`
- `pi32v2/bin/clang` SHA-256: `42b94f9e11140b0fcab8f807b2872ad245b8eeca03a2d792f8706c5a3a35d34c`

Official objdump output:

```text
r03_lock:
  0: 20 00              csync
  2: b0 00              testset b[r0]
  4: 40 e8 fd ff        ifeq goto -6 <r03_lock+0x2>
  8: 20 00              csync
  a: 80 00              rts

r03_unlock:
  c: 20 00              csync
  e: 41 20              r1 = 0
 10: 89 40              b[r0+0] = r1
 12: 20 00              csync
 14: 80 00              rts
```

R03 embeds these exact 12-byte and 10-byte bodies and calls them around the
`valid` test, voice copy, and final `valid=1` publication.

## Remaining constraints

- The lock serializes producer invocations only. This is intentional.
- A producer fault inside the critical section can leave the lock set until
  reboot. Such a fault is already a live hard stop.
- SAVE remains disabled and heap capacity remains reduced by 160 bytes.
- Live heap-pressure and functional validation are still required.
