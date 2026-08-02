# v15 R03 fixed-prefix controlled checkpoint

Date: 2026-08-02

## Decision

**Offline artifact and concurrency validation: PASS. Live flash remains gated by
an independent review of this exact candidate.**

R03 keeps R02's proven Ch1/Ch10 routing behavior but copies the first accepted
product voice into a boot-zeroed, allocator-excluded 160-byte RAM prefix. It is
one-shot per boot. Later product packets cannot replace the snapshot.

No live-functional claim is made by this report.

## Exact artifacts

- app SHA-256: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
- FWSC SHA-256: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`
- exact uploader source SHA-256: `d0c2afdff619d907a68c12abed55269e38e00b17c0248f3039e7674c8a1f7eac`
- rollback v3 ZIP SHA-256: `15dd52dbb18e9267cbc7f3ea7f1c493ba14a9501ca5c073d06f19c6f07cb8ad9`
- changed Flash sectors: `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`
- protected Flash prefix `0x0000..0x3fff`: unchanged

## Owned RAM

The official SDK `sbrk()` match at `0x0205e9da` recovered stock
`HEAP_BEGIN=0x01c46520` and `HEAP_END=0x01c7fd30` with 80 exact non-relocation
bytes. R03 changes both required bounds:

1. boot BSS zero size at `0x0200001e`: `0x3cb48 -> 0x3cbec`
2. `HEAP_BEGIN` at `0x0205e9f8`: `0x01c46520 -> 0x01c465c0`

This initializes and removes `0x01c46520..0x01c465c0` from allocator ownership:

- voice: `0x01c46520..0x01c465bc` (`0x9c` bytes)
- valid: `0x01c465bc`
- atomic lock: `0x01c465bd`
- alignment guard: `0x01c465be..0x01c465c0`

Heap capacity is reduced by exactly 160 bytes.

## Event and publish paths

- Note Off `0x0201c63e` calls wrapper `0x0201e13e`
- Note On `0x0201c67c` calls wrapper `0x0201e16e`
- Ch10 with `valid==1` uses the owned voice
- other channels or invalid state use the stock source
- accepted product-packet callers `0x0201e468` and `0x0201e49c` call producer
  `0x0201e19e`
- producer performs one atomic `testset`; lock failure returns immediately
- success rechecks valid, copies 156 bytes, sets valid last, then unlocks
- a second packet cannot replace the first snapshot until reboot
- revoked R01d early hook `0x02005f9c` remains stock

The earlier blocking-spin candidate is superseded. The pinned SDK requires
`preempt_disable()` around blocking `arch_spin_lock`, so R03 deliberately uses a
nonblocking try-lock to avoid same-core interrupt/preemption deadlock.

## SAVE behavior

SAVE is rejected before either persistent write:

- `0x02026da6`: branch directly to the stock local exit `0x02026dd4`
- `0x02026dac`: the now-unreachable later packer call is also neutralized

The latest PI32 trace decodes the branch as `goto 0x02026dd4`; the subsequent
persistent-write sequence is unreachable from this SAVE path.

## Decoder and official-toolchain evidence

A clean exact-hash Quarkslab run retained 139 rows covering all modified paths.
It decodes the try-lock `csync`, `testset`, success barrier, copy, publication,
unlock, and return. Its sole patched-instruction gap is the failure branch at
`0x0201e1ac` (`40e81b00`).

That opcode is independently established by the official PI32v2 clang object:
`40 e8 03 00 = ifeq goto forward failure path`. The builder adjusts only the
signed displacement, and the validator checks the candidate bytes and exact
return target `0x0201e1e6`. `reproduce_trylock.sh` rebuilt the object
byte-identically and verified the official objdump transcript.

## Rollback and uploader gates

Rollback v3 restores exactly the five changed sectors and requires:

- two fresh byte-identical 1 MiB forced-loader dumps
- each current changed sector to match the exact R03 target hash
- writes only inside the five audited 4 KiB sectors
- 256-byte maximum writes, CRC16-XMODEM, and readback verification
- all other sectors to remain byte-identical

The uploader accepts only package SHA `001582...a62`, firmware identity `015`,
and token `INSTALL-SMK37PRO-V15-R03-001582C0`. Its offline check accepts this
R03 package and rejects official v15.

## Live validation sequence after independent PASS

1. install exact R03 package
2. verify normal boot and identity `015`, without restoring merely because the
   macOS post-update interface claim fails
3. send exact Mooger #1 packet SHA
   `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`
4. verify Ch1 stock timbre and Note Off
5. verify Ch10 Mooger #1 timbre and Note Off
6. change Ch1 patch and verify Ch10 remains unchanged
7. send a different packet and verify the first Ch10 snapshot remains
8. reboot without staging and verify safe stock fallback
9. restage and repeat Note On/Off
10. stress UI, patch browsing, SEQ, USB reconnect, and polyphony

Do not use SAVE during the checkpoint. Any boot failure, USB loss, reboot, stuck
note, cross-channel change, or allocation symptom is a hard stop followed by the
exact rollback v3 path.

## Reproduce

```sh
baselines/v15/analysis/r03-owned-ram/atomic-publish/reproduce_trylock.sh
python3 tools/validate_v15_r03.py
build/smk37-v15-r03-ota check build/SMK37Pro-v15-R03-fixed-prefix.fwsc
```
