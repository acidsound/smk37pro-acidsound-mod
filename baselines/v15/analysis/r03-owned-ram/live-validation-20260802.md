# v15 R03 live validation failure

Date: 2026-08-02 UTC

## Exact candidate

- reviewed code commit: `447eea1e80e3acdd55821c5c2141f6d3865ba7ac`
- independent PASS reviews: `f1e37c6`, `26cf3a1`
- app SHA-256: `3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788`
- FWSC SHA-256: `001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62`
- rollback v4 SHA-256: `ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751`
- staged Mooger #1 packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`

## Live sequence

1. Exact R03 OTA completed through normal and update USB interfaces.
2. macOS initially held interface 4 through `MIDIServer`; no restore was attempted.
3. After stopping `MIDIServer`, device identity `SMK-37 Pro`, version `015` was read.
4. Exact 220-byte USB-MIDI representation of the Mooger #1 product packet was sent successfully.
5. On the first physical Pad Ch10 input, the device rebooted immediately.
6. No further R03 test or SAVE action was performed.

R03 OTA transcript:
`logs/v15/ota-v15-r03-20260802T204838Z.log`

## Recovery

The exact official v15 package was restored by the previously validated OTA path.
Post-update macOS interface claiming returned an access error, but after releasing
`MIDIServer`, a fresh device-info read confirmed name `SMK-37 Pro`, version `015`.
No forced-loader sector rollback was needed.

Restore transcript:
`logs/v15/ota-official-v15-restore-after-r03-reboot-20260802T205007Z.log`

## Result

**LIVE FAIL.** Offline artifact integrity, PI32 decoding, atomic publication, SAVE
rejection, and rollback packaging remain validated, but they do not establish
runtime safety. The first consumer execution after a published owned-RAM voice
causes a reboot.

## Required analysis before another flash

- prove every runtime owner/reference for `0x01c46520..0x01c465c0`, not only the
  matched `sbrk()` immediate
- compare the exact R02 live-success consumer path and R03 consumer path at the
  instruction and calling-convention level
- determine whether producer publication actually completed and whether cache,
  alignment, allocator aliasing, or structure lifetime differs at first Note On
- do not issue another owned-RAM firmware until a falsifiable cause and a safer
  checkpoint are established
