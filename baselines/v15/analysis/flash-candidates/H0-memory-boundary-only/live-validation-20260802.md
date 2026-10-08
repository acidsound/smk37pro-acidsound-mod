# v15 H0 memory-boundary-only live validation

Date: 2026-08-02 UTC

## Artifact

- Reviewed release commit: `2618f516e7ba5aa93db172449a4f78bce7c9fc67`
- Independent PASS review: `d7a741c`
- H0 package SHA-256: `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`
- App SHA-256: `ab2d4d210605f20e35b96a8471c9f2e1102c24e18f3b062d6eabd4970f9794ce`
- Rollback ZIP SHA-256: `05e22531e82b9b3a15338e09d1fde274e18f4697a17c60e00fcba063c7ea60ed`

## Exact scope

Official v15 app with only these two byte-level instruction changes:

- BSS size instruction at `0x0200001e`: `c2ff48cb0300` -> `c2ffeccb0300`
- HEAP_BEGIN instruction at `0x0205e9f8`: `c5ff2065c401` -> `c5ffc065c401`

All Note On/Off, product, SAVE, code-cave, UI, and packer bytes remained official v15.

## Installation

The exact H0 uploader completed OTA. Its built-in post-update identity check initially failed because macOS held interface 4 (`LIBUSB_ERROR_ACCESS`). After releasing `MIDIServer`, device info returned:

- name: `SMK-37 Pro`
- version: `015`

## Live observation

Without sending a product SysEx packet and without SAVE, the user pressed and released a physical Pad.

- Reboot: **none**
- Result: **H0 LIVE PASS for the first-stock-Pad reboot discriminator**

## Interpretation

The two R03 memory-boundary changes alone do not reproduce the first-Pad reboot. This falsifies the simple claim that shifting `HEAP_BEGIN` by `0xa0` or extending BSS alone necessarily causes the observed immediate reboot under this test.

It does not prove complete heap ownership or long-duration allocator headroom. The R03 failure remains narrowed to changes absent from H0, especially:

1. the exact invalid-fallback destination clobber in the R03 Note On/Off wrappers when `valid != 1`;
2. producer/publication behavior;
3. consuming the copied owned voice at `0x01c46520`;
4. their interaction under the first Ch10 event.

The next discriminator is H1: keep the H0 memory boundary and execute the producer, but keep Ch10 consumers on the already live-proven R02 staging source so the newly owned source is written but not consumed.
