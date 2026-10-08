# v15 H2 owned-source corrected-fallback live validation

Date: 2026-08-02 UTC

## Artifact

- H2 implementation commit: `75e71805f28f46ff3afd69d34df43ebd81fa64a0`
- Independent offline PASS review commit: `682130d`
- H2 app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- H2 package SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- H2 rollback ZIP SHA-256: `c7e0f92852c78d5864a2d60d2bee86215babe7b810e0e62d3c9f2c7d5e69739c`

## Exact discriminator

H2 combines:

- the live-proven H0 BSS/HEAP boundary;
- the H1/R03-derived accepted-product-packet producer and publication into owned source `0x01c46520`;
- Ch10 Note On and Note Off consumers that select `0x01c46520` only when `valid == 1`;
- corrected stock fallback paths that restore the original memcpy destination from `r5` into `r0` immediately before both stock memcpy calls;
- SAVE blocked before persistent write.

This directly tests whether owned-source consumption is safe after correcting the exact R03 fallback destination clobber.

## Installation and packet

The exact H2 OTA completed. Its immediate built-in post-update identity check initially encountered macOS interface ownership (`LIBUSB_ERROR_ACCESS`), matching the previously observed H0/H1 host-side behavior rather than a firmware failure.

After releasing `MIDIServer`, device info confirmed:

- name: `SMK-37 Pro`
- version: `015`

The exact 163-byte Bank D, patch 14, Mooger #1 runtime product packet with SHA-256 `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` was dry-run validated and sent as 220 USB-MIDI bytes. Device info again returned version `015` after transmission, proving there was no packet-time reboot.

## Live observation

The user pressed and released a physical Pad after H2 installation and exact Mooger #1 packet staging.

- packet-time reboot: **none**
- first-Pad reboot: **none**
- Ch10 sound: **intended Bank D patch 14 Mooger #1 sound**
- Ch10 Note Off: **normal**
- user result: **모두 정상**
- verdict: **H2 LIVE PASS**

## Interpretation

The audible Mooger #1 result proves that the accepted product packet was copied and published to the owned source at `0x01c46520`, and that the first Ch10 consumer selected and consumed that source. Normal Note Off proves both channel-specific Note On and Note Off operation remained functional. The lack of reboot proves owned-source consumption itself is safe under this tested sequence.

Together with the prior live discriminators:

1. H0 passed, so the BSS/HEAP boundary change alone did not reproduce the reboot.
2. H1 passed, so producer copy/publication into `0x01c46520` alone did not reproduce the reboot while consumers stayed on R02 staging.
3. H2 passed with intended Mooger sound, proving the owned source was actually consumed safely once the fallback destination was restored.

The R03 first-Pad reboot is therefore attributed to the broken consumer fallback semantics, specifically allowing the valid-byte probe value in `r0` to reach the stock memcpy destination argument when the fallback branch was taken. H2 corrects this by restoring the original destination from `r5` immediately before both stock memcpy calls.

## Confirmed capability checkpoint

H2 establishes a live-validated v15 checkpoint with all of the following:

- Ch1 stock voice and Ch10 independently staged voice separation;
- intentional Bank D patch 14 Mooger #1 assignment to Ch10 through the exact product SysEx packet;
- working Ch10 Note On and Note Off;
- physical Pad Ch10 input without reboot;
- owned RAM source consumption after accepted packet publication;
- exact official-v15 input gates, deterministic package construction, exact uploader gate, and a five-sector rollback bundle.

This is a successful controlled checkpoint. It is not yet a production release or a proof of persistence across reboot, SAVE behavior, arbitrary patch-set switching, polyphonic stress, or long-duration stability. Those require separate validation.
