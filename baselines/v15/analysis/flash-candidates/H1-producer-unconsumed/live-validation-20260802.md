# v15 H1 producer-unconsumed live validation

Date: 2026-08-02 UTC

## Artifact

- H1 implementation commit: `edb3a2f53edfaa206e2f166f51bab7c62ee8d47b`
- Independent PASS review: `6859d5a`
- H1 package SHA-256: `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf`
- App SHA-256: `b082e8058cfacdb6e9d548dbe7033f31c0848fcf7d865859bc7c8fd969eac463`
- Rollback ZIP SHA-256: `c1db8c1d24c01bef32953d1d52f9975c45298f729ab056894decc5097e14b4d2`

## Exact discriminator

H1 combines:

- the H0 BSS/HEAP boundary;
- the R03-derived producer that copies accepted staging data to `0x01c46520` and publishes valid/lock state;
- the live-proven R02 Ch10 consumer that continues reading `0x01c37fd0`;
- no consumer reference to `0x01c46520`;
- SAVE blocked before persistent write.

## Installation and packet

The exact H1 OTA completed. The built-in post-update check initially hit macOS interface ownership, then device info confirmed:

- name: `SMK-37 Pro`
- version: `015`

The exact 163-byte Mooger product packet SHA-256 `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` was sent as 220 USB-MIDI bytes. Device info still returned version `015` after the packet, so no packet-time reboot occurred.

## Live observation

The user pressed and released a physical Pad after the packet.

- packet-time reboot: **none**
- first-Pad reboot: **none**
- user result: **이상없음**
- verdict: **H1 LIVE PASS**

## Interpretation

The H1 result shows that the following can coexist under the tested sequence:

1. H0 memory-boundary changes;
2. accepted product packet handling;
3. R03-derived producer execution;
4. a `0x9c` copy and publication into the owned range;
5. first physical Ch10 Pad processing when the consumer remains on R02 staging.

This rules against the producer write/publish side effect alone as the R03 first-Pad reboot cause. The remaining fault is isolated to the R03 consumer changes absent from H1:

- consuming the owned source at `0x01c46520`;
- the exact invalid-fallback destination clobber;
- or their branch-state interaction.

The next checkpoint is H2: use the owned source but restore `r0` before both invalid stock fallback calls. The audible result distinguishes owned publication from fallback: intended Mooger sound means owned source was consumed; stock sound means the corrected fallback ran.
