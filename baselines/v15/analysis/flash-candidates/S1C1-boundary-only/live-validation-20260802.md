# v15 S1-C1 boundary-only live validation

Date: 2026-08-02 UTC

## Result

**LIVE PASS**

The additional `0xa0` BSS reservation and matching heap-boundary shift did not cause a reboot and preserved the live-proven H2 Channel 10 owned-source behavior.

## Exact artifacts

- Candidate app SHA-256: `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e`
- Candidate FWSC SHA-256: `ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d`
- H2 parent app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- Rollback ZIP SHA-256: `9cf3a7ec8a24e09d2d2bef9d55d73363c01f8461a3800ad37ba30abb72d332f1`
- Mooger #1 runtime packet SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`

The exact H2-relative app delta was four bytes, limited to the paired BSS-size and `HEAP_BEGIN` instruction operands. The H2 producer, consumer, fallback, and code-cave bytes remained identical.

## Installation and host verification

The exact S1-C1 FWSC passed the dedicated uploader check and completed both OTA stages. The uploader's immediate identity check encountered the known macOS CoreMIDI interface-ownership race (`LIBUSB_ERROR_ACCESS`). After releasing `MIDIServer`, `device-info` returned:

- name: `SMK-37 Pro`
- version: `015`

The exact 163-byte Mooger #1 runtime packet passed dry-run validation, was sent as 220 USB-MIDI bytes, and `device-info` again returned version `015` without a packet-time reboot.

## Physical live observation

The user pressed and released physical Pads and confirmed all requested observations:

1. no reboot;
2. Channel 10 played the intended Mooger #1 sound;
3. Note Off operated normally;
4. Channel 1 and Channel 10 remained timbrally separated.

User report: `모두 정상`.

## Interpretation

This is positive live evidence that the second `0xa0` reservation boundary itself is viable under the tested H2 workload. It closes the narrow S1-C1 memory-boundary discriminator and permits work to proceed to a guarded two-slot selector checkpoint.

It does not yet prove arbitrary long-duration allocator headroom, 16-slot residency, persistent storage ownership, UI event routing, or a complete per-note patch-set implementation. Those remain separate gated checkpoints.
