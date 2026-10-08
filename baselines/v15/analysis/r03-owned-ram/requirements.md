# R03 owned-RAM checkpoint requirements

Date: 2026-08-02 UTC

R03 may become a Flash candidate only when every required gate below is satisfied. The target is one durable-in-session Channel 10 runtime voice that survives UI patch changes and later supported product SysEx traffic without using shared staging RAM as the Note source.

## Scope

- Base only on exact official v15 app SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- Reuse the R02-live-proven Ch10 Note On/Off branch semantics only where instruction shape and ABI remain exact.
- No v12 address, M08 assumption, R01d boot hook, arbitrary SysEx fuzzing, PCM, custom UI, persistence, or 16-slot expansion in R03.

## Gate A: owned RAM

A candidate destination must document:

1. exact start/end address and required alignment;
2. at least `0x9c` voice bytes plus explicit metadata;
3. initialization/reset behavior;
4. owner and lifetime from normal boot through the full R03 session;
5. every known static reader/writer or a defensible bounded object allocation that reserves the range;
6. why DMA, stack, heap, task, USB, UI, audio, and storage workspaces cannot alias it;
7. `valid` and `generation` semantics;
8. a hard BLOCK if the only evidence is absence of decoded xrefs.

## Gate B: producer path

The producer must:

1. run only after the exact complete product packet is accepted;
2. copy exactly `0x9c` bytes from staging to owned RAM;
3. publish validity only after the copy is complete;
4. avoid all early-boot/post-init hooks;
5. preserve stock SAVE/product SysEx behavior, or explicitly reject the operation without corrupting stock state;
6. define behavior for malformed, partial, repeated, and unsupported product packets;
7. fit in a proven executable region with complete caller inventory and exact ABI.

## Gate C: consumer and generation

- Ch1 remains stock.
- Ch10 Note On and Note Off select the same owned source.
- Invalid source state falls back safely to stock or suppresses Ch10 deterministically. It must never read stale RAM.
- Publishing a new generation while a Ch10 note is active must be prohibited for R03, or active-note generation identity must be proven. The minimal R03 policy may reject reload while any Ch10 note is active.
- R03 must not change the allocator or claimed polyphony.

## Gate D: offline artifact safety

Before device access:

- exact app and FWSC SHA gates;
- byte-level changed-address manifest;
- changed 4 KiB sector inventory;
- protected prefix unchanged;
- exact target-sector rollback package made from verified official v15;
- two independent static reviews of RAM ownership and producer/consumer ABI;
- deterministic build and validator rerun;
- exact-gated uploader and wrong-package/wrong-token rejection tests.

## Gate E: live pass sequence

1. Install R03 and confirm normal boot plus identity `015` before Pad input.
2. Verify Ch1 stock behavior before loading Ch10.
3. Send one exact guarded Mooger #1 packet.
4. Verify Pad Ch10 Mooger #1 and normal Note Off.
5. Change Ch1 UI patch and verify Ch10 remains Mooger #1.
6. Send a second supported product packet or execute the exact operation chosen to test staging overwrite. Verify Ch10 owned voice is unchanged unless the R03 protocol intentionally publishes a new generation.
7. Run overlap/release stress: simultaneous Ch1/Ch10, reverse releases, repeated Pad hits, CC64, CC120 and CC123.
8. Confirm no stuck notes, no cross-channel timbre change, and no reboot.
9. Restore exact official v15 and compare the managed Flash range to the verified baseline.

Any ambiguous sound, unexpected reboot, USB loss, SAVE regression, staging-dependent behavior, or unsupported memory claim is a failure and triggers immediate official-v15 restoration or target-specific rollback.
