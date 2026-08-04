# S1-C5 live validation checkpoint

Date: 2026-08-04

## Installed artifact

- Candidate: `S1C5-playback-register-return`
- App SHA-256: `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189`
- FWSC SHA-256: `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`
- OTA confirmation: `INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-0A6AC1AE`
- OTA transcript: `logs/v15/ota-v15-s1c5-playback-register-return-20260804.log`

The OTA transport completed both update stages. Its final process status was nonzero because interface 4 could not be claimed during post-update identity verification. This is not recorded as an identity-verification PASS.

## Offline release gates

- Exact candidate validation: PASS
- Deterministic app and FWSC rebuild: PASS
- Parent-relative change scope: exactly four app bytes
- PI32 selector return and Note On/Off register ABI: PASS
- Repeated Playback Note values without trigger-slot collapse: PASS
- Protected regions and official-v15 rollback reconstruction: PASS
- Clean-checkout exact OTA compile and accept/reject matrix: PASS
- Independent release reviews: PASS (`3495934`, `257b629`)

## User-observed live result

The user manually tested the installed firmware with the Patch Set Editor and reported the result as **perfect**.

Confirmed behavior:

1. Physical Trigger Notes remain assigned to their original Pad identities.
2. Sixteen Ch10 resident patch slots remain independently selected.
3. Per-Pad Playback Note values alter sounding pitch without changing Trigger Note identity.
4. Repeated Playback Notes, including an all-C4 set, no longer collapse Ch10 behavior to the Ch1 fallback.
5. Mixed Playback Note assignments work.
6. Note On and Note Off behavior is usable without the prior stuck-note failure.

## Checkpoint status

**S1-C5 is the current known-good live baseline for subsequent work.**

Patch Set data and Playback Note mapping are still volatile RAM state. A reboot or power cycle requires retransmission. Persistent device-side storage is intentionally deferred to the next milestone and must not modify this checkpoint in place.
