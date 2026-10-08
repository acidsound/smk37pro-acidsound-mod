# S1-C4 Playback Note v2 slotmeta PASS

- App SHA-256: `0821809021c245645280b05b61732e210fa5a76e488fae32503e6074f49156cc`.
- FWSC SHA-256: `4151fb69acf44c75e58072871818869ebc0520828b86e3b05f87d325fc821c71`.
- Combined code SHA-256: `afc8db530873cae0d6e661d9695289ebc380aa03e558754bb5c933efa0a26b95`.
- Selector SHA-256: `c6d707b591539e6c9411f6239a45f24a9a5f53b65a336eb13f0702c473b8e3e9`.
- Producer SHA-256: `a140a509862d962d2edb4c6a86a5f2419ad0c017ef607bb0d3880df37eb398f9`.
- OTA token: `INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V2-SLOTMETA-4151FB69`.
- Sender token: `SEND-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V2-SLOTMETA-EBB0A98D-182E4A54-964715E7-A16C453B`.

PASS: selector fail-closed; `r5` remains Trigger Note for non-Ch10, out-of-range, not-ARMED, and invalid-slot paths; Playback Note read is after ARMED and selected-slot-valid gates; official/current hashes, rebased branches, memcpy count reload, reset lifecycle, staging/slot restore, ARMED-last, trigger source invariant, metadata neutralization `001600160016`, velocity preservation, rollback.
