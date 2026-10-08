# S1-C5 Marked Playback Note PASS

- App SHA-256: `c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5`.
- FWSC SHA-256: `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`.
- Parent S1-C4 v3 app SHA-256: `c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d`.
- Preserved selector/producer SHA-256: `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`.
- OTA token: `INSTALL-SMK37PRO-V15-S1C5-MARKED-PLAYBACK-CFAFA327`.
- Sender token: `SEND-SMK37PRO-V15-S1C5-ALL-C4-7C7A8AC8-523CCBC8-14D65142-EFAB2E0D`.

PASS: exact S1-C4 v3 basis, selector returns `r0 = dest + 0x9c`, producer stores Playback Note map byte, Note Off reloads `r5` from `[r0]`, Note On reloads `r6` from `[r0]`, velocity `r5` store is preserved, Trigger source remains trigger-selected, duplicates including all C4 are represented by the 16 packet artifacts, rollback reconstructs official v15, and no device/flash path was used.
