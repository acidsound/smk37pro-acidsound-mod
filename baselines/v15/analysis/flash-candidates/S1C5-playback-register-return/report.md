# S1-C5 Playback Register Return PASS

- App SHA-256: `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189`.
- FWSC SHA-256: `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`.
- Parent S1-C4 v3 app SHA-256: `c6e4cf567b2f22d7e39d3b4e0f6cae8c7fd140661e31763567b15a9fcf1e3a3d`.
- Preserved selector/producer SHA-256: `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`.
- OTA token: `INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-0A6AC1AE`.
- Sender token: `SEND-SMK37PRO-V15-S1C5-ALL-C4-7C7A8AC8-523CCBC8-14D65142-EFAB2E0D`.

PASS: exact S1-C4 v3 basis, selector returns `r0 = dest + 0x9c`, producer stores Playback Note map byte, Note Off reloads `r5` from `[r0]`, Note On reloads `r6` from `[r0]`, velocity `r5` store is preserved, Trigger source remains trigger-selected, duplicates including all C4 are represented by the 16 packet artifacts, rollback reconstructs official v15, and no device/flash path was used.
