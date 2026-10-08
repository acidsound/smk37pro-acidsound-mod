# S1-C6 Reset Signature Isolation PASS

- App SHA-256: `312790c080f6fcead69eccd84edf2c608ef3fa7e772455d781ab086dafed44b1`.
- FWSC SHA-256: `fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886`.
- Parent S1-C5 marked app SHA-256: `c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5`.
- Preserved core SHA-256: `1f5ac42f0fd34c725193d308e2a608e1a0f8a9c70c60c29f58d38bcd68804744`.
- Reset signature: `0x64 0x65` at wire bytes 6..7 (structurally impossible in any DX7 voice).
- OTA token: `INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93`.
- Sender token: `SEND-SMK37PRO-V15-S1C6-RESET-SIG-F0F93762-7C7A8AC8-523CCBC8-14D65142`.

PASS: exact S1-C5 marked basis, impossible-signature reset wrapper in place, reset packet not loaded as a voice, callsites and core unchanged, 17-packet transport (1 reset + 16 all-C4 voices), bundled-voice collision scan 0 hits, rollback reconstructs official v15, and no device/flash path was used.
