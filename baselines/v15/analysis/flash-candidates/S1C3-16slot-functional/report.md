# S1-C3 16-slot functional release PASS

Status: **PASS, candidate built offline**

## Exact artifacts

- App: `app.bin`, SHA-256 `679c39612b8b16d8da5ec6500b10ff6ed638b492e585c815f0a0883781118ee7`.
- FWSC: `SMK37Pro-v15-S1C3-16slot-functional.fwsc`, SHA-256 `ff56a56dc464390394a2a3a5b4b15f50f9f765a67a6cd08c95281270df7d37c4`.
- Exact OTA wrapper: `exact_ota.c`, token `INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-FF56A56D`.
- Guarded 16-packet C sender: `exact_16_packet_sender.c`, token `SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7`.
- Dry-run validator: `dry_run_validate.py`.
- Rollback: `rollback/official-v15-recovery-sectors/manifest.json`; restores official v15 flash SHA-256 `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a`.

## PASS gates

- PASS `exact-live-pass-s1c3-boundary-app`
- PASS `reviewed-96-byte-16-note-selector`
- PASS `compact-16-slot-producer`
- PASS `exact-16-packet-set`

## Packet order

Producer, selector, sender, and validator use note order: slot `0..15` -> MIDI notes `36..51`. Physical Pad permutation from `2a23cf5` is UI-only.

| Order | Slot | Note | Name | Packet SHA-256 |
|---:|---:|---:|---|---|
| 1 | 0 | 36 | BUZZ BASS | `1c9239621563722eaac0a85db411571963f9ebbd0dbbb00b21044b76b1581427` |
| 2 | 1 | 37 | Bang ????? | `afa8957005341e6144962ce3120bb1d829475714077617ea8da2c3fee4a0aa21` |
| 3 | 2 | 38 | BASSE BIEN | `8a87a409056457e61944d01bf4bbc0266414b8385c3a848125700da9e8417de3` |
| 4 | 3 | 39 | BASS-THING | `a5c086a77b4de1ce9546e747b72f79d8f6ad7b0dbd7c3b6e1665ef7edf83ff58` |
| 5 | 4 | 40 | BASS SLAP | `ffd1bcc6c7a7c5d8a1bb35f5bf7e39bf63058e62ac574e1e308ba53edc6670ff` |
| 6 | 5 | 41 | BEAMER 2 | `57136706fa633b5b47008ed2616471f72ae629d69e601e33c66daad991df94e9` |
| 7 | 6 | 42 | Onglon | `0f202d88578152ca024b3822f56a7c74c485c42996695033a4c239449d30f366` |
| 8 | 7 | 43 | SOFTSTEEL | `d4ee6f2ccfce2d0c548917bb58ead4988dc3038c2b84edaaa37f047d2e006ea2` |
| 9 | 8 | 44 | BASS-ROADS | `c8c489b72b195dfe5f373b6a860b32f0d07a29a83a9f2c070299df5af88a9cb3` |
| 10 | 9 | 45 | E.ORGAN 1 | `9c895d925a6cb79c4dff9f9f27727cce02f6dd0ed86467c994d7f459f1036258` |
| 11 | 10 | 46 | YEAAAHH | `802944d0e1a8f4e85f1a3a694e2a0dbbfe9bb55972814f11ed4c7be7575b6704` |
| 12 | 11 | 47 | HAND DRUM | `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d` |
| 13 | 12 | 48 | HAND CLAP1 | `622a06870f189b6e4582f0093255f450403d4112836f09563c0b4623c1b287cd` |
| 14 | 13 | 49 | Mooger #1 | `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` |
| 15 | 14 | 50 | Moog Solo2 | `b159db617616621759bb9990991a8214c585d1f7ecd1be0f36d53a0b71b160c8` |
| 16 | 15 | 51 | Mooger Low | `39a3e4eca1c740f719b3495f2a88c63e3b5d575a16a98c7b05fbc211fbfa4775` |

## BLOCK scope

- Device access during this build/validation: **BLOCK**; no USB/MIDI opened.
- Flash/upload/send live actions: **BLOCK unless future explicit authorization plus exact confirmation token**.
- Any hash, size, order, source commit, Pad UI-only, or rollback mismatch: **fail closed**.
