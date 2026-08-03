# S1-C3 offline Bank D 1..16 exact packet set

Status: **PASS** for the offline exact packet set. **BLOCK** for device access, firmware/FWSC build, flash, reset, MIDI transport open, or live send.

## Scope

This directory contains an offline diagnostic packet set built from official v15 factory Bank D patches 1..16. It uses note-ordered slots `0..15` for MIDI notes `36..51`.

No device access, firmware candidate, FWSC package, flash, reset, MIDI transport, or live send was performed or produced.

## Derivation

- Tool: `tools/build_v15_patch_set.py`, SHA-256 `69fe187836d491362fe56000582ce5dc33cce4f8ca10292bbb9b58c699e6802f`.
- DX7 unpack helper: `tools/dx7_vmem.py`, SHA-256 `c833bbd39dc4cd5df2c90c0e444beef2e36edd78ab88aaf1129656c3253392bf`.
- SHA-gated dump used locally: `baselines/v15/device-dumps/v15-clean-baseline-a.bin`.
- Official v15 dump SHA-256: `1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b`.
- Direct Yamaha product SysEx shape: `F0 43 00 00 01 1B` + 156-byte runtime object + `F7`.
- Each packet is exactly 163 bytes. The sequential stream is `2608` bytes.

## Pinned slot order, names, and hashes

| Slot | Note | Bank | Patch, 1-based | Name | Runtime SHA-256 | Packet SHA-256 |
|---:|---:|---|---:|---|---|---|
| 0 | 36 | D | 1 | BUZZ BASS | `e2beb705a28e83940b2708f8ba0976e8c093ca12f45d0045f290b1589760d76b` | `1c9239621563722eaac0a85db411571963f9ebbd0dbbb00b21044b76b1581427` |
| 1 | 37 | D | 2 | Bang ????? | `5dab954752769609d64dd162360182138c8bc399030b88cf8d61b76fb7208f97` | `afa8957005341e6144962ce3120bb1d829475714077617ea8da2c3fee4a0aa21` |
| 2 | 38 | D | 3 | BASSE BIEN | `3e140cc8613ec555fcae2109d216c5e838d3193b305352992dc4062556af8b60` | `8a87a409056457e61944d01bf4bbc0266414b8385c3a848125700da9e8417de3` |
| 3 | 39 | D | 4 | BASS-THING | `5f60dc8f39b4ec43dc4368050701550ca56581948451f0c8083ace61e9d98dc7` | `a5c086a77b4de1ce9546e747b72f79d8f6ad7b0dbd7c3b6e1665ef7edf83ff58` |
| 4 | 40 | D | 5 | BASS SLAP | `5da8be28b3468a534aa488b02d47522df36e6b5b02b14f992bcb869fc4bb9ecc` | `ffd1bcc6c7a7c5d8a1bb35f5bf7e39bf63058e62ac574e1e308ba53edc6670ff` |
| 5 | 41 | D | 6 | BEAMER 2 | `d38dfdac699a0fadbf7c99c98103a5f2bf7297a6746e94525d7eca3472223d40` | `57136706fa633b5b47008ed2616471f72ae629d69e601e33c66daad991df94e9` |
| 6 | 42 | D | 7 | Onglon | `7727f3b7856a73b3c32bca1b6e15ed74672d6dc97e00641761ef14237b0d8a44` | `0f202d88578152ca024b3822f56a7c74c485c42996695033a4c239449d30f366` |
| 7 | 43 | D | 8 | SOFTSTEEL | `8b0463a7b52857203105525af3456636b3a427e5db5f1eb75ea687bd6677bbbb` | `d4ee6f2ccfce2d0c548917bb58ead4988dc3038c2b84edaaa37f047d2e006ea2` |
| 8 | 44 | D | 9 | BASS-ROADS | `1602db2d94930482f631d087bf4b645d626f12b88da1e8deee21202210b7177c` | `c8c489b72b195dfe5f373b6a860b32f0d07a29a83a9f2c070299df5af88a9cb3` |
| 9 | 45 | D | 10 | E.ORGAN 1 | `33dd55bbc6ebc2361260b9a581203f682b49388f9e4284b95de15136b630a178` | `9c895d925a6cb79c4dff9f9f27727cce02f6dd0ed86467c994d7f459f1036258` |
| 10 | 46 | D | 11 | YEAAAHH | `9c5abf35d8c039be1c8603f4fb5296f7b7d3e28503b330b5d3dd33c1b5a6dff9` | `802944d0e1a8f4e85f1a3a694e2a0dbbfe9bb55972814f11ed4c7be7575b6704` |
| 11 | 47 | D | 12 | HAND DRUM | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` | `c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d` |
| 12 | 48 | D | 13 | HAND CLAP1 | `452efa8d41eecc7a5c57f1dfdecc072e1bc4266020cfe824edbc1b87415c2e38` | `622a06870f189b6e4582f0093255f450403d4112836f09563c0b4623c1b287cd` |
| 13 | 49 | D | 14 | Mooger #1 | `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` | `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27` |
| 14 | 50 | D | 15 | Moog Solo2 | `cfa79fc5ba72bcd50b0465a116e109da90ca5dcdcdc40bc89cdad218ee468417` | `b159db617616621759bb9990991a8214c585d1f7ecd1be0f36d53a0b71b160c8` |
| 15 | 51 | D | 16 | Mooger Low | `a28849a192d5dad000622c8aa749baa6508ad73e2c1cc6659b33a0419b6a0e88` | `39a3e4eca1c740f719b3495f2a88c63e3b5d575a16a98c7b05fbc211fbfa4775` |

## Physical Pad permutation from commit `2a23cf5`

The current profile's physical Pad 1..16 order is not note order. The permutation is pinned from commit `2a23cf5`:

```text
Pad 1..16 -> note-ordered slot 4,5,6,7,12,13,14,15,0,1,2,3,8,9,10,11
```

| Physical Pad, 1-based | MIDI note | Note-ordered slot | Slot patch name |
|---:|---:|---:|---|
| 1 | 40 | 4 | BASS SLAP |
| 2 | 41 | 5 | BEAMER 2 |
| 3 | 42 | 6 | Onglon |
| 4 | 43 | 7 | SOFTSTEEL |
| 5 | 48 | 12 | HAND CLAP1 |
| 6 | 49 | 13 | Mooger #1 |
| 7 | 50 | 14 | Moog Solo2 |
| 8 | 51 | 15 | Mooger Low |
| 9 | 36 | 0 | BUZZ BASS |
| 10 | 37 | 1 | Bang ????? |
| 11 | 38 | 2 | BASSE BIEN |
| 12 | 39 | 3 | BASS-THING |
| 13 | 44 | 8 | BASS-ROADS |
| 14 | 45 | 9 | E.ORGAN 1 |
| 15 | 46 | 10 | YEAAAHH |
| 16 | 47 | 11 | HAND DRUM |

## Sender manifest

`sender-manifest.json` is a dry-run-only sender manifest. It pins the exact 16 packet files, order, lengths, hashes, and USB-MIDI packetization facts. It explicitly sets `send_enabled: false` and records device/live/firmware actions as blocked.

## Validation

Run:

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16/validate.py
```

Expected result includes:

```text
PASS offline exact Bank D 1..16 packet set
BLOCK device access, firmware/FWSC, flash/reset, MIDI transport, live send
```
