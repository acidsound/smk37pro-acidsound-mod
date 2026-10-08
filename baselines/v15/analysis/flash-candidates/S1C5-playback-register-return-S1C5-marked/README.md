# S1-C5 Marked Playback Note offline release

Status: **PASS, candidate built offline**.

App SHA-256 `c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5`. FWSC SHA-256 `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`. OTA token `INSTALL-SMK37PRO-V15-S1C5-MARKED-PLAYBACK-CFAFA327`.

Basis is exact S1-C4 v3 segmented-final only. Producer/selector bytes are preserved byte-for-byte. The app changes vs S1-C4 v3 are the two post-hook register reload windows and the same-length visible marker `1.10` -> `S1C5`: Note Off loads `[r0]` into `r5`, Note On loads `[r0]` into `r6`, and the stock velocity store remains intact. The included 16-packet sender artifacts deliberately map every trigger to C4 (60) to prove duplicate Playback Notes are allowed. No live actions were performed.
