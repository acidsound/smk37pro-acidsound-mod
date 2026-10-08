# S1-C5 Playback Register Return offline release

Status: **PASS, candidate built offline**.

App SHA-256 `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189`. FWSC SHA-256 `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91`. OTA token `INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-0A6AC1AE`.

Basis is exact S1-C4 v3 segmented-final only. Producer/selector bytes are preserved byte-for-byte. The only app changes vs S1-C4 v3 are the two post-hook register reload windows: Note Off loads `[r0]` into `r5`, Note On loads `[r0]` into `r6`, and the stock velocity store remains intact. The included 16-packet sender artifacts deliberately map every trigger to C4 (60) to prove duplicate Playback Notes are allowed. No live actions were performed.
