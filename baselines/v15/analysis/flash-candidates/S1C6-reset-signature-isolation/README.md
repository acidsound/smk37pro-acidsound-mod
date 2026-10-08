# S1-C6 Reset Signature Isolation (S16) offline release

Status: **PASS, candidate built offline**.

App SHA-256 `312790c080f6fcead69eccd84edf2c608ef3fa7e772455d781ab086dafed44b1`. FWSC SHA-256 `fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886`. OTA token `INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93`.

Fixes the 2026-08-14 FM Drum load failure: the S1-C5 reset wrapper detected `0x62 0x63` at wire bytes 6..7 and loaded the packet as a voice, so any voice whose first payload bytes were `62 63` (HITUN RIMS, BUZZ BASS) reset the transaction mid-load. S1-C6 replaces the signature with the structurally impossible `0x64 0x65` (payload bytes 0..1 are OP1 EG rates, DX7 range 0..99) and returns without loading the reset packet as a voice. Hosts send 1 explicit reset packet + 16 voice packets. The new wrapper fits in place; callsites `0x0201e468`/`0x0201e49c` and the selector/producer core are unchanged. Display marker `S16`. No live actions were performed.
