# S1C5 marked playback-note review

Decision: **PASS**.

Reviewed exact HEAD `ebedcfe6a73ba10f46de7472096ead47e7bc8d87` and exact candidate `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return-S1C5-marked` offline only. No device, USB, MIDI, OTA upload, flash, reset, or live-send path was opened.

## Concrete validation

- **PASS** app marker: app offset `0x572a2`, runtime `0x020572a2`, changed from `1.10\0` in the independently reviewed S1C5 app to `S1C5\0`; marked app differs from that reviewed S1C5 app only at offsets `[357026, 357027, 357028, 357029]`.
- **PASS** identity: app still contains two `SMK-37 Pro_015` USB identity strings at `0x205797f, 0x2057dc8`; exact OTA check accepts only FWSC name `SMK-37 Pro`, version `15`, and package hash `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`.
- **PASS** selector/producer and ABI unchanged from the independently reviewed S1C5 candidate: window `0x0201e13e..0x0201e254` SHA-256 `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1`; Note Off reload `0d4000160016` (`lb.z r5,[r0]`), Note On reload `0e4000160016` (`lb.z r6,[r0]`), velocity store `8d42` preserved.
- **PASS** package and rollback gates: FWSC `SMK37Pro-v15-S1C5-playback-register-return-S1C5-marked.fwsc` SHA-256 `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`, package safety gate `PASS`, SHA256SUMS inventory passed, rollback manifest restores official flash with sectors `0x04000, 0x20000, 0x22000, 0x2a000, 0x5a000, 0x62000`.
- **PASS** deterministic rebuild: two isolated scratch rebuilds reproduced app `c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5`, FWSC `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`, and evidence `42a2b1ee51d5a2bdfa07dcb300a9fcd146ae7b4417be71e05c849625d85c10dd`.
- **PASS** exact OTA check matrix: marked candidate accepted with rc 0; S1C4 parent, official v15, and unmarked S1C5 were rejected with rc 1; upload mode was not invoked.
- **PASS** stale-token scan: no old unmarked OTA token/hash label, unmarked `.fwsc` artifact reference, or old `Playback Register Return package` OTA accept/reject text remained. Top-level candidate contains only `SMK37Pro-v15-S1C5-playback-register-return-S1C5-marked.fwsc` as an FWSC artifact.

## Scope

All checks were local file reads, Python validation, C compilation, and exact-hash `check` mode. This review makes no live-device claim.
