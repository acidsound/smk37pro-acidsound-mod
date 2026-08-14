# Custom firmware versioning

Last updated: 2026-08-01 (KST)

## Two independent identities

Every custom build records both identities. Do not replace or conflate them:

- upstream base: updater version `012`, stock display version `1.05`;
- custom display/build ID: `MNN`, a three-character monotonically increasing
  ID.

The updater version `012` and every OTA/bootloader compatibility field remain
byte-identical to official v12. Only the four-byte application UI field `1.05`
is replaced with three visible `MNN` bytes plus a NUL terminator. This makes a
running custom application visible without changing update selection or
recovery semantics.

## Rules

1. Use `M02`, `M03`, and so on; never reuse an ID, even for a failed
   experiment. M001 is retained as the historical four-character trial.
2. Increment the ID whenever the generated FWSC bytes or intended behavior
   change.
3. Name artifacts `SMK37ProMod-MNN-base012.fwsc` and retain the matching
   manifest beside them under ignored `build/`.
4. Record the exact SHA-256 and one of `OFFLINE`, `INSTALLED`, `REJECTED`, or
   `RECOVERY-VERIFIED` in the ledger below.
5. A version number is identification, not evidence of successful boot or
   behavior. Installation and recovery results are separate ledger events.

## Build ledger

| ID | Base | Purpose | Package SHA-256 | State |
| --- | --- | --- | --- | --- |
| M001 | updater 012 / display 1.05 | First four-character marker trial | `af9ef78c80391d5a7eaa9d8d8bd5d6b3e77e891c532150fb80578bdcaa28a6a2` | INSTALLED and booted; screen showed truncated `M00`; subsequently entered OTA and installed M02 |
| M02 | updater 012 / display 1.05 | Three-character marker `M02`; no functional change | `c2aa5ee8e82a5c1a85f58c3361404838a9f3bd9a7657698db23e8fd52bf149b1` | INSTALLED; USB identity 012 and full `M02` screen display verified |
| M03 | updater 012 / display 1.05 | First `Hello,` / `acidsound` string-map test | `217bbdc356c603227045dca295e92e9fc01b82b8972b95479735e66e134c9fd0` | INSTALLED and booted; `Hello,` appeared but the selected second string was not used by that screen |
| M04 | updater 012 / display 1.05 | Exact two-line `Hello,` / `acidsound` display test | `fffb9552d3ea8433b98e150d4c529e95e3dd6b2bb103b8839be06f2f5f7e6246` | INSTALLED and verified; then successfully restored to exact official v12/display 1.05 |
| M05 | updater 012 / display 1.05 | Minimal two-timbre checkpoint: Ch1 = N, Ch2 = `(N + 1) & 31` | `0beab977977bd175ea484be44851c76958d22de4e787b9cbc34ddfaa8400c1f6` | INSTALLED and VERIFIED; owner confirmed intended simultaneous Ch1/N and Ch2/N+1 playback |
| M06 | updater 012 / display 1.05 | Local keys/Ch1 = N; local pads and USB Ch10 = `(N + 1) & 31` | `61b2f5707a2b5779ffa118612957b232027de72f377d56adc9d68d6ed302aac4` | INSTALLED and VERIFIED; owner confirmed intended simultaneous local-key N and local-pad N+1 FM playback |
| M07 | updater 012 / display 1.05 | Intended Ch10 notes 36-51 = same-bank patches `N+1` through `N+16` | `b80ed7480152f07652eb8f809305f50d2bdb2990fb89875c317f27d5e99de082` | INSTALLED; 16 per-note timbres PASS, Ch1 isolation FAIL because local keys also received per-note timbres |
| M08 | updater 012 / display 1.05 | Ch1 = UI patch; Ch10 notes 36-51 = fixed Bank 0 presets 0-15 | `4498a935951e32d21b85167e5ba369a5051d32d93ba66e51229d5d255c8dc31f` | INSTALLED and VERIFIED; Ch1/Ch10 isolation and UI Patch independence pass, maximum-polyphony stress pending |
| M09 | updater 012 / display 1.05 | Ch1 = UI patch; Ch10 notes 36-51 = app-resident DX7 FM drum templates | `5ac1264eba85ce5f1747458a90203bc144d21f87dc66f189ca055b74700ab5c8` | BOOT-FAILED / NO-USB; OTA request 1241 and completion acknowledgement passed, then display remained black; a true power cycle left display and pad LEDs off, with neither normal nor updater USB identity present |
| M10 | updater 012 / display 1.05 | M08 execution path unchanged; populate the M09 candidate data range only | `6ad99ed15232a5d8e55be836f3cb13561b68b152aaae2642964e6855bd6628b5` | BOOT-FAILED / NO-USB; both OTA stages and `0xf0000000` acknowledgement passed, then normal identity `4c4a:c755` did not return |

M001 artifact paths:

- `build/SMK37ProMod-M001-base012.fwsc`
- `build/SMK37ProMod-M001-base012-manifest.json`

The application replacement changes three actual data bytes because one byte
is common between `1.05` and `M001`. The verifier reports 11 changed Flash
bytes after application CRC fields are included. Boot/layout, `uboot.boot`,
`isd_config.ini`, and post-application resource/reserved hashes are unchanged.

M02 artifact paths:

- `build/SMK37ProMod-M02-base012.fwsc`
- `build/SMK37ProMod-M02-base012-manifest.json`

M02 replaces all four field bytes with `M02\0`. The verifier reports four
changed application bytes and 12 changed Flash bytes after CRC fields are
included. Both the M001 and M02 live transcripts completed 1,241 stage-2
requests, acknowledged `0xF0000000`, rebooted, and reported USB identity 012.

M03/M04 artifact paths:

- `build/SMK37ProMod-M03-hello-base012.fwsc`
- `build/SMK37ProMod-M03-hello-base012-manifest.json`
- `build/SMK37ProMod-M04-hello-base012.fwsc`
- `build/SMK37ProMod-M04-hello-base012-manifest.json`

M04 changed only application strings and their enclosing CRC fields. It
displayed exactly:

```text
Hello,
acidsound
```

The exact official package was then installed from the running M04 app. The
loader completed 1,241 stage-2 requests, normal USB identity returned to 012,
and the owner verified both display version 1.05 and the original Reset UI.
`VERSION` records the latest custom build artifact, not the firmware currently
installed on the device. Current device state after this test is official v12.

M05 artifact paths:

- `build/SMK37ProMod-M05-two-timbre-base012.fwsc`
- `build/SMK37ProMod-M05-two-timbre-base012-manifest.json`
- `build/SMK37ProMod-M05-app.bin`
- `build/SMK37ProMod-M05-app-manifest.json`

M05 is the first functional audio experiment, not a confirmed multitimbral
result. It routes USB MIDI channel 1 to the currently selected patch N and
channel 2 to the next patch in the same 32-preset bank, wrapping 31 to 0. Its
application SHA-256 is
`0cdba4335a39015825edcfc8351ae8b4e80ffe7b03d3529d1e151c050642ede0`.
The repack verifier reports 124 changed application bytes, 132 changed Flash
bytes including CRC fields, and 138 changed FWSC bytes. All protected hashes
remain identical to official v12.

The M05 code cave replaces the Yamaha single-voice SysEx pack/save routine, so
that one feature is intentionally disabled for this checkpoint. Normal USB
MIDI notes are the only supported test input; do not send Yamaha preset SysEx
during the test. No patch-selection UI, Program Change support, or persistent
part state is included.

Live result, 2026-07-15: after M05 installed and rebooted normally, the owner
played channel-separated loops from a host sequencer and confirmed that the
implementation behaved exactly as intended. Channel 1 retained patch N while
channel 2 sounded patch N+1 simultaneously. This is the first verified
two-part multitimbral FM build for the SMK-37 Pro project.

M06 artifact paths:

- `build/SMK37ProMod-M06-local-pads-base012.fwsc`
- `build/SMK37ProMod-M06-local-pads-base012-manifest.json`
- `build/SMK37ProMod-M06-app.bin`
- `build/SMK37ProMod-M06-app-manifest.json`

M06 moves the special FM part from human MIDI channel 2 to channel 10 and adds
a local raw-MIDI pad bridge. The application SHA-256 is
`bc56b86afab4f64d29e4d389f7b99c7af656c5f4a9c98c93931ac218e08e6919`.
The repack verifier reports 174 changed application bytes, 182 changed Flash
bytes including CRC fields, and 188 changed FWSC bytes. All protected hashes
remain identical to official v12. As in M05, Yamaha single-voice preset SysEx
pack/save remains temporarily unavailable.

M06 completed both OTA stages, all 1,241 stage-2 requests, and the
`0xF0000000` completion acknowledgement. It rebooted and reported USB identity
012. Install transcript: `backups/ota-M06-install-20260715.log`.

Owner live result, 2026-07-15: M06 behaved as intended. The local keyboard
continued to use Ch1/current patch N, while the physical pads used Ch10/patch
N+1 through the new FM bridge. This verifies the first local-input two-part FM
configuration. It does not yet assign different FM patches to individual pad
notes.

M07 artifact paths:

- `build/SMK37ProMod-M07-per-note-pads-base012.fwsc`
- `build/SMK37ProMod-M07-per-note-pads-base012-manifest.json`
- `build/SMK37ProMod-M07-app.bin`
- `build/SMK37ProMod-M07-app-manifest.json`

M07 keeps local keys and USB Ch1 on current patch N. For Ch10, it derives a
per-note preset offset as `(note - 35) & 31`, so the physical notes 36-51 map
to same-bank patches N+1 through N+16. Both Note On and Note Off use the same
mapping, and the original note, velocity, release timing, and pad MIDI output
are retained. The application SHA-256 is
`43e40ee627a33d06da589f036fc98ac13ed7edbbe1639ba6277e77385aa4423a`.
The repack verifier reports 192 changed application bytes, 200 changed Flash
bytes including CRC fields, and 206 changed FWSC bytes. All protected hashes
remain identical to official v12.

This checkpoint proves 16 independent note-to-FM-patch selections; it does
not claim that the selected factory presets are already tuned as percussion.
After live verification, the N-relative selection can be replaced by a fixed
curated GM drum table without changing the proven Ch10/local-pad route.

M07 completed both OTA stages and returned to normal USB identity 012. Install
transcript: `backups/ota-M07-install-20260715.log`. This proves installation
and application startup. Owner audio test found that the 16 per-note timbres
were independent, but the same note-dependent mapping contaminated Ch1/local
keys. M07 therefore fails the channel-isolation requirement and must not be
treated as the drum-map baseline.

M08 artifact paths:

- `build/SMK37ProMod-M08-fixed-drum-map-base012.fwsc`
- `build/SMK37ProMod-M08-fixed-drum-map-base012-manifest.json`
- `build/SMK37ProMod-M08-app.bin`
- `build/SMK37ProMod-M08-app-manifest.json`

M08 gates the channel before moving the note into any temporary register.
Ch1/local keys take the stock snapshot path. Ch10 notes 36-51 temporarily
select fixed Bank 0 presets 0-15, snapshot the timbre, then restore both the
UI bank selector and Bank 0 preset index before returning. The application
SHA-256 is
`73ae9baa5c732f91e91e7133cda4a9146a00d3b70333ed53814e3747a1297e25`.
M08 completed both OTA stages and returned to normal USB identity 012.
Transcript: `backups/ota-M08-install-20260715.log`. Audio isolation and UI
Patch independence were then verified by the owner. Ch1 retained the selected
UI patch while Ch10 retained its fixed 16-note map across UI Patch changes.
No functional problem was observed in normal simultaneous use. Maximum
polyphony, voice stealing, and release behavior under saturation remain
untested.

M09 artifact paths:

- `build/SMK37ProMod-M09-dx7-drums-base012.fwsc`
- `build/SMK37ProMod-M09-dx7-drums-base012-manifest.json`
- `build/SMK37ProMod-M09-app.bin`
- `build/SMK37ProMod-M09-app-manifest.json`

M09 bypasses the factory patch loader for Ch10. Eight 156-byte DX7 runtime
snapshots and a 16-byte GM-note map were placed in a zero-filled application
tail range that static analysis found unreferenced but live failure shows must
not be classified as a safe data cave. Ch1 and the Patch UI retain the stock
path; Ch10 neither reads nor writes the global bank, preset index, or
current-patch buffer. Notes 36-51 map to kick, stick, snare, clap, tom,
closed/open hi-hat, and cymbal templates. Reused tom/cymbal templates retain
the incoming note pitch. The application SHA-256 is
`8c63f6f44877810b7f23ba88a91870aa758add099cb02d3de9721b6f636ecdbe`.

The live OTA transcript is `backups/ota-M09-install-20260715.log`. Both stages
completed through request 1241, and the updater acknowledged the final
`0xf0000000` completion request. The immediate post-update open failed. A
subsequent descriptor-only macOS USB-tree scan found neither normal identity
`4c4a:c755` nor updater identity `4d4a:4155`; the normal-device probe also
reported not found. Therefore the flash transfer is established, but boot,
display marker, audio behavior, and recovery-path availability were not
established by the transfer itself. Physical inspection then confirmed a
black display. USB-only reconnection did not help; after a true power cycle,
the display and all pad LEDs remained off and a fresh scan again found neither
USB identity. M09 is therefore a demonstrated pre-USB boot failure, not a
verified build. Do not reinstall it.

M10 artifact paths:

- `build/SMK37ProMod-M10-data-only-base012.fwsc`
- `build/SMK37ProMod-M10-data-only-base012-manifest.json`
- `build/SMK37ProMod-M10-app.bin`
- `build/SMK37ProMod-M10-app-manifest.json`
- `build/SMK37Pro-WL82-M10-rollback-20260801-v4.zip`

M10 is a data-only diagnostic derivative of M08. Its execution bytes, code
cave, hooks, and call targets are unchanged from the recorded M08 app. It
populates `0x020959EE..0x02095EDE` with 1,264 bytes (789 nonzero changes) and
changes only the display marker from `M08` to `M10`. It must be classified by
boot/USB return separately from audio behavior; the embedded data is not read
by any new M10 code.

Live M10 attempt on 2026-08-01: stage 1 and stage 2 completed through request
1241 and acknowledged `0xf0000000`, but post-update normal identity failed and
the subsequent descriptor-only probe found no `4c4a:c755`. Do not retry the
M10 upload; forced recovery is pending.

The incident analysis is `docs/m09-brick-incident.md`. It separates the
confirmed M09 application failure boundary from the still-unproven exact root
cause and from the independent failure to establish forced recovery first.

## v15 S1C 시리즈 표시 마커 규칙 (2026-08-14)

S1C 시리즈(v15 기반)는 이 문서의 교훈(4자 `M001` → 화면 `M00` 잘림 → `MNN`
3자 체계로 전환)을 반복해 4자 마커 `S1C5`를 사용했고, 표시에서 `S1C`로 잘려
버전 오독(→ S1C1)이 발생했습니다.

- 규칙: **표시 마커는 정확히 3자** — `S` + 2자리 빌드 번호 (`S15`, `S16`, …),
  번호 재사용 금지 (M-시리즈 규칙 1과 동일).
- 대응: S1C5 ↔ 표시 `S15`. 문서·아티팩트의 전체 명칭(S1C5 등)은 유지하되
  표시 마커와의 대응을 명시.
- 다음 v15 펌웨어(Phase 1 결과물)부터 적용. 현재 설치된 S1C5 마커
  (`S1C5`, 표시 `S1C`)는 재빌드 결정 전까지 유지.
