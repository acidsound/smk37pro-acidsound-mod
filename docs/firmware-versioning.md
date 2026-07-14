# Custom firmware versioning

Last updated: 2026-07-15 (KST)

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
