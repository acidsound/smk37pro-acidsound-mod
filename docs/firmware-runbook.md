# SMK-37 Pro firmware runbook

Last verified: 2026-07-15 (KST)

This runbook covers the native direct-USB path on macOS. It does not use a
Windows VM, CoreMIDI API, or SysEx API. The USB-MIDI class transport is accessed
directly through libusb bulk endpoints.

## Safety boundary

The stock restore command accepts only the exact official SMK-37 Pro v12
package:

- updater identity: `SMK-37 Pro_012`
- display version: 1.05
- file size: 701,140 bytes
- file SHA-256:
  `c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a`

Do not substitute firmware 015 or firmware for Elite, MKE-P37, or Starrykey.
The stock `upload` and `upload-resume-v12` paths reject every package whose
SHA-256 is not the official v12 hash. Named custom commands accept only their
one recorded build hash, so experimental and recovery paths cannot be crossed
accidentally. Downgrade remains untested.

## Build

```sh
make test
```

The Makefile rejects libusb older than 1.0.30 because 1.0.29 deadlocked during
a Darwin USB detach transition on this machine.

Set the package path once:

```sh
FWSC=~/Downloads/SMK-37_Pro_012.fwsc
```

## Read-only checks and backup

```sh
scripts/smk37-fw-direct device-info
build/smk37-fw inspect "$FWSC"
scripts/smk37-fw-direct upload-check "$FWSC"
build/smk37-fw upload-dry-run "$FWSC"
scripts/smk37-fw-direct dump backups/smk37-pro-live.bin 0x100000
shasum -a 256 backups/smk37-pro-live.bin
```

The dump is the raw encrypted/scrambled flash representation. It is valuable
evidence and input for analysis, but it is not yet a proven standalone recovery
image.

## Guarded stock restore

Keep the SMK directly connected by USB-C and on external power. Close DAWs,
Audio MIDI Setup, and other MIDI clients. Then run:

```sh
scripts/smk37-fw-direct upload "$FWSC" backups/ota-restore.log \
  --confirm SMK-37-Pro-012
```

Expected transport sequence:

1. Normal device `4C4A:C755`, MIDI Streaming interface 4, endpoints
   `0x04/0x84`.
2. Verification completion request `0xE0000000` and `success\0` response.
3. Automatic re-enumeration on the same physical port as update device
   `4D4A:4155`.
4. Update-mode MIDI Streaming interface 1, endpoints `0x04/0x84`.
5. Write completion request `0xF0000000` and `success\0` response.
6. Automatic normal-mode reboot and identity `SMK-37 Pro_012`.

The `upload-resume-v12` command exists only to recover a process that stopped
after verification while the device is visibly present as `4D4A:4155`. It is
locked to the exact v12 hash and a separate confirmation token. Do not use it
from normal mode.

## Offline application-only repack gate

The experimental packer is intentionally separate from the live uploader:

```sh
make test-safe-repack FWSC="$FWSC"
```

This command decrypts and re-encrypts every v12 application container layer,
recomputes the JLFS and UFW CRC chain, and requires the resulting no-change
file to be byte-for-byte identical to the official package. The verified
result on 2026-07-15 had the same package SHA-256 shown above and zero changed
bytes.

An offline mutation can be generated with `tools/smk37_app_patch.py`, but the
tool accepts only the exact official v12 input and only equal-length changes
inside `app.bin`. Its manifest requires these protected hashes to remain
identical:

- flash header, boot/update loader, and top-level layout before `0x4000`
- raw `uboot.boot`
- raw `isd_config.ini`
- resources and reserved definitions after the application container

Modified-image live commands are permitted only as named, exact-SHA build
commands. `upload-m001`, `upload-m02`, and `upload-m05` each accept one
recorded package hash; the stock `upload` and `upload-resume-v12` commands
still reject custom packages. Never replace this allow-list with a generic
modified-image switch.

M001 proved modified-package acceptance and normal boot. While M001 was
running, it accepted the normal OTA command, entered update loader
`4D4A:4155`, installed M02, and booted again. This proves the normal custom-app
update line. It still does not prove recovery from a future custom application
that crashes before normal USB and the OTA command handler initialize. See
`docs/fm-drum-plan.md` for that remaining boundary.

## M05 minimal two-timbre checkpoint

M05 is a behavior experiment, not a confirmed multitimbral result. It keeps
the stock patch selector and implements only this fixed routing:

- human MIDI channel 1: current patch N;
- human MIDI channel 2: same-bank patch `(N + 1) & 31`;
- all other channels: stock current-patch behavior.

The exact package SHA-256 is
`0beab977977bd175ea484be44851c76958d22de4e787b9cbc34ddfaa8400c1f6`.
After read-only `device-info`, `inspect`, `upload-check`, and `upload-dry-run`
all pass, the guarded install command is:

```sh
scripts/smk37-fw-direct upload-m05 \
  build/SMK37ProMod-M05-two-timbre-base012.fwsc \
  backups/ota-M05-install-20260715.log \
  --confirm INSTALL-SMK37PRO-M05-0BEAB977
```

Do not send Yamaha preset SysEx while M05 is installed; its single-voice
pack/save routine supplies the temporary code space for this checkpoint.
Program Change is not implemented.

For the audio test, create two overlapping Logic tracks targeting the SMK:

1. Track A transmits sustained notes on MIDI channel 1.
2. Track B transmits overlapping notes on MIDI channel 2.
3. Use a current patch whose adjacent patch is audibly distinct.
4. Confirm that the channel-1 note retains patch N while channel 2 sounds N+1.
5. Release notes in both orders and run a short repeated-note loop to check for
   stuck notes or cross-channel note-off.
6. As a boundary test, select patch 31 and confirm channel 2 uses patch 0.

The physical keyboard alone cannot prove this build because it does not
generate both test channels. Success requires two different timbres to remain
audible at the same time; merely receiving both channels is insufficient.

## M06 local-pad channel-10 FM checkpoint

M06 keeps local keys and USB Ch1 on current patch N. It bridges the factory
local pads, and incoming USB Ch10, to same-bank patch `(N + 1) & 31`. All 16
factory pad notes 36-51, velocity, Note Off, and original MIDI output are
preserved. This build still uses one FM patch across the pad range.

Package SHA-256:
`61b2f5707a2b5779ffa118612957b232027de72f377d56adc9d68d6ed302aac4`.

```sh
scripts/smk37-fw-direct upload-m06 \
  build/SMK37ProMod-M06-local-pads-base012.fwsc \
  backups/ota-M06-install-20260715.log \
  --confirm INSTALL-SMK37PRO-M06-61B2F570
```

After boot, hold a local-key note and strike/release each pad. Verify that the
key retains patch N, pads use N+1, attacks are not doubled, released pads do
not stick, and the pads still transmit Ch10 over USB.

## M07 per-note channel-10 FM checkpoint

M07 keeps local keys and USB Ch1 on current patch N. Ch10 notes 36-51 use
different same-bank FM snapshots: N+1 through N+16, wrapping within the
32-preset bank. Note pitch, velocity, paired Note Off, and the original local
pad MIDI output are preserved. The selected factory presets are a diagnostic
16-timbre palette, not yet a curated percussion bank.

Package SHA-256:
`b80ed7480152f07652eb8f809305f50d2bdb2990fb89875c317f27d5e99de082`.

```sh
scripts/smk37-fw-direct upload-m07 \
  build/SMK37ProMod-M07-per-note-pads-base012.fwsc \
  backups/ota-M07-install-20260715.log \
  --confirm INSTALL-SMK37PRO-M07-B80ED748
```

After boot, verify the display reads M07. Hold a local-key note and press all
16 pads. Each pad should have a different FM timbre while the key retains N.
Then run repeated hits and releases on every pad to detect doubled attacks,
stuck notes, or a Note Off that terminates another pad.

## M08 isolated fixed channel-10 map

M08 restores the Ch1 stock path and maps Ch10 notes 36-51 to fixed Bank 0
preset IDs 0-15. It saves and restores the UI bank and preset state around
each Ch10 snapshot, so UI Patch changes should affect Ch1 only.

Package SHA-256:
`4498a935951e32d21b85167e5ba369a5051d32d93ba66e51229d5d255c8dc31f`.

```sh
scripts/smk37-fw-direct upload-m08 \
  build/SMK37ProMod-M08-fixed-drum-map-base012.fwsc \
  backups/ota-M08-install-20260715.log \
  --confirm INSTALL-SMK37PRO-M08-4498A935
```

## M09 app-resident DX7 FM drums

**REVOKED: DO NOT INSTALL.** M09 completed OTA but failed before display and
USB initialization. After a true power cycle neither normal nor updater USB
identity was present. The action below is retained only as an incident record
and must not be executed. See `docs/m09-brick-incident.md`.

M09 no longer borrows factory presets. Ch1/local keys retain the UI patch and
Ch10/local pads use eight embedded DX7 percussion templates through a 16-note
GM map. The build does not write the user preset sectors at
`0xF4000..0xF7FFF`.

Package SHA-256:
`5ac1264eba85ce5f1747458a90203bc144d21f87dc66f189ca055b74700ab5c8`.

Historical upload action: `upload-m09` with confirmation token
`INSTALL-SMK37PRO-M09-5AC1264E`. It is deliberately not presented as a
copyable command.

## M10 data-only boot probe

M10 starts from the byte-exact M08 application. It keeps the M08 execution
path, code cave, hooks, and call targets unchanged, then populates only the
candidate application data range `0x020959EE..0x02095EDE` and changes the
display marker to `M10`. No new M10 code reads this data; the purpose is to
separate the M09 data-range hypothesis from the M09 wrapper hypothesis.

Package SHA-256:
`6ad99ed15232a5d8e55be836f3cb13561b68b152aaae2642964e6855bd6628b5`.

The host tool has a dedicated exact-package gate:

```sh
scripts/smk37-fw-direct upload-m10 \
  build/SMK37ProMod-M10-data-only-base012.fwsc \
  backups/ota-M10-install-20260801.log \
  --confirm INSTALL-SMK37PRO-M10-6AD99ED1
```

Before this command, preserve two identical 1-MiB read-only dumps and verify
the normal device identity is `SMK-37 Pro_012`. If M10 does not return normal
USB, use the prepared M10 rollback bundle
`build/SMK37Pro-WL82-M10-rollback-20260801-v4.zip`; it erases/writes only the
six audited 4-KiB application sectors and has no chip-erase, full-flash,
key-write, reset, or run-app operation.

Live result on 2026-08-01: the command was executed once, both OTA stages
completed and request 1241 acknowledged `0xf0000000`, but post-update identity
verification failed and `4c4a:c755` was not found afterward. Do not execute
`upload-m10` again; proceed to forced recovery.

## Confirmed live result

The verification stage completed with 49 requests. The resumed write stage
completed with 1,241 requests and acknowledged `0xF0000000`. The unit then
booted normally and reported version `012`. A complete post-restore 1-MiB dump
also succeeded.

Subsequent M001 and M02 writes completed normally. The earlier post-restore
verification timeouts did not prevent later same-base writes and are no longer
an active blocker, though unnecessary repeat writes should still be avoided.

Confirmed custom sequence on 2026-07-15:

1. Official v12/display 1.05 installed M001.
2. M001 booted and displayed `M00`, proving the UI field is only three
   characters wide.
3. Running M001 entered OTA loader `4D4A:4155` and installed M02.
4. M02 booted, retained USB identity 012, and displayed `M02` in full.
5. M03 booted; its first display string worked, revealing that the proposed
   second string was not part of the active screen.
6. M04 booted and displayed the exact two lines `Hello,` and `acidsound`.
7. Running M04 entered OTA loader `4D4A:4155` and installed the exact archived
   official v12 package.
8. The official app booted with USB identity 012; the owner verified display
   version 1.05 and the restored stock Reset UI.
9. Official v12 installed M05; both OTA stages and 1,241 stage-2 requests
   completed, then M05 booted and reported USB identity 012. The owner then
   confirmed intended simultaneous Ch1/N and Ch2/N+1 playback from overlapping
   host-sequencer loops.
10. Running M05 installed M06; both OTA stages and 1,241 stage-2 requests
    completed, then M06 booted and reported USB identity 012. The owner
    confirmed intended simultaneous local-key Ch1/N and local-pad Ch10/N+1 FM
    behavior.
11. Running M06 installed M07; both OTA stages completed and normal USB
    identity 012 returned. The owner confirmed independent per-note timbres,
    but Ch1/local keys were also remapped; M07 fails channel isolation.
12. Running M07 installed M08; both OTA stages completed and normal USB
    identity 012 returned. The owner then verified Ch1/Ch10 isolation and UI
    Patch independence in normal simultaneous use. Maximum-polyphony stress
    remains pending.

This is a complete custom-to-official round trip for a normally booting
application-only modification. Transcript:
`backups/ota-M04-to-official-v12-20260715.log`.

M05 install transcript: `backups/ota-M05-install-20260715.log`.
M06 install transcript: `backups/ota-M06-install-20260715.log`.
M07 install transcript: `backups/ota-M07-install-20260715.log`.
M08 install transcript: `backups/ota-M08-install-20260715.log`.

If an operation reaches a state where a power cycle or button action is
required, stop host-side commands and perform only the explicitly identified
device action.
