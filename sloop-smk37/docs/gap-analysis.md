# Gap analysis: SLOOP 2.4.1 (FM-1) → SMK-37 Pro port

Date: 2026-10-09. Compares the FM-1 firmware (upstream pin in `SLOOP_PIN`) with
the SMK-37 Pro hardware and with what this port builds. Status key:

- **PARITY** same behaviour, same hardware role
- **MAPPED** FM-1 function moved to another control (see README)
- **MISSING** not in this build; reason and what it would take
- **UNVERIFIED** built, but depends on an electrical fact not yet measured

Evidence labels as in `docs/port-evidence.md`.

## 1. Most important: what this build does NOT do

The port is built with `FELUCCA_FLASH=0 FELUCCA_OTA=0` on purpose (see §3).
Compared with the FM-1 firmware, this build is **missing**:

| FM-1 feature (acceptance criterion) | This build | Why | To restore |
|---|---|---|---|
| Settings, 4 projects, autosave, 32 user presets, 27 FM6 patches **persist across power-off** | MISSING: RAM only | The FM-1 storage map (`FL_DATA 0x97000..`) lies inside the SMK app slot (§3) | A verified SMK free region (owner dump, §5) |
| **Web editor protocol** (SysEx editing, backup/restore, sample upload) | MISSING | `editor.c` needs OTA plumbing and flash for save/sample storage | Flash map + enable `FELUCCA_OTA` for the SysEx path |
| **User samples USR1–USR4** (80 KiB slots) | MISSING | They live in flash | Flash map |
| In-app update over USB (M-UPGRADE) | MISSING (repo's gated path only) | `ota.c` writes flash; the FM-1 loader is not this board's | Repo's `exact_ota` + baseline + rollback (`docs/firmware-runbook.md`) |
| **USB rescue** at power-on (FM-1: OCT− at power-on) | MISSING | `recovery.c` is part of the OTA build | Forced recovery per the repo's runbook (`esp32c3-usbkey`); do not rely on an in-app rescue |
| TRS MIDI IN, MIDI clock in over TRS | MISSING (no jack on the SMK) | Hardware absent | USB MIDI in and clock work; nothing to add |

Everything else in the acceptance list (4 tracks, 10 engines incl. FM6/DX7,
sequencer, layers, songs, USB MIDI, USB audio, the core UI) is built and
tested on the host with the upstream UI fuzz.

## 2. Hardware differences

| Area | FM-1 | SMK-37 Pro | Status | Decision |
|---|---|---|---|---|
| Function buttons | 14 buttons with LEDs | 5 silkscreen buttons + 16 RGB pads | MAPPED | 9 switches on pads 1–9, each with its own colour (`smk37_pad_rgb.h`) |
| Pad / button light | one LED per switch, on the switch's own column and row (`hal/fm1_input.h`: LED lines PH6/PH9/PA9/PA10 and PA5..PA8) | pad RGB; silkscreen LEDs unknown | UNVERIFIED | pad colour from core LED state (lit / dim / backlight / off); output path not decoded (§4) |
| LIGHTS / KEYS / NOTES menu | lights buttons and keys | LCD unchanged; pad lights as above | PARITY (logic) / UNVERIFIED (light) | same logic in core; key lights not shown (keybed unlit) |
| Note keys | 27 keys (FM-1 ids 14..40: 16 white + 11 black) | 37 velocity keys | PARITY | the same 27-key grid on the window F2..G4; 10 keys spare |
| Key velocity | none in the core (fixed) | velocity | PARITY | the core takes no velocity from the HAL, so the SMK behaves like the FM-1; `smk37_key_vel` is kept for later |
| Encoders | K1–K4 + SELECT, ALGORITHM, PRESETS | K1–K8 | MAPPED | K5 SELECT, K6 ALGORITHM, K7 PRESETS, K1–K4; K8 spare |
| MASTER | pot | fader 4 | UNVERIFIED | ADC channel order (bring-up) |
| Faders 1–3 | none | yes | MISSING (unused) | not used by the core |
| Pitch / mod wheels | none | yes | MISSING (unused) | not used by the core |
| Sustain / expression pedal | none | yes | MISSING (unused) | read by the ADC layer, ignored by the core |
| Scan | 11 columns × 6 rows, 2×74HC595 | 12 columns × 8 rows, SPI2 word, GPIO rows | PARITY (logic) | `[DECODED]` v15 ISR |
| LCD | 240×240 RGB565 | 1.54" 240×240 | PARITY | same init (`[DECODED]`, v15 `FUN_0201e846`) |
| Audio DAC | codec via ALNK0 | CS4344 via ALNK0 | PARITY (init) / UNVERIFIED (PC6 enable) | bring-up |
| Battery | yes | yes (TP4056 charger) | UNVERIFIED | ADC channel `SMK37_ADC_BATT` |
| MIDI out | USB | USB; TRS OUT Type A (not used) | PARITY | TRS OUT is available in `fm1_uart.h` but off (`FELUCCA_UART=0`) |
| USB | MIDI + audio | MIDI + audio | PARITY | identity decision, §6 |

## 3. Brick and data-loss review (why FLASH=0)

Facts used:
- `storage.c` and `fm1_flash.h` place data at `0x97000..0xDFFFF` and `0xFC000..` (FM-1 map).
- The packer (`tools/pack_sdk_app_fwsc.py`) puts the SMK app data at flash
  `0x4120` for `617,012` bytes, so the app ends at `0x9AB53`.
- `FL_DATA_LO = 0x97000` is **inside** that range: a settings or project save
  would overwrite code the device executes at boot. That is the failure class
  of the M09 / P0c incidents, so the port must not write there.
- `fl_plain_window_init()` changes the SFC encryption window (`0x93000` upward).
  On the SMK, that range is the encrypted app area. It would make the CPU read
  ciphertext as code. It runs only with `FELUCCA_FLASH`, which is now 0.
- The v15 docs disagree on the tail boundary: `docs/flash-layout-cipher-analysis.md`
  says the tail starts at `0x9A833`, the packer says the app slot runs to
  `0x9AB53`. The packer is the one validated on a device, so the port follows it.
  The discrepancy is recorded for the owner.

Protections in the build:
1. `FELUCCA_FLASH=0`, `FELUCCA_OTA=0` (`tools/build_smk37.py` FLAGS).
2. Link gate: no `fl_write`, `fl_erase4k_*`, `st_save`, `fl_plain_window_init` in the symbol table.
3. `tests/unity_syntax.sh` uses the same flags.
4. The packager refuses any image without a matching PASS build record (`make_smk37_fwsc.py`).

Other boot-time hazards reviewed:
- **UBOOT entry**: OCT− + OCT+ (pads 8 + 9) held 5 s while stopped enters the
  stock USB update mode. It is cancellable (release before 5 s) and never runs
  while a song plays (`main.c` ~l.198). Kept for FM-1 parity. On the SMK the
  two pads are also the drum ghost / hard modifiers, so a long double-hold on
  the stopped drum track can enter update mode. Consider removing this entry
  for the performance build.
- **Power-on calibration**: pads 8 + 9 held at power-on (`main.c` ~l.169) rewrite
  only the RAM label table in this build (no flash), so a wrong calibration is
  cleared by a reset.
- **Bootguard / watchdog**: falls back to ROM on a fault (`bootguard.h`); unchanged.
- **Pin muxing**: IOMAP changes come from the stock `[DECODED]` sequences (SPI1,
  ALNK0). A wrong pin means a wrong signal, not a damaged pin, but bring-up
  must check them one at a time.

## 4. Pad colours: what is done and what is not

Done (host-tested):
- Colour per switch pad, distinct, from the LCD palette (`smk37_pad_rgb.h`).
- Level per LED state: lit 100 %, dim 25 %, backlight ~10 %, off 0.
- Computed in the scan (`fm1__frame`), about 9 cell reads per frame.
- Test: each switch has a colour, pads 10–16 are black, the precomputed cell
  table matches `SMK37_LEDMAP`, and levels scale correctly.

Not done (blocking for visible colour):
- **The pad RGB protocol is not known.** `ui.md` (LED row) records no decoded
  pad-LED ABI. The stock firmware does drive pad LEDs independently of the
  display (`docs/research-notes.md`, M09 notes: pads stayed lit after the display
  went black), so they are MCU-driven, but the bus is not identified.
- `smk37_pad_hw.h` therefore uses `SMK37_PAD_HW_NONE`. Pads show their state only
  through the matrix LED line in `SMK37_LEDMAP`, which is also `[UNVERIFIED]`.
- **To finish**: capture the pad LED line with a logic analyser while the stock
  firmware lights a pad (read-only capture, no flash), then add a backend in
  `smk37_pad_hw.h`. Nothing else changes.

## 5. Flash map, needed for persistence

To enable persistence (and with it the editor, user samples, and presets):
1. Read-only full dump by the owner (`device-info` / forced-loader dump, see
   `docs/m09-wl82-dump-2026-08-15.md`).
2. Find a region that is free in the **live** dump and outside the app data
   `0x4120..0x9AB53` (the packer's map). Live-only data at `0x9C000..0xFFFFF`
   is not documented, so do not use it without its contents being known.
3. Put the region in `storage.c` / `fm1_flash.h`, then build with
   `FELUCCA_FLASH=1` and extend the link gate's allowed list.
Until then, RAM-only is the only build this repo can justify.

### 5a. What the evidence now shows (review, Oct 2026)

- **Official v15 JLFS directory** (`baselines/v15/analysis/patch-set-ui/persistence/report.md`,
  [DECODED-repo]): `app.bin` `0x04120..0x9AB54`; `cfg_tool.bin` `0x9AB54..0x9ACD3`;
  `VM` `0xA0000..0xC4000` (147,456 B); `BTIF` `0xC4000`; `USRTRIM` `0xC5000`;
  `USRFLASH` `0xC6000..0xEF000` (167,936 B); `USR` `0xF8000..0x102000` (the 0xF8000
  record store, occupied, do not write). The report's conclusion is that the **safe
  unallocated budget is 0 bytes** until the VM and USRFLASH allocation maps are proven.
- **Tail boundary**: the v15 directory says `app.bin` ends at `0x9AB54`; the packer
  uses `0x9AB53`. Both leave `0x9AB54..0x9ACD3` to `cfg_tool.bin`, so the layout is
  consistent but not byte-exact. Do not put anything after `0x9ACD3`.
- **External precedent** (`amalahama/smk37-firmware-custom-mod`, v022, unverified):
  a community custom `.fwsc` was flashed through the stock USB-MIDI SysEx OTA
  (`tools/smk_ota_win.py`), and its BLE patch changes the flash **VM key** that holds the
  static MAC from 102 to 108. This suggests that VM is a key/value store reached through
  SDK key IDs, which would be the natural persistence entry point. It also gives a
  different cfg offset (`0x9B757` for v016), which conflicts with v15, and no VM record
  format, allocator, or free-key list. Treat it as a lead only. It is not an SDK fact.
- **Decision**: no persistence write path is added. The next step is the owner's
  read-only dump of the live device (VM and USRFLASH allocation maps), and the SDK VM
  API must be confirmed before any key is written.

## 6. Identity and recovery

- Normal USB: this build presents `1209:0001` (pid.codes test ID, from upstream
  `usb.c`). The repo records the stock SMK identity as `4C4A:C755`
  (`docs/research-notes.md`) and the stock update mode as `4d4a:4155`.
  Tools that match by VID/PID will not find this build. The repo's own
  recovery docs say to match by bus port. **Decision for the owner**: keep the
  test ID (private use only), or set `FELUCCA_USB_PID` and a VID, which should
  not be done for a distributed build without thought.
- Recovery without an in-app rescue: the forced-recovery steps in
  `docs/forced-recovery-plan.md` and `docs/firmware-runbook.md`.

## 7. Open items, by priority

1. Owner decision: persistence path (§5) vs RAM-only release.
2. Pad RGB logic capture (§4).
3. Bring-up checklist in `docs/port-evidence.md` §2 (scan columns, ADC order, LED lines, PC6, velocity).
4. Decide on UBOOT entry for the performance build (§3).
5. Decide the USB identity (§6).
