# SMK-37 Pro SLOOP port — evidence and bring-up checklist

Evidence labels:
- **[DECODED]** — read directly from the v15 stock firmware disassembly
  (`baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz`).
- **[INFERRED]** — deduced from the layout/silkscreen/photos; not seen in code.
- **[UNVERIFIED]** — assumed; must be confirmed on hardware before trusting it.

## 1. v15 addresses → HAL constants

| Function | Evidence | HAL constant / use |
|---|---|---|
| LCD init `FUN_0201e846` | [DECODED] SPI1 DMA, D/C=PB5, CS=PC8, CASET/RASET 0..0xF0, RAMWR 115200 B | `SMK37_LCD_*`, `LCD_BAUD 4`, 240×240 RGB565 |
| SPI1 baud `FUN_0201de2e` | [DECODED] SPI1_BAUD=8, IOMAP_CON1 \|= 0x10 | `IOMAP_CON1 0x51020 |= 0x10` |
| Key-scan ISR `0x0201BCE6..0x0201BDC8` | [DECODED] PA1 strobe; rows PA2/5/6/7/9 + PH6/8/9; SPI2 4-byte column/LED DMA; raw table `(col<<4)+row`; SARADC stepping | `smk37_map.h` row/strobe, `fm1_input.h` debounce |
| SPI2 scan DMA | [DECODED] SPI2 `0x11E00` | 4-byte word `[cols_lo, cols_hi, leds_lo, leds_hi]`, active low, CON `0x4021` |
| ALNK0 init `0x02007084..0x0200713c` | [DECODED] byte-identical to FM-1 sequence; codec pins PC0/PC2/PC1 (ids 0x20/0x22/0x21) | `fm1_audio.h` ALNK0 `0x12E00` |
| IOMAP_CON5 / CLK | [DECODED] IOMAP_CON5 `0x51030` &= ~0xC0; CLK 0x10014 &= ~0xF00 | `fm1_audio.h` |
| SARADC | [DECODED] SARADC `0x13100` used | `fm1_adc.h` CON `0xF04E \| ch<<8` |
| Peripheral SFR bases | [DECODED] psfr `0x50000,0x50040,0x50044,0x501C4,0x51000,0x5101C,0x51020,0x51028,0x51030`; lsfr incl. `0x11D00` SPI1, `0x11E00` SPI2, `0x12E00` ALNK0, `0x13100` SARADC, `0x10800` TIMER4, `0x13E08` P33, `0x11800` USB | HAL base addresses |
| Codec enable | [DECODED] pin-id set via GPIO fn `0x02006762` | PC6 enable is still [UNVERIFIED] (see §2) |
| Pad LEDs are MCU-driven | [INFERRED] `docs/research-notes.md` (M09): pad LEDs stayed lit while the display was black, so they are driven by the MCU, not the display | pad colour output: `smk37_pad_hw.h` (NONE) |
| Pad LED ABI | [UNVERIFIED] `baselines/v15/analysis/subsystem-feasibility/ui.md` LED row: "ABI unknown", no pad table found | none; needs a logic-analyser capture |
| App-data slot | [DECODED-repo] `tools/pack_sdk_app_fwsc.py`: app data at flash `0x4120`, 617,012 B, so it ends at `0x9AB53`; the packer is validated on a device | `APP_SLOT`; FM-1 storage must not overlap it |
| FM-1 storage map | [DECODED-port] `storage.c` / `fm1_flash.h`: data `0x97000..0xDFFFF`, globals `0xFC000..` (inside the SMK app slot for `0x97000..0x9AB53`) | `FELUCCA_FLASH=0` in this build |
| SFC plain window | [DECODED-port] `fm1_flash.h` `fl_plain_window_init()`: maps `0x93000` upward as plain XIP | runs only with `FELUCCA_FLASH`; not in this build |
| Tail boundary conflict | [CONFLICT] `docs/flash-layout-cipher-analysis.md` says the tail starts at `0x9A833`; the packer says app data runs to `0x9AB53` | the packer is followed; owner to resolve with a dump |
| Stock flash regions (v15) | [DECODED-repo] `baselines/v15/analysis/patch-set-ui/persistence/report.md`: `VM` `0xA0000..0xC4000`, `USRFLASH` `0xC6000..0xEF000`, `USR` `0xF8000..0x102000`; safe free budget 0 B | no write path; `docs/gap-analysis.md` §5a |
| VM key store | [UNVERIFIED] `amalahama/smk37-firmware-custom-mod` (v022 BLE patch): stock flash VM key 102 holds the static MAC, redirected to key 108 | not used; needs an SDK VM API and a dump |
| Community custom flash | [UNVERIFIED] same repo: custom `.fwsc` flashed over stock USB-MIDI SysEx OTA (`smk_ota_win.py`) | not used; this repo's exact-SHA gate and rollback still apply |
| USB identity | [DECODED-repo] stock `4C4A:C755`, update mode `4d4a:4155`; this build `1209:0001` (upstream test ID) | `usb.c` `FELUCCA_USB_PID`; owner decision (`docs/gap-analysis.md` §6) |

## 2. Bring-up checklist (hardware, read-only first)

Do these before any flash. Each item names what to observe and the file to fix.

1. **[INFERRED] Scan column count (12) and block order** — `smk37_map.h`.
   Confirm: press each keybed key, each pad, each right button; check that the
   raw table index `(col<<4)+row` maps to the expected logical id. Wrong order
   shows as misplaced notes/pads.
2. **[UNVERIFIED] ADC channel order** — `smk37_board.h` `SMK37_ADC_*`.
   Sweep fader1..3, master, pitch, mod, pedal and check each reads its own
   control. Swapped channels → fix the enum only.
3. **[UNVERIFIED] LCD backlight pin** — `SMK37_LCD_BL_PORT -1` (none).
   If the panel stays dark with the image visible in the dump, look for a
   backlight GPIO and set it.
4. **[UNVERIFIED] LED line map and pad colours** — `smk37_map.h` `SMK37_LEDMAP`,
   `smk37_pad_rgb.h` (colours), `smk37_pad_hw.h` (output, NONE).
   The core lights a function by looking its slot up in FM1_KEYMAP (rows 1..4,
   `ui_input.c` `led_pos_init`); the port's LEDMAP places slot s at column
   `s % 4`, row `1 + s / 4`. This layout was assigned, not measured. The pad
   colours are computed from it. Bring-up:
   1. Light each slot in turn (`fm1_led_key(slot, 1)`) and check the lit LED is the intended function. Fix the table where it is not.
   2. Capture the pad LED line once with a logic analyser while the stock firmware lights a pad (read-only, no flash). Identify the bus (WS2812-style, SPI, or a driver IC), then add a backend to `smk37_pad_hw.h`.
   Note keys have no LED on this board (by design).
5. **[UNVERIFIED] PC6 codec enable** — `fm1_audio.h`. Confirm audio output
   with the enable pin high. If silent, the enable line is wrong for this board
   and must be re-derived from the v15 codec init (`0x02006762` call sites).
6. **[UNVERIFIED] Velocity / aftertouch path** — keybed velocity and pad
   aftertouch come from the scan timing, not an ADC. Play a dynamic test:
   velocity should track strike speed, aftertouch should track pad pressure.

## 3. Pad-button remapping rationale (switches and colours)

FM-1 controls with no SMK-37 counterpart are provided by the 16 RGB pads.
The full table lives in `board/hal/smk37_map.h` (`SMK37_SLOT_OF`,
`SMK37_PHYS_OF_SLOT`) and `README.md`. LEDs use their own table,
`SMK37_LEDMAP` (`FM1_KEYMAP` for the core's LED lookup), so the scan layout
and the LED layout do not have to agree. The core dispatches only logical slots
0..13 (`ui_input.c` loop `id < 14u`), so physical ids are mapped to slots
inside the HAL debounce, never in `panel.btn[]` directly.

## 4. Host verification (what is and is not checked)

| Check | Covers | Does not cover |
|---|---|---|
| `panel_smk37_test` | slot wiring, bijection, key window, LED map complete, pad colours and levels, calibration fallback | the real chip registers (stubbed) |
| `ui_pages_smk37_test` | upstream live-UI fuzz through this panel | HAL: its LED/key tables are stubbed |
| `unity_syntax.sh` | whole SLOOP TU compiles against this HAL (names, types) | code generation, timing, pi32v2 intrinsics |

Electrical behaviour (scan timing, LED lines, ADC order) is only checked on
hardware, in the bring-up list above.

## 5. Safety (see docs/gap-analysis.md §3)

- `FELUCCA_FLASH=0`: the FM-1 storage map lies inside this board's app slot.
  The build's link gate refuses flash-writing symbols.

- `make_smk37_fwsc.py` packages only an image that starts with the entry stub,
  fits the app slot, and has a PASS build record with the same SHA-256.
- No flash has been performed. Flashing requires the repo's exact SHA-256
  gate (`exact_ota`), a read-only baseline (`device-info`/dump) and a tested
  rollback. Do not substitute switches.
- `build_smk37.py` refuses SDRAM `0x04000000` sections and any section outside
  the RAM/XIP windows (P0c brick, 2026-08-15 lesson).
