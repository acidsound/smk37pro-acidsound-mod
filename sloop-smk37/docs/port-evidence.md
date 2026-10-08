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
4. **[UNVERIFIED] LED line map and pad LEDs** — `smk37_map.h` `SMK37_LEDMAP`.
   The core lights a function by looking its slot up in FM1_KEYMAP (rows 1..4,
   `ui_input.c` `led_pos_init`); the port's LEDMAP places slot s at column
   `s % 4`, row `1 + s / 4`. This layout was assigned, not measured. Bring-up:
   light each slot in turn (`fm1_led_key(slot, 1)`), and check that the LED
   that lights is the intended function. Fix the table where it is not.
   Pads are RGB: if a pad LED is not a single bit of the column word, the pad
   colour path (SPI2 leds word vs a separate RGB line) must be added to
   `fm1_input.h`. Note keys have no LED on this board (by design).
5. **[UNVERIFIED] PC6 codec enable** — `fm1_audio.h`. Confirm audio output
   with the enable pin high. If silent, the enable line is wrong for this board
   and must be re-derived from the v15 codec init (`0x02006762` call sites).
6. **[UNVERIFIED] Velocity / aftertouch path** — keybed velocity and pad
   aftertouch come from the scan timing, not an ADC. Play a dynamic test:
   velocity should track strike speed, aftertouch should track pad pressure.

## 3. Pad-button remapping rationale

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
| `panel_smk37_test` | slot wiring, bijection, key window, LED map complete, calibration fallback | the real chip registers (stubbed) |
| `ui_pages_smk37_test` | upstream live-UI fuzz through this panel | HAL: its LED/key tables are stubbed |
| `unity_syntax.sh` | whole SLOOP TU compiles against this HAL (names, types) | code generation, timing, pi32v2 intrinsics |

Electrical behaviour (scan timing, LED lines, ADC order) is only checked on
hardware, in the bring-up list above.

## 5. Safety

- `make_smk37_fwsc.py` packages only an image that starts with the entry stub,
  fits the app slot, and has a PASS build record with the same SHA-256.
- No flash has been performed. Flashing requires the repo's exact SHA-256
  gate (`exact_ota`), a read-only baseline (`device-info`/dump) and a tested
  rollback. Do not substitute switches.
- `build_smk37.py` refuses SDRAM `0x04000000` sections and any section outside
  the RAM/XIP windows (P0c brick, 2026-08-15 lesson).
