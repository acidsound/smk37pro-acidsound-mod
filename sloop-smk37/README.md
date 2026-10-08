# SLOOP for SMK-37 Pro (`sloop-smk37`)

[English](README.md) | [한국어](README.kr.md)

A custom firmware for the **M-VAVE SMK-37 Pro** that behaves exactly like
[`isod89/sloop-fm1`](https://github.com/isod89/sloop-fm1) (SLOOP 2.4.1, the
FM-1 groovebox firmware): four tracks (three synths + drums), ten engines
including 6-op FM with DX7 patches, the live layers, the sequencer with
parameter locks / micro timing / fills, songs, the web editor protocol, USB
MIDI + USB audio — on the SMK-37 Pro's panel.

The two machines share the JieLi **AC791N / WL82** SoC (pi32v2), so this is a
board-support-package port of SLOOP, not a rewrite: the whole SLOOP core is
used **unmodified** at a pinned upstream commit (`SLOOP_PIN`), and this
directory contributes only what differs — the SMK-37 Pro board HAL, the panel
map, the packaging path and the tests.

> ⚠️ Research port, not yet on hardware. Everything here is offline-verified
> (host tests + static evidence from the stock v15 firmware). Flashing stays
> under this repository's gates: `docs/firmware-runbook.md`,
> `docs/usb-flash-safety-case.md`, exact-hash OTA gate, rollback plan first.
> The repo's hard rule stands: **no live-device writes outside those gates.**

## The panel: pads carry what the silkscreen lacks

The SMK-37 Pro has no silkscreen for nine of the FM-1's fourteen function
buttons. **Those nine live on the pads** — hold a pad for the layer, tap it
for its pages, pad RGB follows the button LED:

| SLOOP (FM-1) | SMK-37 Pro | | SLOOP (FM-1) | SMK-37 Pro |
|---|---|---|---|---|
| FX | **pad 1** | | ARP | ARP button |
| SCL | SCALE button | | SEQ | SEQ PLAY button |
| ENV | **pad 2** | | PLAY | PLAY button |
| LFO | **pad 3** | | REC | REC button |
| EDIT | **pad 4** | | OCT− | **pad 8** |
| GLO | **pad 5** | | OCT+ | **pad 9** |
| HOME | **pad 6** | | SELECT / ALGORITHM / PRESETS knobs | K5 / K6 / K7 |
| SAVE | **pad 7** | | KNOB 1..4 | K1..K4 |
| 27 note keys (F3..G5 grid) | keybed window F2..G4 (16 white + 11 black) | | MASTER pot | fader 4 (MASTER) |

Pads 10–16, K8, faders 1–3, the wheels and the remaining silkscreen buttons
(NOTE REPEAT, CHORD, BANK, X/Y, SEQ REC, ENGINE, PRESET, ◄, ►, FUNCTIONS,
TEACH, RECORDER) are **unassigned by default**: every control the FM-1 has is
reachable, and nothing the FM-1 lacks changes the core's behaviour — the port
operates identically, with the extra hardware idle. The physical→logical
wiring is `board/hal/smk37_map.h` (`SMK37_SLOT_OF[]`); HARDWARE CALIBRATION
(hold pads 8+9 at power-on) permutes labels over slots as upstream.

The SMK-37 Pro has **no TRS MIDI IN** jack (OUT only), so the build defaults
`FELUCCA_UART=0`; `board/hal/fm1_uart.h` still provides the TRS OUT TX path
for a future DIN-side sequencer mirror. The FM-1 in-app updater speaks the
FM-1 installer's wire protocol, so `FELUCCA_OTA=0` here: updates and rollback
go through this repository's own path (`tools/make_smk37_fwsc.py` +
`exact_ota`, forced recovery via `esp32c3-usbkey`).

## Layout

```
sloop-smk37/
├── SLOOP_PIN               pinned upstream commit (PROVENANCE.md)
├── board/
│   ├── hal/                SMK-37 Pro board HAL (shadows the FM-1 board HAL)
│   │   ├── smk37_board.h     pin map + evidence labels ([DECODED]/[INFERRED]/[UNVERIFIED])
│   │   ├── smk37_map.h       pure tables: matrix, key window, pad→slot wiring
│   │   ├── fm1_input.h       scan glue: rows/strobe/SPI2 chain, debounce, quadrature, pad RGB
│   │   ├── fm1_lcd_hw.h      SPI1 LCD, D/C = PB5, CS = PC8, 240x240 RGB565
│   │   ├── fm1_audio.h       ALNK0 -> CS4344 (PC0/1/2/6)
│   │   ├── fm1_adc.h         SARADC: faders, wheels, pedal, battery
│   │   └── fm1_uart.h        TRS MIDI OUT TX (no IN jack on this board)
│   └── src/panel.c         panel table + settings (replaces upstream panel.c)
├── tools/
│   ├── fetch_sloop.py      fetch/verify the pinned upstream tree
│   ├── build_smk37.py      BSP-overlay target build + offline gates
│   └── make_smk37_fwsc.py  pack app.bin into the v15 FWSC container (exact_ota path)
├── tests/
│   ├── panel_smk37_test.c     board-map unit test (host)
│   ├── ui_pages_smk37_test.c  upstream live-UI fuzz, compiled with this panel
│   └── run_smk37_tests.sh
└── docs/port-evidence.md   every board constant and where it was read from
```

Chip-level HAL (GPIO ports, TIMER4/5, IRQ/P33, SFC flash, USB0) is the same
silicon as the FM-1 and comes from upstream untouched; the overlay puts
`board/hal` and `board/src` first on the include path, so `fm1_input.h`,
`fm1_lcd_hw.h`, `fm1_audio.h`, `fm1_adc.h`, `fm1_uart.h` and `panel.c` are the
port's, everything else is upstream's.

## Build and test

```sh
# host tests (no hardware): board map + the upstream UI fuzz on this panel
SLOOP_SRC=/path/to/sloop-fm1 tests/run_smk37_tests.sh     # or: it fetches the pin

# target image (JieLi pi32v2 Linux toolchain; Docker on non-x86_64, as upstream)
JIELI_TOOLCHAIN=~/.jieli/toolchain tools/build_smk37.py

# offline packaging into the SMK-37 Pro v15 OTA container
tools/make_smk37_fwsc.py --app build/smk37-sloop.bin \
    --template /path/to/SMK-37_Pro_015.fwsc --output-dir build
```

`build_smk37.py` gates before it emits anything: entry stub and `_start` at
`0x02000120`, `.ram_text` without calls, image within the 617,012 B v15 app
slot, and — the 2026-08-15 brick lesson (RC-1) — **no section in the SDRAM
window `0x04000000`**, none outside the confirmed RAM/XIP windows.

## Status

- 2026-10-08: port created. Host tests pass (board map; upstream live-UI
  fuzz incl. 20000-frame random use, through the SMK-37 panel).
- Board HAL electrical details carry evidence labels; the [INFERRED] /
  [UNVERIFIED] ones (column count of the scan chain, ADC channel order,
  backlight pin, pad RGB serial path) are the bring-up checklist in
  `docs/port-evidence.md` §8, relearnable on-device where calibration applies.
- Not flashed, not run on hardware: the repo's no-live-device rule stands.

## Licence

GPL-3.0-only, as upstream SLOOP (see `PROVENANCE.md` and upstream
`LICENSING.md`). Upstream copyrights remain with their holders; this port
adds board files under the same licence.
