/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): M-VAVE SMK-37 Pro board map.
 *
 * Single source of truth for every board-level constant of this port. The
 * chip-level HAL (GPIO ports, TIMER4/5, IRQ, P33, SFC, USB0, ALNK0, SPI1/2,
 * SARADC, UART) is the JieLi AC791N/WL82 one and is taken unchanged from
 * upstream sloop-fm1 (same SoC family as the M-VAVE FM-1); this header only
 * says WHICH PINS / WHICH CHANNELS / WHICH MATRIX the SMK-37 Pro board uses.
 *
 * EVIDENCE LABELS (repo convention, docs/research-notes.md):
 *   [DECODED]    read out of the stock SMK-37 Pro v15 application this session
 *                (baselines/v15/analysis/quarkslab recursive listing), with the
 *                exact firmware address quoted. Reproduce with
 *                sloop-smk37/docs/port-evidence.md §9.
 *   [INFERRED]   several independent facts agree; a board measurement is still
 *                missing.
 *   [UNVERIFIED] plausible default; must be confirmed at board bring-up. The
 *                on-device HARDWARE CALIBRATION (hold OCT- + OCT+ at power-on,
 *                i.e. pads 8 + 9) can relearn every [INFERRED]/[UNVERIFIED]
 *                table entry without a new firmware build.
 *
 * The SMK-37 Pro (M-VAVE) and the FM-1 (M-VAVE) share the AC791N/WL82 SoC, so
 * a SLOOP port is a board-support-package job: same chip HAL, new board HAL.
 */
#pragma once
#include <stdint.h>

/* ---------------------------------------------------------------- LCD ----
 * [DECODED] v15 FUN_0201e846 (0x0201e846..0x0201e95e) is the panel driver:
 *   r0 = 0x50040 (PORTB), r0+0x40 = 0x50080 (PORTC), r1 = 0x11D00 (SPI1);
 *   command byte: PB5 = 0 (D/C low), PC8 = 0 (CS low), SPI1_BUF = cmd,
 *                 wait done, PC8 = 1 (deselect);
 *   data:         PB5 = 1 (D/C high), PC8 = 0, SPI1_ADR = buf, SPI1_CNT = n;
 *   0x2A CASET / 0x2B RASET get 0x0000..0x00F0 (240), 0x2C RAMWR is pumped
 *   0xB40 times 40 B = 115200 B = 240*240*2 -> 240x240 RGB565, ST7789V class
 *   (docs/research-notes.md "LCD and UI research").
 * [DECODED] v15 0x0201de40: IOMAP_CON1 (0x51020) |= 0x10 -> SPI1 CLK/DO on
 *   the IOMAP'd pins, exactly like fm1_lcd_hw_init() of the FM-1; 0x0201de3c
 *   writes SPI1_BAUD (0x11D04) = 8 before the init sequence.
 * So: SPI1 on the IOMAP pins, D/C = PB5, CS = PC8 (the FM-1 has D/C = PC8,
 * CS = PC7: the only wiring difference).
 */
#define SMK37_LCD_SPI      1u          /* SPI1: 0x11D00 block (fm1_lcd_hw.h) */
#define SMK37_LCD_DC_PORT  1u          /* PB */
#define SMK37_LCD_DC_BIT   5u          /* [DECODED] D/C, 0 = command */
#define SMK37_LCD_CS_PORT  2u          /* PC */
#define SMK37_LCD_CS_BIT   8u          /* [DECODED] CS, active low */
#define SMK37_LCD_W        240u        /* [DECODED] CASET/RASET 0..0xF0 */
#define SMK37_LCD_H        240u
/* Backlight: no GPIO toggle was found in the v15 LCD driver [INFERRED: the
 * panel backlight is on from the power rail, as on every photo of a powered
 * unit]. -1 = no GPIO: fm1_lcd_hw_init() leaves it alone. Set to a port/bit
 * pair at bring-up if a toggle is found (active low, like the FM-1's PA2). */
#define SMK37_LCD_BL_PORT  (-1)
#define SMK37_LCD_BL_BIT   0u
#ifndef LCD_BAUD
#define LCD_BAUD 4u                    /* lsb/(BAUD+1): the FM-1's 12 MHz */
#endif

/* -------------------------------------------------------------- audio ----
 * [DECODED] v15 FUN at 0x02007084..0x0200713c is byte-for-byte the FM-1's
 * fm1_audio_init(): ALNK0 (0x12E00) CON0..CON3 = 0, IOMAP_CON5 (0x51030) &=
 * ~0xC0, CON3 |= 3, then GPIO pin 0x20 (PC0), CON0 |= 0x100, pin 0x22 (PC2),
 * pin 0x21 (PC1), CON0 |= 0x80 / &= ~0x40, LEN, CON0 &= ~0x400 / ~0x200,
 * CLK_CON2 (0x10014) &= ~0xF00, CON3 = (CON3 & 0x1F) | 0x80, CON1 |= 0x1000 /
 * 0x4000, ADR3, CON1 &= ~0x8000, CON2 = 0x0F, CON0 |= 0x800.
 * The external codec is a Cirrus CS4344 (community teardown, README of
 * jonathaslacerda/smk-37-pro-docs); the three PC lines are its clock/reset
 * bring-up, as on the FM-1's codec. PC6 (the FM-1's codec enable) was not
 * seen in the decoded window [UNVERIFIED: kept, harmless if unconnected].
 */
#define SMK37_CODEC_PORT   2u          /* PC */
#define SMK37_CODEC_MCLK   0u          /* [DECODED] PC0 */
#define SMK37_CODEC_LRCK   2u          /* [DECODED] PC2 */
#define SMK37_CODEC_SDIN   1u          /* [DECODED] PC1 */
#define SMK37_CODEC_EN     6u          /* [UNVERIFIED] PC6, as the FM-1 */

/* -------------------------------------------------------------- input ----
 * [DECODED] v15 ISR 0x0201bce6..0x0201bdc8 (ends in rti) is the control scan:
 *   - PA1 is driven as a strobe (PA_OUT |= 2 ... &= ~2 around the read);
 *   - one packed row byte is assembled from PA2, PA5, PA6, PA7, PA9, PH6,
 *     PH8, PH9 (eight inputs: the shifts/masks 0x03, 0x0E, 0x10, 0x20, 0xC0
 *     in the ISR) and stored in a raw table indexed (column << 4) + row;
 *   - columns and LED data go out as one 4-byte SPI2 (0x11E00) DMA word
 *     (SPI2_ADR / SPI2_CNT = 4), i.e. a shift-register chain as on the FM-1,
 *     but hardware-shifted instead of bit-banged;
 *   - a SARADC channel is stepped each tick (ADC CON = 0x407D | ch << 8),
 *     the multiplexed analog side (faders, wheels, pedal).
 * [INFERRED] column count 12 and the block assignment below: 5 columns of
 * keybed (40 positions >= 37 keys), 2 of pads (16), 3 of buttons (18), 2 of
 * encoder quadrature (16) = 96 = 12 x 8. The count/assignment is what the
 * calibration mode relearns; the rows, the strobe and the SPI2 word are the
 * decoded part.
 */
#define SMK37_NROW   8u
#define SMK37_NCOL   12u
#define SMK37_STROBE_PORT 0u           /* PA */
#define SMK37_STROBE_BIT  1u           /* [DECODED] PA1 */
/* row input lines, packed bit -> GPIO (packed order as stored by the ISR) */
#define SMK37_ROWS  { {0, 2}, {0, 5}, {0, 6}, {0, 7}, {0, 9}, {7, 6}, {7, 8}, {7, 9} }
/* SPI2: the column/LED shift chain */
#define SMK37_SR_SPI 2u                /* SPI2: 0x11E00 block */

/* matrix ids, one uint32_t button bitmask as the SLOOP core expects:
 * 0..15 the silkscreen buttons (SMK37_B_*), 16+pad (16..31) the pads,
 * 32+key the keybed (SMK37_KEYNOTE decides the SLOOP note key), encoders by
 * (column, row) position in SMK37_ENC. Pads therefore start where the buttons
 * end: 18 buttons + 16 pads = 32 bits exactly. */
#define SMK37_BTN0   0u
#define SMK37_PAD0   16u
#define SMK37_KEY0   32u

/* the 16 silkscreen buttons that live in the matrix, panel order (photo of
 * the panel, official-1.jpg of jonathaslacerda/smk-37-pro-docs). TEACH and
 * RECORDER have no matrix position: the button bitmask is 32 bits wide (the
 * SLOOP core's uint32_t) and 16 buttons + 16 pads fill it exactly; they are
 * bring-up candidates for the spare keybed keys (calibration). */
enum {
    SMK37_B_ARP = 0, SMK37_B_NOTEREP, SMK37_B_SCALE, SMK37_B_CHORD,
    SMK37_B_BANK, SMK37_B_XY, SMK37_B_PLAY, SMK37_B_STOP, SMK37_B_REC,
    SMK37_B_SEQPLAY, SMK37_B_SEQREC, SMK37_B_ENGINE, SMK37_B_PRESET,
    SMK37_B_LEFT, SMK37_B_RIGHT, SMK37_B_FUNC, SMK37_NBTN = 16
};
/* the 8 rotary encoders K1..K8 and the 4 faders: analog/quadrature roles */
enum { SMK37_K1 = 0, SMK37_K2, SMK37_K3, SMK37_K4, SMK37_K5, SMK37_K6,
       SMK37_K7, SMK37_K8, SMK37_NENC_PHYS = 8 };
enum { SMK37_F1 = 0, SMK37_F2, SMK37_F3, SMK37_FMASTER, SMK37_NFADER = 4 };
enum { SMK37_W_PITCH = 0, SMK37_W_MOD, SMK37_NWHEEL = 2 };

/* SARADC channels [UNVERIFIED channel numbers; the multiplexed-analog scan is
 * [DECODED], the channel order is a bring-up table]. 10-bit, polled. */
enum {
    SMK37_ADC_FADER1 = 0, SMK37_ADC_FADER2, SMK37_ADC_FADER3,
    SMK37_ADC_MASTER,                  /* fader 4, the silkscreen MASTER */
    SMK37_ADC_PITCH, SMK37_ADC_MOD, SMK37_ADC_PEDAL,
    SMK37_ADC_BATT,                    /* battery divider */
    SMK37_ADC_N = 8
};
#define FM1_ADC_BATT   SMK37_ADC_BATT      /* the names main.c uses */
#define FM1_ADC_MASTER SMK37_ADC_MASTER
