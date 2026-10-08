/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): board map tables, pure C.
 *
 * The scan-independent part of the SMK-37 Pro input map: which matrix
 * position is which control, and which keybed key is which SLOOP note key.
 * hal/fm1_input.h (the register glue) and the host tests both build on this;
 * keeping it register-free is what lets tests/panel_smk37_test.c run the
 * mapping on a host with no chip behind it.
 *
 * Evidence: smk37_board.h (rows / strobe / SPI2 word [DECODED] from the stock
 * v15 scan ISR; column count and block order [INFERRED], relearnable on the
 * device by HARDWARE CALIBRATION).
 */
#pragma once
#include <stdint.h>
#include "smk37_board.h"

/* matrix ids: 0..15 silkscreen buttons, 16+pad (16..31) pads, 32+key (32..68)
 * keybed; encoders are addressed by (column, row), not by id */
#define SMK37_NID_MAT 69u
#define SMK37_PAD_ID(p) (16u + (p))

/* THE PADS CARRY THE FM-1 BUTTONS THE SMK-37 PRO DOES NOT HAVE.
 *
 * The SLOOP core dispatches button taps on bits 0..13 of fm1_in.buttons --
 * the fourteen logical FM-1 function buttons (ui_input.c); holds and LEDs go
 * through panel.btn[] into the same space. So the board presents LOGICAL
 * slots in fm1_in.buttons, and this table is the physical wiring of them:
 * slot <- silkscreen button where the SMK-37 Pro has one (SCALE, ARP,
 * SEQ PLAY, PLAY, REC), else <- a pad. Pads 1..9 = FX, ENV, LFO, EDIT, GLO,
 * HOME, SAVE, OCT-, OCT+; pads 10..16 stay unassigned (NONE), as do the ten
 * silkscreen buttons with no FM-1 counterpart (NOTE REPEAT, CHORD, BANK,
 * X/Y, SEQ REC, ENGINE, PRESET, LEFT, RIGHT, FUNCTIONS) and K8 / faders 1..3:
 * every control the FM-1 has is reachable, nothing extra changes behaviour.
 * Slot order = the core's B_* enum (panel.c). */
enum { SMK37_SLOT_NONE = 0xFFu };
static const uint8_t SMK37_SLOT_OF[32] = {
    /*  0 ARP        */ 8,
    /*  1 NOTE REPEAT*/ SMK37_SLOT_NONE,
    /*  2 SCALE      */ 1,
    /*  3 CHORD      */ SMK37_SLOT_NONE,
    /*  4 BANK       */ SMK37_SLOT_NONE,
    /*  5 X/Y        */ SMK37_SLOT_NONE,
    /*  6 PLAY       */ 10,
    /*  7 STOP       */ SMK37_SLOT_NONE,
    /*  8 REC        */ 11,
    /*  9 SEQ PLAY   */ 9,
    /* 10 SEQ REC    */ SMK37_SLOT_NONE,
    /* 11 ENGINE     */ SMK37_SLOT_NONE,
    /* 12 PRESET     */ SMK37_SLOT_NONE,
    /* 13 LEFT       */ SMK37_SLOT_NONE,
    /* 14 RIGHT      */ SMK37_SLOT_NONE,
    /* 15 FUNCTIONS  */ SMK37_SLOT_NONE,
    /* pad 1  (16)   */ 0,              /* FX   */
    /* pad 2  (17)   */ 2,              /* ENV  */
    /* pad 3  (18)   */ 3,              /* LFO  */
    /* pad 4  (19)   */ 4,              /* EDIT */
    /* pad 5  (20)   */ 5,              /* GLO  */
    /* pad 6  (21)   */ 6,              /* HOME */
    /* pad 7  (22)   */ 7,              /* SAVE */
    /* pad 8  (23)   */ 12,             /* OCT- */
    /* pad 9  (24)   */ 13,             /* OCT+ */
    /* pad 10 (25)   */ SMK37_SLOT_NONE,
    /* pad 11 (26)   */ SMK37_SLOT_NONE,
    /* pad 12 (27)   */ SMK37_SLOT_NONE,
    /* pad 13 (28)   */ SMK37_SLOT_NONE,
    /* pad 14 (29)   */ SMK37_SLOT_NONE,
    /* pad 15 (30)   */ SMK37_SLOT_NONE,
    /* pad 16 (31)   */ SMK37_SLOT_NONE,
};
/* the reverse, for LEDs: slot -> physical control (a pad's RGB or a line) */
static const uint8_t SMK37_PHYS_OF_SLOT[14] = {
    16, 2, 17, 18, 19, 20, 21, 22, 0, 9, 6, 8, 23, 24,
};

/* keybed key (chromatic from the low C) -> SLOOP note key 0..26, -1 = spare.
 * The window is F..G two octaves and a second (27 keys: 16 white + 11 black),
 * the same grid shape the FM-1's 25-key keyboard gives SLOOP; on a 37-key bed
 * that is F2..G4, leaving five keys spare at each end. */
static const int8_t SMK37_KEYNOTE[37] = {
    -1, -1, -1, -1, -1,                  /* C2..E2: spare */
     0,  1,  2,  3,  4,  5,  6,          /* F2..B2  */
     7,  8,  9, 10, 11, 12, 13,          /* C3..B3  */
    14, 15, 16, 17, 18, 19, 20,          /* C4..B4  */
    21, 22, 23, 24, 25, 26,              /* F4..G4 (29..31 chromatic) */
    -1, -1, -1, -1, -1,
};
#define SMK37_KEY_WINDOW_LO 5u           /* F2 */
#define SMK37_KEY_WINDOW_HI 31u          /* G4: 27 keys */

/* key id at (row, column), -1 = none. Columns 0..4 the keybed (column-major:
 * key k at (k / 5? no: k = col * 8 + row) -- 37 keys in 5 columns x 8 rows),
 * 5..6 the pads (16..31), 7..9 the silkscreen buttons (0..15); columns 10..11
 * are the encoder quadrature lines (SMK37_ENC) and carry no key ids. */
static const int8_t SMK37_KEYMAP[SMK37_NROW][SMK37_NCOL] = {
    /* c0  c1  c2  c3  c4  c5  c6  c7  c8  c9  c10 c11 */
    { 32, 40, 48, 56, 64, 16, 24,  0,  6, 12, -1, -1},   /* row 0 (PA2) */
    { 33, 41, 49, 57, 65, 17, 25,  1,  7, 13, -1, -1},   /* row 1 (PA5) */
    { 34, 42, 50, 58, 66, 18, 26,  2,  8, 14, -1, -1},   /* row 2 (PA6) */
    { 35, 43, 51, 59, 67, 19, 27,  3,  9, 15, -1, -1},   /* row 3 (PA7) */
    { 36, 44, 52, 60, 68, 20, 28,  4, 10, -1, -1, -1},   /* row 4 (PA9) */
    { 37, 45, 53, 61, -1, 21, 29,  5, 11, -1, -1, -1},   /* row 5 (PH6) */
    { 38, 46, 54, 62, -1, 22, 30, -1, -1, -1, -1, -1},   /* row 6 (PH8) */
    { 39, 47, 55, 63, -1, 23, 31, -1, -1, -1, -1, -1},   /* row 7 (PH9) */
};

/* encoder k (K1..K8): A at (col, row), B at (col, row) */
static const uint8_t SMK37_ENC[8][4] = {
    {10, 0, 11, 0}, {10, 1, 11, 1}, {10, 2, 11, 2}, {10, 3, 11, 3},
    {10, 4, 11, 4}, {10, 5, 11, 5}, {10, 6, 11, 6}, {10, 7, 11, 7},
};

/* matrix id -> what it is, for tests and calibration displays */
enum { SMK37_MAP_NONE = 0, SMK37_MAP_BTN, SMK37_MAP_PAD, SMK37_MAP_KEY };
static int smk37_map_kind(uint32_t id)
{
    if (id < 16u)
        return SMK37_MAP_BTN;
    if (id < 32u)
        return SMK37_MAP_PAD;
    if (id < SMK37_NID_MAT)
        return SMK37_MAP_KEY;
    return SMK37_MAP_NONE;
}
