/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): pad colours.
 *
 * The FM-1 lights its function buttons. On the SMK-37 Pro nine of those
 * functions are carried by the RGB pads 1..9 (smk37_map.h), so each switch
 * pad needs its own colour and its own lit / dim / off states. This header is
 * the pure part: the colour of each pad and how the core's LED state
 * (fm1_led / fm1_led_dim / fm1_led_bg, set by ui_leds in ui_input.c) turns
 * into an RGB value. It has no hardware in it, so the host tests run it.
 *
 * Colours follow the LCD: the track colours of the SLOOP screen (blue 1, green
 * 2, yellow 3, orange 4 = drums; SONG colours in ui_song.c), red = recording
 * (never used for a switch, so it means REC only), white = the global HOME.
 *
 *   pad  switch   colour
 *    1   FX       violet
 *    2   ENV      cyan
 *    3   LFO      green
 *    4   EDIT     yellow
 *    5   GLO      orange
 *    6   HOME     white
 *    7   SAVE     pink
 *    8   OCT-     blue
 *    9   OCT+     lime
 *   10..16        off (no function: the pads are free for later layers)
 *
 * Level (scaled into the colour): lit = full, dim (the landmarks of a layer,
 * the drum track's ghost / hard) = 1/4, backlight (menu LIGHTS) = 1/10, off = 0.
 *
 * Output to the pads: smk37_pad_hw.h, [UNVERIFIED] protocol, default NONE.
 */
#pragma once
#include <stdint.h>
#include "smk37_board.h"
#include "smk37_map.h"

typedef struct { uint8_t r, g, b; } smk37_rgb_t;

#define SMK37_PAD_LIT    255u
#define SMK37_PAD_DIM    64u
#define SMK37_PAD_BG     26u

/* physical pad index 0..15 (pad 1..16) -> full-level colour */
static const smk37_rgb_t SMK37_PAD_RGB[16] = {
    {170,  80, 255},   /* pad 1  FX    */
    {  0, 200, 255},   /* pad 2  ENV   */
    { 30, 204, 112},   /* pad 3  LFO   */
    {255, 198,  24},   /* pad 4  EDIT  */
    {255,  98,  26},   /* pad 5  GLO   */
    {255, 255, 255},   /* pad 6  HOME  */
    {255,  60, 150},   /* pad 7  SAVE  */
    { 40, 124, 255},   /* pad 8  OCT-  */
    {150, 255,  40},   /* pad 9  OCT+  */
    /* pads 10..16: no function, black */
    {  0,   0,   0}, {  0,   0,   0}, {  0,   0,   0}, {  0,   0,   0},
    {  0,   0,   0}, {  0,   0,   0}, {  0,   0,   0},
};

/* LED level of one LED cell: 0 off, 1 backlight, 2 dim, 3 lit */
static uint8_t smk37_cell_level(const uint8_t *lit, const uint8_t *dim, const uint8_t *bg,
                                uint32_t col, uint32_t row)
{
    uint8_t m = (uint8_t)(1u << row);
    if (lit[col] & m) return 3u;
    if (dim[col] & m) return 2u;
    if (bg[col] & m)  return 1u;
    return 0u;
}

/* LED cell (col, row) of each switch pad 1..9, precomputed from SMK37_LEDMAP
 * (the panel test checks every entry against the map). The scan ISR runs
 * this every frame, so it must not search the map. */
static const uint8_t SMK37_PAD_CELL[9][2] = {
    {0, 1},  /* pad 1 FX    slot 0  */
    {2, 1},  /* pad 2 ENV   slot 2  */
    {3, 1},  /* pad 3 LFO   slot 3  */
    {0, 2},  /* pad 4 EDIT  slot 4  */
    {1, 2},  /* pad 5 GLO   slot 5  */
    {2, 2},  /* pad 6 HOME  slot 6  */
    {3, 2},  /* pad 7 SAVE  slot 7  */
    {0, 4},  /* pad 8 OCT-  slot 12 */
    {1, 4},  /* pad 9 OCT+  slot 13 */
};

/* RGB of the nine switch pads from the core's LED arrays (ui_input.c ui_leds
 * fills them). Pads 10..16 are always black. */
static void smk37_pad_frame(const uint8_t *lit, const uint8_t *dim, const uint8_t *bg,
                            uint8_t out[16][3])
{
    uint32_t i;
    for (i = 0; i < 16u; i++)
        out[i][0] = out[i][1] = out[i][2] = 0;
    for (i = 0; i < 9u; i++) {
        uint32_t c = SMK37_PAD_CELL[i][0], r = SMK37_PAD_CELL[i][1];
        uint8_t l = smk37_cell_level(lit, dim, bg, c, r);
        uint32_t lv = l == 3u ? SMK37_PAD_LIT : l == 2u ? SMK37_PAD_DIM : l == 1u ? SMK37_PAD_BG : 0u;
        out[i][0] = (uint8_t)((uint32_t)SMK37_PAD_RGB[i].r * lv / 255u);
        out[i][1] = (uint8_t)((uint32_t)SMK37_PAD_RGB[i].g * lv / 255u);
        out[i][2] = (uint8_t)((uint32_t)SMK37_PAD_RGB[i].b * lv / 255u);
    }
}
