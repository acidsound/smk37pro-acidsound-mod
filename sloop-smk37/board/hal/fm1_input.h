/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): input HAL (board level).
 *
 * Same interface as sloop-fm1's firmware/hal/fm1_input.h -- the SLOOP core
 * (ui_input.c, ui_layers.c, drums.c, panel.c, main.c) is written against that
 * interface -- with the SMK-37 Pro board behind it:
 *
 *   - 37-key velocity keybed  -> the 27 SLOOP note keys (a 27-key window,
 *     F..G two octaves plus a second: 16 white + 11 black, as the FM-1 grid);
 *   - 16 RGB pads             -> matrix buttons (the FM-1 function buttons
 *     the SMK-37 Pro has no silkscreen for live on the pads: panel.c);
 *   - 16 silkscreen buttons   -> matrix buttons 0..15;
 *   - 8 rotary encoders K1..K8-> fm1_enc_take() quadrature (7 roles + spare);
 *   - 4 faders, 2 wheels, pedal, battery -> SARADC (hal/fm1_adc.h).
 *
 * Electrical scan, from the stock v15 firmware [DECODED, see smk37_board.h]:
 * one packed row byte of eight GPIO inputs (PA2, PA5, PA6, PA7, PA9, PH6, PH8,
 * PH9) per column, PA1 strobe around the read, columns and LED data shifted
 * out as one 4-byte SPI2 DMA word per column (a 595-class chain as on the
 * FM-1, hardware-shifted), raw table kept per (column, row).
 *
 * Debounce and quadrature decoding are the FM-1's, unchanged: a press counts
 * after FM1_DEB_PRESS frames closed in a row, a release after
 * FM1_DEB_RELEASE; one encoder click is one full quadrature cycle back at the
 * detent state learnt at power-on. Only the sampling differs: rows are read
 * here directly from GPIO instead of a diode matrix behind a bit-banged 595.
 *
 *   fm1_input_init();
 *   polled:  for (;;) { fm1_input_scan(); ... }
 *   IRQ:     fm1_input_tick() from the ~10 kHz TIMER5 ISR, one column a call;
 *            the main loop takes edges with fm1_input_edges() /
 *            fm1_input_note_edges() and knob steps with fm1_enc_take().
 */
#pragma once
#include <stdint.h>
#include "fm1_time.h"
#include "fm1_gpio.h"
#include "fm1_cc.h"
#include "smk37_board.h"

#ifndef FM1_INPUT_IDLE
#define FM1_INPUT_IDLE() ((void)0)
#endif
#ifndef FM1_LED_US
#define FM1_LED_US 40u
#endif
#define FM1_DEB_PRESS 2u
#define FM1_DEB_RELEASE 8u
#define FM1_SETTLE_US 10u
#define FM1_REST_FRAMES 900u
#define FM1_NCOL SMK37_NCOL
#define FM1_NKEY SMK37_NID_MAT          /* debounce counters per matrix id */
#define FM1_NENC 7u                      /* roles the core uses; K8 is spare */

/* the tables (keymap, key window, encoder positions) live in smk37_map.h so
 * the host tests can run the mapping with no chip behind them */
#include "smk37_map.h"
#include "smk37_pad_rgb.h"
#include "smk37_pad_hw.h"

/* the core looks LED positions up in FM1_KEYMAP (ui_input.c led_pos_init);
 * on this board that table is the LED map, not the scan map */
#define FM1_KEYMAP SMK37_LEDMAP

static volatile struct {
    uint32_t notes;              /* bit n = SLOOP note key n (0..26) */
    uint32_t buttons;            /* bit i = matrix button i (0..31) */
    uint32_t pressed, released;  /* button edges since fm1_input_edges() */
    uint32_t notes_pressed;      /* note-key press edges */
    uint8_t raw[FM1_NCOL];       /* last frame, packed rows, 1 = closed */
    uint8_t cnt[SMK37_NID_MAT];
    uint8_t enc_prev[8], enc_last[8];
    uint8_t enc_rest[8];
    uint16_t enc_still[8];
    int8_t enc_sub[8];
    int16_t enc_steps[8];        /* + = clockwise */
    uint32_t frames;
} fm1_in;
static uint8_t fm1_led[FM1_NCOL];         /* packed row bits, lit while scanned */
#ifndef FM1_GLOW_NS
#define FM1_GLOW_NS 4000u
#endif
static uint8_t fm1_led_dim[FM1_NCOL];     /* the glow (landmarks) */
static uint8_t fm1_led_bg[FM1_NCOL];      /* the backlight (menu LIGHTS) */
static volatile uint16_t fm1_led_bg_ns;
/* SMK-37 extras the FM-1 has no hardware for; the core ignores them, the web
 * editor / future layers may use them. [UNVERIFIED] sources (ADC burst at
 * note-on); 0 until the bring-up table fills them. */
static uint8_t smk37_pad_out[16][3];       /* pad RGB of this scan (smk37_pad_rgb.h) */
static uint8_t smk37_pad_vel[16], smk37_pad_touch[16];
static uint8_t smk37_key_vel[37];
static uint16_t smk37_fader[SMK37_NFADER], smk37_wheel[SMK37_NWHEEL];

/* ------------------------------------------------------- shift chain ---- */
/* the 4-byte SPI2 word: [cols lo, cols hi, leds lo, leds hi]; columns and
 * LEDs active low as on the FM-1's 595 chain [INFERRED polarity]. */
#define SMK37_SR_CON (*(volatile uint32_t *)0x11E00u)
#define SMK37_SR_ADR (*(volatile uint32_t *)0x11E0Cu)
#define SMK37_SR_CNT (*(volatile uint32_t *)0x11E10u)
static uint8_t smk37_sr_word[4];

static void smk37__sr_put(uint32_t col, uint32_t leds)
{
    uint32_t c = 0xFFFu ^ (col < FM1_NCOL ? 1u << col : 0u);
    smk37_sr_word[0] = (uint8_t)c;
    smk37_sr_word[1] = (uint8_t)(c >> 8);
    smk37_sr_word[2] = (uint8_t)leds;
    smk37_sr_word[3] = (uint8_t)(leds >> 8);
    SMK37_SR_ADR = (uint32_t)(uintptr_t)smk37_sr_word;
    SMK37_SR_CNT = 4u;
}
static void smk37__sr_wait(void)
{
    uint32_t n;
    for (n = 0; n < 4000000u && !(SMK37_SR_CON & 0x8000u); n++)
        ;
    SMK37_SR_CON |= 0x4000u;
}

static const uint8_t SMK37_ROW_PIN[SMK37_NROW][2] = SMK37_ROWS;

static uint32_t smk37__rows(void)
{
    uint32_t r, v = 0;
    for (r = 0; r < SMK37_NROW; r++)
        if (!(FM1_PR(SMK37_ROW_PIN[r][0], FM1_IN) & (1u << SMK37_ROW_PIN[r][1])))
            v |= 1u << r;                  /* low = closed, pull-ups on */
    return v;
}
static void smk37__strobe(int on)
{
    if (on)
        FM1_PR(SMK37_STROBE_PORT, FM1_OUT) |= 1u << SMK37_STROBE_BIT;
    else
        FM1_PR(SMK37_STROBE_PORT, FM1_OUT) &= ~(1u << SMK37_STROBE_BIT);
}
static void smk37__wait(uint32_t us)
{
    uint32_t t0 = fm1_ticks(), span = us * FM1_TICKS_PER_US;
    while ((uint32_t)(fm1_ticks() - t0) < span)
        FM1_INPUT_IDLE();
}

/* --------------------------------------------------------- debouncing ---
 * Buttons debounce in PHYSICAL space (smk37_phys, bit per matrix id 0..31);
 * a flip of a physical button that carries a logical slot (SMK37_SLOT_OF)
 * moves the matching bit of fm1_in.buttons -- the space the SLOOP core
 * dispatches on (ui_input.c reads bits 0..13). Keybed keys debounce straight
 * into fm1_in.notes through SMK37_KEYNOTE. */
static volatile uint32_t smk37_phys;

static void fm1__key(uint32_t id, uint32_t closed)
{
    volatile uint8_t *c = &fm1_in.cnt[id];
    uint32_t note, bit, on;
    int8_t nk;
    if (id < 32u) {
        uint8_t slot = SMK37_SLOT_OF[id];
        if (slot == SMK37_SLOT_NONE)
            return;
        note = 0;
        bit = 1u << slot;
        on = (fm1_in.buttons & bit) != 0u;
    } else {
        nk = SMK37_KEYNOTE[id - 32u];
        if (nk < 0)
            return;
        note = 1;
        bit = 1u << (uint32_t)nk;
        on = (fm1_in.notes & bit) != 0u;
    }
    if (closed == on) {
        *c = 0;
        return;
    }
    if (++*c < (on ? FM1_DEB_RELEASE : FM1_DEB_PRESS))
        return;
    *c = 0;
    if (id < 32u)
        smk37_phys ^= 1u << id;
    if (note) {
        if (!on)
            fm1_in.notes_pressed |= bit;
        fm1_in.notes ^= bit;
    } else {
        fm1_in.buttons ^= bit;
        if (!on)
            fm1_in.pressed |= bit;
        else
            fm1_in.released |= bit;
    }
}
static void fm1__keys(uint32_t p)
{
    uint32_t r, raw = fm1_in.raw[p];
    for (r = 0; r < SMK37_NROW; r++)
        if (SMK37_KEYMAP[r][p] >= 0)
            fm1__key((uint32_t)SMK37_KEYMAP[r][p], (raw >> r) & 1u);
}

static void fm1__frame(void)
{
    uint32_t e;
    /* pad colours from this scan's LED state (9 switches, cheap) */
    smk37_pad_frame(fm1_led, fm1_led_dim, fm1_led_bg, smk37_pad_out);
    smk37_pad_hw_write(smk37_pad_out);
    for (e = 0; e < 8u; e++) {             /* quadrature + detents, as FM-1 */
        const uint8_t *m = SMK37_ENC[e];
        uint32_t cur = ((fm1_in.raw[m[0]] >> m[1]) & 1u) << 1 |
                       ((fm1_in.raw[m[2]] >> m[3]) & 1u);
        uint32_t idx;
        volatile int8_t *sub = &fm1_in.enc_sub[e];
        if (cur != fm1_in.enc_last[e]) {
            fm1_in.enc_last[e] = (uint8_t)cur;
            fm1_in.enc_still[e] = 0;
            continue;
        }
        if (fm1_in.enc_prev[e] == 0xFF) {
            fm1_in.enc_prev[e] = (uint8_t)cur;
            fm1_in.enc_rest[e] = (uint8_t)cur;
        }
        if (fm1_in.enc_still[e] < 0xFFFFu && ++fm1_in.enc_still[e] == FM1_REST_FRAMES &&
            cur != fm1_in.enc_rest[e]) {
            fm1_in.enc_rest[e] = (uint8_t)cur;
            *sub = 0;
        }
        if (cur == fm1_in.enc_prev[e])
            continue;
        idx = (uint32_t)fm1_in.enc_prev[e] << 2 | cur;
        if ((0x4182u >> idx) & 1u)
            (*sub)++;
        else if ((0x2814u >> idx) & 1u)
            (*sub)--;
        else if (*sub > 0)
            *sub = (int8_t)(*sub + 2);
        else if (*sub < 0)
            *sub = (int8_t)(*sub - 2);
        fm1_in.enc_prev[e] = (uint8_t)cur;
        if (*sub > 100 || *sub < -100)
            *sub = 0;
        if (cur == fm1_in.enc_rest[e] && e < FM1_NENC) {
            int32_t n = *sub < 0 ? -*sub : *sub;
            n = n >= 2 ? (n + 2) / 4 : 0;
            fm1_in.enc_steps[e] = (int16_t)(fm1_in.enc_steps[e] + (*sub < 0 ? -n : n));
            *sub = 0;
        }
    }
    fm1_in.frames++;
}

static void fm1_input_init(void)
{
    uint32_t r, i;
    for (r = 0; r < SMK37_NROW; r++) {
        uint32_t p = SMK37_ROW_PIN[r][0], m = 1u << SMK37_ROW_PIN[r][1];
        FM1_PR(p, FM1_DIE) |= m;
        FM1_PR(p, FM1_DIR) |= m;
        FM1_PR(p, FM1_PD) &= ~m;
        FM1_PR(p, FM1_PU) |= m;
    }
    {
        uint32_t m = 1u << SMK37_STROBE_BIT;
        FM1_PR(SMK37_STROBE_PORT, FM1_DIE) |= m;
        FM1_PR(SMK37_STROBE_PORT, FM1_PU) &= ~m;
        FM1_PR(SMK37_STROBE_PORT, FM1_PD) &= ~m;
        FM1_PR(SMK37_STROBE_PORT, FM1_OUT) &= ~m;
        FM1_PR(SMK37_STROBE_PORT, FM1_DIR) &= ~m;
    }
    SMK37_SR_CON = 0x4021u;                /* SPI2 master, as SPI1 in fm1_lcd_hw */
    smk37__sr_put(FM1_NCOL, 0xFFFFu);      /* no column, LEDs dark */
    smk37__sr_wait();
    for (i = 0; i < 8u; i++)
        fm1_in.enc_prev[i] = fm1_in.enc_last[i] = 0xFF;
}

static uint32_t fm1__leds_of(uint32_t p)
{
    return fm1_led[p] | (fm1_led_dim[p] & ~fm1_led[p]) |
           (fm1_led_bg[p] & ~fm1_led[p] & ~fm1_led_dim[p]);
}

static void fm1_input_scan(void)
{
    uint32_t p;
    for (p = 0; p < FM1_NCOL; p++) {
        smk37__sr_put(p, fm1__leds_of(p));
        smk37__strobe(1);
        smk37__wait(FM1_SETTLE_US);
        fm1_in.raw[p] = (uint8_t)smk37__rows();
        smk37__strobe(0);
        fm1__keys(p);
        smk37__sr_wait();
    }
    smk37__sr_put(FM1_NCOL, 0xFFFFu);
    fm1__frame();
}

/* one column per call from the TIMER5 ISR: latch column n, read column p
 * (latched a tick ago), debounce p at once as the FM-1's tick does. */
static uint8_t fm1__tick_col;
static void fm1_input_tick(void)
{
    uint32_t p = fm1__tick_col, n = p + 1u == FM1_NCOL ? 0u : p + 1u;
    smk37__sr_put(n, fm1__leds_of(n));
    smk37__strobe(1);
    fm1_in.raw[p] = (uint8_t)smk37__rows();
    smk37__strobe(0);
    fm1__keys(p);
    fm1__tick_col = (uint8_t)n;
    if (n == 0u)
        fm1__frame();
}

static inline uint32_t fm1__lock(void)
{
    __asm__ volatile("cli" ::: "memory");
    return 0;
}
static inline void fm1__unlock(uint32_t v)
{
    (void)v;
    __asm__ volatile("csync\n\tsti" ::: "memory");
}

static int32_t fm1_enc_take(uint32_t e)
{
    uint32_t k;
    int32_t s;
    if (e >= 8u)
        return 0;
    k = fm1__lock();
    s = fm1_in.enc_steps[e];
    fm1_in.enc_steps[e] = 0;
    fm1__unlock(k);
    return s;
}

static uint32_t fm1_input_edges(uint32_t *released)
{
    uint32_t k = fm1__lock();
    uint32_t p = fm1_in.pressed;
    if (released)
        *released = fm1_in.released;
    fm1_in.pressed = fm1_in.released = 0;
    fm1__unlock(k);
    return p;
}

static uint32_t fm1_input_note_edges(void)
{
    uint32_t k = fm1__lock();
    uint32_t p = fm1_in.notes_pressed;
    fm1_in.notes_pressed = 0;
    fm1__unlock(k);
    return p;
}

/* LED of a logical button slot (0..13): fm1_led[col] bit `row` per
 * SMK37_LEDMAP (smk37_map.h). Note keys (14..40) have no LED on this board:
 * the keybed is unlit; the landmarks the FM-1 keys light show on the LCD. */
static void fm1_led_key(uint32_t id, int on)
{
    uint32_t p, r;
    if (id >= 14u)
        return;
    for (p = 0; p < FM1_NCOL; p++)
        for (r = 1; r < 5u; r++)
            if (SMK37_LEDMAP[r][p] == (int8_t)id) {
                if (on)
                    fm1_led[p] |= (uint8_t)(1u << r);
                else
                    fm1_led[p] &= (uint8_t)~(1u << r);
            }
}
