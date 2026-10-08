/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): SARADC (board level).
 *
 * Same interface as sloop-fm1's firmware/hal/fm1_adc.h. The multiplexed
 * analog scan is [DECODED] (the v15 scan ISR steps the ADC channel each tick,
 * ADC CON = 0x407D | ch << 8, smk37_board.h "input"); the channel order below
 * is the bring-up table [UNVERIFIED] and is what HARDWARE CALIBRATION and a
 * bench sweep settle. 10 bit, polled from the main loop.
 *
 *   fm1_adc_init()        the analog pins as inputs, no pulls
 *   fm1_adc_read(ch)      0..1023, -1 on timeout
 *
 * main.c reads FM1_ADC_BATT (battery icon) and FM1_ADC_MASTER (the master
 * level: on the SMK-37 Pro that is fader 4, silkscreen MASTER).
 */
#pragma once
#include <stdint.h>
#include "fm1_gpio.h"
#include "smk37_board.h"

#define FM1_ADC_CON (*(volatile uint32_t *)0x13100u)
#define FM1_ADC_RES (*(volatile uint32_t *)0x13104u)
#define FM1_WLA_CON0 (*(volatile uint32_t *)0x11900u)

/* The SMK-37 Pro's analog controls are on an external mux [INFERRED]: the
 * channel select reaches the SARADC as one 4-bit field, as on the FM-1. */
static void fm1_adc_init(void)
{
    /* every analog pin: input, no pull, digital input off. The pin list is
     * the bring-up table; an unused entry costs nothing. [UNVERIFIED] */
    static const uint8_t PIN[SMK37_ADC_N][2] = {
        {1, 1}, {1, 2}, {1, 3}, {1, 6},         /* FADER1..3, MASTER: PB1, PB2, PB3, PB6 */
        {0, 0}, {0, 5},                         /* pitch, mod wheel: PA0, PA5 (mux sel) */
        {7, 7}, {1, 1},                         /* pedal: PH7; battery: PB1 divider */
    };
    uint32_t i;
    for (i = 0; i < SMK37_ADC_N; i++) {
        uint32_t p = PIN[i][0], m = 1u << PIN[i][1];
        FM1_PR(p, FM1_DIE) &= ~m;
        FM1_PR(p, FM1_PU) &= ~m;
        FM1_PR(p, FM1_PD) &= ~m;
        FM1_PR(p, FM1_DIR) |= m;
    }
}

static int32_t fm1_adc_read(uint32_t ch)
{
    uint32_t t, v;
    if (ch >= SMK37_ADC_N)
        return -1;
    FM1_ADC_CON = 0;
    if (FM1_WLA_CON0 & (1u << 14))
        FM1_WLA_CON0 &= ~(1u << 14);
    FM1_ADC_CON = 0xF04Eu | ((ch & 0xFu) << 8);
    FM1_ADC_CON |= 0x10u;
    FM1_ADC_CON |= 0x40u;
    for (t = 0; t < 20000u; t++)
        if (FM1_ADC_CON & 0x80u)
            break;
    v = FM1_ADC_RES & 0x3FFu;
    FM1_ADC_CON = 0x40u;
    FM1_ADC_CON = 0;
    return t == 20000u ? -1 : (int32_t)v;
}
