/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): audio out (board level).
 *
 * Same interface as sloop-fm1's firmware/hal/fm1_audio.h. The SMK-37 Pro and
 * the FM-1 bring ALNK0 (I2S) up in the same register order [DECODED: the v15
 * routine at 0x02007084 is the FM-1's fm1_audio_init() step for step, see
 * smk37_board.h "audio"], into an external codec -- a Cirrus CS4344 here
 * (community teardown) instead of the FM-1's part. The three decoded PC lines
 * are its clock bring-up; PC6 stays as the FM-1's codec enable [UNVERIFIED].
 *
 * The application owns the buffer: two halves of half_words int32
 * (L, R, 24-bit left-justified), zeroed before init.
 *
 *   fm1_audio_init(buf, half_words, isr, prio)
 *   in the ISR: p = fm1_audio_pending(); fm1_audio_ack_aux(p);
 *               if (p & FM1_AUDIO_HALF) { fill fm1_audio_free_half();
 *                                         fm1_audio_ack_half(); }
 *   fm1_audio_stop()      DMA off (crash screen, UBOOT): no looping buzz
 */
#pragma once
#include <stdint.h>
#include "fm1_cc.h"
#include "fm1_time.h"
#include "fm1_irq.h"
#include "fm1_gpio.h"
#include "smk37_board.h"

#define FM1_ALNK 0x12E00u
#define FM1_ALNK_CON0 (*(volatile uint16_t *)(FM1_ALNK + 0x00u))
#define FM1_ALNK_CON1 (*(volatile uint16_t *)(FM1_ALNK + 0x04u))
#define FM1_ALNK_CON2 (*(volatile uint8_t *)(FM1_ALNK + 0x08u))
#define FM1_ALNK_CON3 (*(volatile uint8_t *)(FM1_ALNK + 0x0Cu))
#define FM1_ALNK_ADR3 (*(volatile uint32_t *)(FM1_ALNK + 0x1Cu))
#define FM1_ALNK_LEN (*(volatile uint16_t *)(FM1_ALNK + 0x20u))
#define FM1_CLK_CON2 (*(volatile uint32_t *)0x10014u)
#define FM1_IOMAP_CON5 (*(volatile uint32_t *)0x51030u)
#define FM1_AUDIO_HALF 0x80u

static void fm1__codec_pin(uint32_t bit, int v)
{
    uint32_t m = 1u << bit;
    FM1_PR(SMK37_CODEC_PORT, FM1_DIE) |= m;
    if (v)
        FM1_PR(SMK37_CODEC_PORT, FM1_OUT) |= m;
    else
        FM1_PR(SMK37_CODEC_PORT, FM1_OUT) &= ~m;
    FM1_PR(SMK37_CODEC_PORT, FM1_DIR) &= ~m;
}

FM1_INLINE void fm1_audio_init(int32_t *buf, uint32_t half_words, void (*isr)(void), uint32_t prio)
{
    fm1__codec_pin(SMK37_CODEC_EN, 0);
    fm1_delay_ms(5);
    FM1_ALNK_CON0 = 0;
    FM1_ALNK_CON1 = 0;
    FM1_ALNK_CON2 = 0;
    FM1_ALNK_CON3 = 0;
    FM1_IOMAP_CON5 &= ~0xC0u;
    FM1_ALNK_CON3 |= 3u;
    fm1__codec_pin(SMK37_CODEC_MCLK, 1);
    FM1_ALNK_CON0 |= 0x100u;
    fm1__codec_pin(SMK37_CODEC_LRCK, 1);
    fm1__codec_pin(SMK37_CODEC_SDIN, 1);
    FM1_ALNK_CON0 |= 0x80u;
    FM1_ALNK_CON0 &= ~0x40u;
    FM1_ALNK_LEN = half_words;
    FM1_ALNK_CON0 &= ~0x400u;
    FM1_ALNK_CON0 &= ~0x200u;
    FM1_CLK_CON2 &= 0xFFFFF0FFu;
    FM1_ALNK_CON3 &= ~0x1Cu;
    FM1_ALNK_CON3 = (uint8_t)((FM1_ALNK_CON3 & 0x1Fu) | 0x80u);
    FM1_ALNK_CON1 |= 1u << 12;
    FM1_ALNK_CON1 |= 1u << 14;
    FM1_ALNK_ADR3 = (uint32_t)(uintptr_t)buf;
    fm1__codec_pin(SMK37_CODEC_EN, 1);
    FM1_ALNK_CON1 &= ~(1u << 15);
    FM1_ALNK_CON2 = 0x0Fu;
    fm1_irq_attach(FM1_IRQ_ALNK0, isr, prio);
    FM1_ALNK_CON0 |= 0x800u;
    fm1_delay_ms(5);
    fm1__codec_pin(SMK37_CODEC_EN, 1);
}

FM1_INLINE uint8_t fm1_audio_pending(void) { return FM1_ALNK_CON2; }
FM1_INLINE void fm1_audio_ack_aux(uint8_t p)
{
    if (p & 0x10u)
        FM1_ALNK_CON2 |= 1u;
    if (p & 0x20u)
        FM1_ALNK_CON2 |= 2u;
    if (p & 0x40u)
        FM1_ALNK_CON2 |= 4u;
}
FM1_INLINE uint32_t fm1_audio_free_half(void) { return ((FM1_ALNK_CON0 >> 15) & 1u) ^ 1u; }
FM1_INLINE void fm1_audio_ack_half(void) { FM1_ALNK_CON2 |= 0x08u; }
FM1_INLINE void fm1_audio_stop(void) { FM1_ALNK_CON0 &= ~0x800u; }
