/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): UART1 MIDI (board level).
 *
 * The SMK-37 Pro rear panel has a 3.5 mm TRS MIDI **OUT** (type A) and no
 * MIDI IN jack (community docs, rear-panel photo): the FM-1's "TRS MIDI IN"
 * role has no hardware here. The build therefore defaults FELUCCA_UART=0
 * (tools/build_smk37.py) and the SLOOP core behaves exactly as an FM-1 with
 * no TRS in: MIDI arrives on USB only.
 *
 * This header still provides the upstream interface (so a build with
 * FELUCCA_UART=1 compiles and simply never sees a byte: RX on an unconnected
 * pin with its pull-up idles high) plus the board extension the SMK-37 Pro
 * hardware actually offers: UART1 TX to the TRS OUT jack, for a future
 * "sequencer to MIDI out" on the DIN side (G_MIDI today mirrors to USB).
 *
 *   fm1_uart1_midi_init(ring, len)   as upstream; len a power of two
 *   fm1_uart1_rx_take()              bytes DMA'd since the last call
 *   smk37_midi_tx(p, n)              polled TX to the TRS OUT jack
 */
#pragma once
#include <stdint.h>
#include "fm1_cc.h"

#define FM1_UT1_CON0   (*(volatile uint32_t *)0x12100u)
#define FM1_UT1_CON1   (*(volatile uint32_t *)0x12104u)
#define FM1_UT1_BAUD   (*(volatile uint32_t *)0x12108u)
#define FM1_UT1_OTCNT  (*(volatile uint32_t *)0x12110u)
#define FM1_UT1_RXSADR (*(volatile uint32_t *)0x1211Cu)
#define FM1_UT1_RXEADR (*(volatile uint32_t *)0x12120u)
#define FM1_UT1_RXCNT  (*(volatile uint32_t *)0x12124u)
#define FM1_UT1_HRXCNT (*(volatile uint32_t *)0x12128u)
#define FM1_UT1_TXADR  (*(volatile uint32_t *)0x12114u)
#define FM1_UT1_TXCNT  (*(volatile uint32_t *)0x12118u)
#define FM1_UM_CLK_CON1  (*(volatile uint32_t *)0x10010u)   /* [11:10] UART clock: 1 = PLL48M */
#define FM1_UM_IOMAP2    (*(volatile uint32_t *)0x51024u)   /* input ch1 source [13:8] */
#define FM1_UM_IOMAP3    (*(volatile uint32_t *)0x51028u)   /* UT1: b7 fixed IO, [6:4] RX/TX select */
#define FM1_UM_PH_DIR    (*(volatile uint32_t *)0x501C8u)
#define FM1_UM_PH_DIE    (*(volatile uint32_t *)0x501CCu)
#define FM1_UM_PH_PU     (*(volatile uint32_t *)0x501D0u)
#define FM1_UM_PH_PD     (*(volatile uint32_t *)0x501D4u)

FM1_INLINE void fm1_uart1_midi_init(volatile uint8_t *ring, uint32_t len)
{
    FM1_UT1_CON0 = 0x3400u;                            /* off, pendings cleared */
    FM1_UT1_CON1 = 0;
    FM1_UM_CLK_CON1 = (FM1_UM_CLK_CON1 & ~(3u << 10)) | (1u << 10);
    FM1_UT1_BAUD = 0x10000u * 3u / 4u;                 /* 31250 baud at 48 MHz / 16 */
    FM1_UM_IOMAP3 = (FM1_UM_IOMAP3 & ~0x70u) | 0x10u;  /* UT1 RX on the fixed IO */
    FM1_UM_PH_DIR |= 1u << 8;                          /* PH8: input, no jack behind it */
    FM1_UM_PH_DIE |= 1u << 8;
    FM1_UM_PH_PU |= 1u << 8;
    FM1_UM_PH_PD &= ~(1u << 8);
    FM1_UT1_RXSADR = (uint32_t)(uintptr_t)ring;
    FM1_UT1_RXEADR = (uint32_t)(uintptr_t)(ring + len);
    FM1_UT1_CON0 = 0x3400u | 0x800u | 0x10u;           /* RX DMA on */
}

FM1_INLINE uint32_t fm1_uart1_rx_take(void)
{
    uint32_t n = FM1_UT1_RXCNT;
    FM1_UT1_CON0 |= 0x2400u;                           /* clear the RX pendings */
    return n;
}

/* TRS MIDI OUT (type A): polled, called from the main loop only. */
static void smk37_midi_tx(const uint8_t *p, uint32_t n)
{
    uint32_t t;
    if (!n)
        return;
    FM1_UM_IOMAP3 |= 0x80u;                            /* UT1 TX on the fixed IO */
    FM1_UT1_TXADR = (uint32_t)(uintptr_t)p;
    FM1_UT1_TXCNT = n;
    for (t = 0; t < 400000u; t++)
        if (FM1_UT1_CON0 & 0x400u)                     /* TX done pending */
            break;
    FM1_UT1_CON0 |= 0x400u;
}
