/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro ("sloop-smk37"): LCD wiring (board level).
 *
 * Same interface as sloop-fm1's firmware/hal/fm1_lcd_hw.h; src/lcd.c (the
 * ST7789V panel protocol, 240x240 RGB565) is reused unchanged.
 *
 * SMK-37 Pro wiring, [DECODED] from the stock v15 application
 * (smk37_board.h "LCD"): SPI1 on the IOMAP'd pins (IOMAP_CON1 |= 0x10, the
 * same bit the FM-1 sets), D/C = PB5, CS = PC8, backlight on from the rail
 * (no GPIO found; SMK37_LCD_BL_PORT = -1).
 *
 *   fm1_lcd_hw_init()          pins, SPI1 master at BAUD 4
 *   fm1_lcd_baud(b)            SPI1 clock = lsb / (b + 1)
 *   fm1_lcd_send_cmd(c)        D/C low, CS low, one byte
 *   fm1_lcd_send_data(p, n)    D/C high, CS low, DMA n bytes from RAM p
 *   fm1_lcd_wait()             SPI done (or timeout, counted), pending cleared
 *   fm1_lcd_deselect()         CS high
 */
#pragma once
#include <stdint.h>
#include "fm1_cc.h"
#include "smk37_board.h"

#define FM1_LCD_PC_OUT (*(volatile uint32_t *)0x50080u)
#define FM1_LCD_PC_DIR (*(volatile uint32_t *)0x50088u)
#define FM1_LCD_PB_OUT (*(volatile uint32_t *)0x50040u)
#define FM1_LCD_PB_DIR (*(volatile uint32_t *)0x50048u)
#define FM1_LCD_IOMAP_CON1 (*(volatile uint32_t *)0x51020u)
#define FM1_LCD_SPI_CON (*(volatile uint32_t *)0x11D00u)
#define FM1_LCD_SPI_BAUD (*(volatile uint32_t *)0x11D04u)
#define FM1_LCD_SPI_BUF (*(volatile uint32_t *)0x11D08u)
#define FM1_LCD_SPI_ADR (*(volatile uint32_t *)0x11D0Cu)
#define FM1_LCD_SPI_CNT (*(volatile uint32_t *)0x11D10u)
#define FM1_LCD_CS (1u << SMK37_LCD_CS_BIT)
#define FM1_LCD_DC (1u << SMK37_LCD_DC_BIT)

static uint32_t fm1_lcd_timeouts;

FM1_INLINE void fm1_lcd_hw_init(void)
{
#if SMK37_LCD_BL_PORT >= 0
    FM1_PR(SMK37_LCD_BL_PORT, FM1_OUT) &= ~(1u << SMK37_LCD_BL_BIT);   /* active low */
    FM1_PR(SMK37_LCD_BL_PORT, FM1_DIR) &= ~(1u << SMK37_LCD_BL_BIT);
#endif
    FM1_LCD_IOMAP_CON1 |= 0x10u;             /* [DECODED] v15 0x0201de40 */
    FM1_LCD_PC_OUT |= FM1_LCD_CS;
    FM1_LCD_PC_DIR &= ~FM1_LCD_CS;
    FM1_LCD_PB_OUT &= ~FM1_LCD_DC;
    FM1_LCD_PB_DIR &= ~FM1_LCD_DC;
    FM1_LCD_SPI_CON = 0x4021u;
    FM1_LCD_SPI_BAUD = 4u;
}

FM1_INLINE void fm1_lcd_baud(uint32_t b) { FM1_LCD_SPI_BAUD = b; }

static void fm1_lcd_wait(void)
{
    uint32_t n;
    for (n = 0; n < 4000000u && !(FM1_LCD_SPI_CON & 0x8000u); n++)
        ;
    if (n == 4000000u)
        fm1_lcd_timeouts++;
    FM1_LCD_SPI_CON |= 0x4000u;
}

FM1_INLINE void fm1_lcd_deselect(void) { FM1_LCD_PC_OUT |= FM1_LCD_CS; }

FM1_INLINE void fm1_lcd_send_cmd(uint8_t c)
{
    FM1_LCD_PB_OUT &= ~FM1_LCD_DC;           /* D/C low: command */
    FM1_LCD_PC_OUT &= ~FM1_LCD_CS;
    FM1_LCD_SPI_CON |= 0x4000u;
    FM1_LCD_SPI_BUF = c;
}
FM1_INLINE void fm1_lcd_send_data(const void *p, uint32_t n)
{
    FM1_LCD_PB_OUT |= FM1_LCD_DC;            /* D/C high: pixel / parameter */
    FM1_LCD_PC_OUT &= ~FM1_LCD_CS;
    FM1_LCD_SPI_CON |= 0x4000u;
    FM1_LCD_SPI_ADR = (uint32_t)(uintptr_t)p;
    FM1_LCD_SPI_CNT = n;
}
