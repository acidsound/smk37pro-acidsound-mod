/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 Leo Kuroshita (@kurogedelic), Hügelton Instruments */
/* SLOOP for SMK-37 Pro ("sloop-smk37"): LCD driver (board level).
 *
 * Shadows sloop-fm1's firmware/src/lcd.c in the unity build, the same way
 * board/src/panel.c shadows the FM-1 panel. Every line below the LCD_SEQ table
 * is a verbatim copy of upstream; ONLY the init sequence differs.
 *
 * WHY: the FM-1 sequence left the ST7789V power and gamma registers at their
 * power-on defaults, which on this panel means the display driver never
 * starts. The installed P1 build showed a black LCD while the pad LEDs ran,
 * which is that failure, not a dead panel.
 *
 * The sequence below is Jieli's own ST7789V init, transcribed from
 * apps/common/ui/lcd_driver/lcd_st7789v.c in the AC79 SDK (V1.0.3/V1.2.0),
 * which docs/research-notes.md records the stock v15 application as matching:
 *   0x11 0x36 0x3A 0x05 0xB2 0xB7 0xBB 0xC2 0xE0 0xE1 0x21.
 * Geometry is confirmed 240x240 by the v15 driver itself: it pumps
 * 0xB40 * 40 = 115200 bytes per frame = 240*240*2, and CASET/RASET span
 * 0x0000..0x00EF = 240.
 * Pins stay as decoded from v15 (D/C = PB5, CS = PC8) via
 * board/hal/fm1_lcd_hw.h.
 *
 * ST7789V-class 240x240 panel on SPI1. Polled DMA transfers; every source
 * buffer must be in RAM. A pixel transfer is left running (lcd_busy): the next
 * LCD access, or a write to its source buffer (lcd_sync), waits for it, so the
 * main loop works while the last strip of a frame goes out. */
/* pins and SPI1: hal/fm1_lcd_hw.h */
#ifndef LCD_BAUD
#define LCD_BAUD 4u                /* lsb/(BAUD+1): 4 = 12 MHz */
#endif

static uint8_t lcd_small[64];
static uint8_t lcd_busy;           /* a lcd_data DMA may still run; CS is low */

static void lcd_spin(uint32_t n)
{
    for (volatile uint32_t i = 0; i < n; i++)
        ;
}

static void lcd_sync(void)          /* finish the running transfer (before touching its buffer) */
{
    if (!lcd_busy)
        return;
    fm1_lcd_wait();
    fm1_lcd_deselect();
    lcd_busy = 0;
}

static void lcd_cmd(uint8_t c)
{
    lcd_sync();
    fm1_lcd_send_cmd(c);
    fm1_lcd_wait();
    fm1_lcd_deselect();
}

static void lcd_data(const void *p, uint32_t n)
{
    if (!n)
        return;                    /* SPI_CNT = 0 never completes */
    lcd_sync();
    fm1_lcd_send_data(p, n);
    lcd_busy = 1;                  /* completed by lcd_sync */
}

static void lcd_window(uint32_t x0, uint32_t y0, uint32_t x1, uint32_t y1)
{
    lcd_sync();
    lcd_small[0] = (uint8_t)(x0 >> 8);
    lcd_small[1] = (uint8_t)x0;
    lcd_small[2] = (uint8_t)(x1 >> 8);
    lcd_small[3] = (uint8_t)x1;
    lcd_cmd(0x2A);
    lcd_data(lcd_small, 4);
    lcd_small[4] = (uint8_t)(y0 >> 8);       /* own bytes: the x transfer may still read [0..3] */
    lcd_small[5] = (uint8_t)y0;
    lcd_small[6] = (uint8_t)(y1 >> 8);
    lcd_small[7] = (uint8_t)y1;
    lcd_cmd(0x2B);
    lcd_data(lcd_small + 4, 4);
    lcd_cmd(0x2C);
}

static uint16_t lcd_fillbuf[240];

static void lcd_fill(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint16_t c)
{
    uint32_t i, n, k, sw = (uint16_t)((c >> 8) | (c << 8));
    if (!w || !h || x >= 240u || y >= 240u)
        return;
    if (x + w > 240u)
        w = 240u - x;
    if (y + h > 240u)
        h = 240u - y;
    lcd_sync();
    k = 240u / w * w;                       /* whole rows per transfer (narrow fills: one DMA) */
    for (i = 0; i < k; i++)
        lcd_fillbuf[i] = (uint16_t)sw;
    lcd_window(x, y, x + w - 1u, y + h - 1u);
    for (n = w * h; n; n -= k) {
        if (k > n)
            k = n;
        lcd_data(lcd_fillbuf, k * 2u);
    }
}

static void lcd_blit(uint32_t x, uint32_t y, uint32_t w, uint32_t h, const uint16_t *px)
{
    if (!w || !h)
        return;
    lcd_window(x, y, x + w - 1u, y + h - 1u);
    lcd_data(px, w * h * 2u);
}

/* Jieli ST7789V init, transcribed from the SDK's lcd_st7789v.c.
 * Format: cmd, n, n data bytes; cmd 0x00 = wait (data byte: ~ms).
 * The power block (0xB2 0xB7 0xBB 0xC2 0xC3 0xC4 0xC6 0xD0) and the gamma
 * block (0xE0 0xE1) are what the FM-1 sequence omitted. COLMOD is 0x05 here,
 * not the FM-1's 0x55. */
static const uint8_t LCD_SEQ[] = {
    0x01, 0,                                                     /* SWRESET */
    0x00, 1, 120,
    0x11, 0,                                                     /* SLPOUT */
    0x00, 1, 120,
    0x36, 1, 0x00,                                               /* MADCTL: top-left, RGB */
    0x3A, 1, 0x05,                                               /* COLMOD: RGB565 */
    0xB2, 5, 0x0c, 0x0c, 0x00, 0x33, 0x33,                       /* porch */
    0xB7, 1, 0x22,                                               /* gate control */
    0xBB, 1, 0x36,                                               /* VCOM */
    0xC2, 1, 0x01,                                               /* power */
    0xC3, 1, 0x19,
    0xC4, 1, 0x20,
    0xC6, 1, 0x0f,                                               /* gate */
    0xD0, 2, 0xa4, 0xa1,                                         /* power */
    0xE0, 14, 0xd0, 0x04, 0x0d, 0x11, 0x13, 0x2b, 0x3f,
              0x54, 0x4c, 0x18, 0x0d, 0x0b, 0x1f, 0x23,           /* gamma + */
    0xE1, 14, 0xd0, 0x04, 0x0c, 0x11, 0x13, 0x2c, 0x3f,
              0x44, 0x51, 0x2f, 0x1f, 0x1f, 0x20, 0x23,           /* gamma - */
    0x21, 0,                                                     /* INVON */
    0x2a, 4, 0x00, 0x00, 0x00, 0xef,                               /* CASET 240 */
    0x2b, 4, 0x00, 0x00, 0x00, 0xef,                               /* RASET 240 */
    0x29, 0,                                                     /* DISPON */
    0x00, 1, 20,
    0x2c, 0,                                                     /* RAMWR */
    0x00, 1, 20,
};

static void lcd_init(void)
{
    uint32_t r, x;
    fm1_lcd_hw_init();
    lcd_spin(2000000u);
    for (r = 0; r < sizeof LCD_SEQ; r += 2u + LCD_SEQ[r + 1u]) {
        if (LCD_SEQ[r] == 0x00u) {                       /* pseudo command: wait */
            lcd_spin(LCD_SEQ[r + 2u] * 25000u);          /* ~1 ms per unit (lcd_spin(3000000) ~ 120 ms) */
            continue;
        }
        lcd_cmd(LCD_SEQ[r]);
        for (x = 0; x < LCD_SEQ[r + 1u]; x++)
            lcd_small[x] = LCD_SEQ[r + 2u + x];
        if (LCD_SEQ[r + 1u])
            lcd_data(lcd_small, LCD_SEQ[r + 1u]);
    }
    fm1_lcd_baud(LCD_BAUD);
    lcd_fill(0, 0, 240, 240, 0);
    lcd_cmd(0x29);
}
