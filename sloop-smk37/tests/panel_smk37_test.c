/* SPDX-License-Identifier: GPL-3.0-only
 * SLOOP for SMK-37 Pro: host test of the board map (no chip, no registers).
 *
 * Compiles the real board panel (board/src/panel.c) and the real map tables
 * (board/hal/smk37_map.h) with tiny stubs and pins down:
 *   - the nine FM-1 labels with no silkscreen on the SMK-37 Pro (FX, ENV,
 *     LFO, EDIT, GLO, HOME, SAVE, OCT-, OCT+) are carried by pads 1..9 --
 *     the port's headline requirement -- and the five silkscreen matches
 *     (SCL, ARP, SEQ, PLAY, REC) by their own buttons (SMK37_SLOT_OF);
 *   - pads 10..16, the ten extra silkscreen buttons and K8 stay unassigned;
 *   - the slot table and its LED reverse agree, every slot exactly once;
 *   - panel.btn[] is a permutation of the 14 slots the SLOOP core dispatches
 *     (ui_input.c reads button bits 0..13), and panel_init() rejects a
 *     corrupt learned table;
 *   - the encoder roles are distinct physical encoders, K8 spare;
 *   - the keybed window is exactly the 27-key SLOOP grid (16 white + 11
 *     black), each note key once;
 *   - the scan matrix is a bijection over buttons / pads / keybed, and the
 *     encoder lines carry no key.
 *
 * build: cc -O1 -Wall -I../board/hal panel_smk37_test.c (run_smk37_tests.sh)
 */
#include <stdio.h>
#include <string.h>
#include "smk37_map.h"

/* ---- stubs for the symbols board/src/panel.c borrows from the core ---- */
static volatile uint32_t fm1_ms;
static int32_t fm1_enc_take(uint32_t e) { (void)e; return 0; }
static void fm1_led_key(uint32_t id, int on) { (void)id; (void)on; }
static uint8_t rec_tempo, rec_count, usb_full;
static uint8_t fx_lowcut;
#define NPALETTES 8u
static void palette_set(uint32_t p) { (void)p; }
#include "../board/src/panel.c"

static int fails;
#define CHECK(c, ...) do { if (!(c)) { fails++; printf("FAIL %d: ", __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)

int main(void)
{
    uint32_t i, k;
    uint8_t cnt[69], slot_seen[14];

    panel_init();
    /* the physical wiring: pads 1..9 carry the nine missing FM-1 buttons */
    CHECK(SMK37_SLOT_OF[SMK37_PAD_ID(0)] == 0 && SMK37_SLOT_OF[SMK37_PAD_ID(1)] == 2 &&
          SMK37_SLOT_OF[SMK37_PAD_ID(2)] == 3 && SMK37_SLOT_OF[SMK37_PAD_ID(3)] == 4 &&
          SMK37_SLOT_OF[SMK37_PAD_ID(4)] == 5 && SMK37_SLOT_OF[SMK37_PAD_ID(5)] == 6 &&
          SMK37_SLOT_OF[SMK37_PAD_ID(6)] == 7 && SMK37_SLOT_OF[SMK37_PAD_ID(7)] == 12 &&
          SMK37_SLOT_OF[SMK37_PAD_ID(8)] == 13, "pads 1..9 do not carry the nine missing buttons");
    /* the five silkscreen matches */
    CHECK(SMK37_SLOT_OF[SMK37_B_SCALE] == 1 && SMK37_SLOT_OF[SMK37_B_ARP] == 8 &&
          SMK37_SLOT_OF[SMK37_B_SEQPLAY] == 9 && SMK37_SLOT_OF[SMK37_B_PLAY] == 10 &&
          SMK37_SLOT_OF[SMK37_B_REC] == 11, "silkscreen matches drifted");
    /* every slot exactly once; the reverse table agrees */
    memset(slot_seen, 0, sizeof slot_seen);
    for (i = 0; i < 32; i++)
        if (SMK37_SLOT_OF[i] != SMK37_SLOT_NONE) {
            CHECK(SMK37_SLOT_OF[i] < 14 && !slot_seen[SMK37_SLOT_OF[i]],
                  "physical %u: slot %u twice or bad", i, SMK37_SLOT_OF[i]);
            slot_seen[SMK37_SLOT_OF[i]] = 1;
        }
    for (i = 0; i < 14; i++) {
        CHECK(slot_seen[i], "slot %u has no physical control", i);
        CHECK(SMK37_SLOT_OF[SMK37_PHYS_OF_SLOT[i]] == i, "slot %u: LED reverse disagrees", i);
    }
    /* pads 10..16, the extra silkscreen buttons: unassigned */
    for (i = 9; i < 16; i++)
        CHECK(SMK37_SLOT_OF[SMK37_PAD_ID(i)] == SMK37_SLOT_NONE, "pad %u should stay unassigned", i + 1);
    for (i = 0; i < 16; i++)
        if (i != SMK37_B_ARP && i != SMK37_B_SCALE && i != SMK37_B_PLAY &&
            i != SMK37_B_REC && i != SMK37_B_SEQPLAY)
            CHECK(SMK37_SLOT_OF[i] == SMK37_SLOT_NONE, "button %u should stay unassigned", i);

    /* panel.btn[]: a permutation of the core's 14 button slots */
    memset(slot_seen, 0, sizeof slot_seen);
    for (i = 0; i < NB; i++) {
        CHECK(panel.btn[i] < 14u && !slot_seen[panel.btn[i]], "label %u: slot %u bad/twice",
              i, panel.btn[i]);
        slot_seen[panel.btn[i]] = 1;
    }
    for (i = 0; i < 14; i++)
        CHECK(slot_seen[i], "slot %u carries no label", i);
    CHECK(panel_btn_of(panel.btn[B_HOME]) == B_HOME && panel_btn_of(14) == NB,
          "panel_btn_of wrong");
    for (i = 0; i < NE; i++) {
        uint32_t n = 0, j;
        for (j = 0; j < NE; j++)
            n += panel.enc[j] == panel.enc[i];
        CHECK(n == 1 && panel.enc[i] < 8u && panel.dir[i] == 1, "role %u: encoder bad", i);
    }
    for (k = 0; k < NE; k++)
        CHECK(panel.enc[k] != SMK37_K8, "K8 should stay spare");

    /* keybed window: 27 keys, each note once, 16 white + 11 black */
    {
        uint8_t note[27];
        uint32_t whites = 0, n = 0;
        memset(note, 0, sizeof note);
        for (i = 0; i < 37; i++) {
            int8_t v = SMK37_KEYNOTE[i];
            uint32_t white = (i % 12 == 0 || i % 12 == 2 || i % 12 == 4 || i % 12 == 5 ||
                              i % 12 == 7 || i % 12 == 9 || i % 12 == 11);
            if (v < 0) {
                CHECK(i < SMK37_KEY_WINDOW_LO || i > SMK37_KEY_WINDOW_HI,
                      "key %u spare inside the window", i);
                continue;
            }
            CHECK(v < 27 && !note[v], "key %u: note %d twice or out of range", i, v);
            note[v] = 1;
            n++;
            whites += white;
        }
        CHECK(n == 27, "window has %u keys, not 27", n);
        CHECK(whites == 16, "window has %u white keys, not 16", whites);
    }
    /* scan matrix bijection over buttons / pads / keybed */
    memset(cnt, 0, sizeof cnt);
    for (i = 0; i < SMK37_NROW; i++)
        for (k = 0; k < SMK37_NCOL; k++) {
            int8_t id = SMK37_KEYMAP[i][k];
            if (id < 0)
                continue;
            CHECK(id < 69, "keymap id %d out of range", id);
            cnt[id]++;
        }
    for (i = 0; i < 69; i++)
        CHECK(cnt[i] == 1, "matrix id %u appears %u times", i, cnt[i]);
    for (i = 0; i < 8; i++)
        CHECK(SMK37_KEYMAP[SMK37_ENC[i][1]][SMK37_ENC[i][0]] < 0 &&
              SMK37_KEYMAP[SMK37_ENC[i][3]][SMK37_ENC[i][2]] < 0,
              "encoder %u collides with a key", i);
    CHECK(smk37_map_kind(SMK37_B_ARP) == SMK37_MAP_BTN &&
          smk37_map_kind(SMK37_PAD_ID(3)) == SMK37_MAP_PAD &&
          smk37_map_kind(40) == SMK37_MAP_KEY && smk37_map_kind(200) == SMK37_MAP_NONE,
          "smk37_map_kind wrong");

    /* a corrupt learned table falls back to the default */
    {
        uint8_t good[sizeof panel];
        memcpy(good, &panel, sizeof panel);
        panel.btn[B_FX] = 200;
        panel_init();
        CHECK(memcmp(good, &panel, sizeof panel) == 0, "corrupt table not restored");
        panel.magic ^= 0xFFu;
        panel_init();
        CHECK(memcmp(good, &panel, sizeof panel) == 0, "bad magic not restored");
    }

    if (fails) {
        printf("panel_smk37_test: %d FAIL(s)\n", fails);
        return 1;
    }
    printf("panel_smk37_test: pads 1..9 carry FX ENV LFO EDIT GLO HOME SAVE OCT- OCT+; "
           "SCL/ARP/SEQ/PLAY/REC on silkscreen; 27-key window; matrix bijective; "
           "corrupt calibration falls back\n");
    return 0;
}
