/* SPDX-License-Identifier: GPL-3.0-only
 * sloop-smk37 board override: storage.c is a deliberate no-op.
 *
 * WHY THIS EXISTS
 * ---------------
 * sloop-fm1's felucca.c puts the flash PRIMITIVES (st_read, fl_erase4k_quiet,
 * fl_write) inside "#if FELUCCA_FLASH", together with "#include storage.c".
 * The build script pins FELUCCA_FLASH=0 to keep storage.c out, and its note
 * says why: FM-1's store map puts FL_DATA at 0x97000, which lies INSIDE this
 * board's app-data slot (flash 0x4120 + 617,012 B, ending 0x9AB34). With the
 * real storage.c linked, st_save would erase and program running code.
 *
 * That pins FELUCCA_OTA=0 as well, because felucca.c errors out on
 * "FELUCCA_OTA needs FELUCCA_FLASH". A SLOOP build with OTA off cannot answer
 * the M-UPGRADE upgrade command at all, so once such a build is installed the
 * instrument can only be re-flashed through the Jieli UBOOT mass-storage path
 * -- which is vendor-Windows, and which macOS refuses (libusb claim -3,
 * IOKit kIOReturnExclusiveAccess). One such install ends the macOS session.
 *
 * What we actually want is narrower than FELUCCA_FLASH: the primitives, with
 * storage.c absent. felucca.c's OTA hooks already bound themselves:
 *
 *   ota_erase(off)  -> fl_erase4k_quiet, requires ota_in_area(off, 0x1000)
 *   ota_prog(off,p,n)-> fl_write,      requires ota_in_area(off, n)
 *   ota_fread(off,p,n)-> st_read      (read only)
 *
 * OTA_AREA is 0xE0000..0xE4FFF, well clear of the app-data slot above. So the
 * three hooks can write the staging area and nothing else.
 *
 * This file therefore replaces the preset store with functions that always
 * fail. Every caller is written to handle that: editor.c and fm6_bank.c test
 * the return value and report "SAVE ERROR"; project.c reports "SAVE ERROR".
 * Nothing can erase or program a preset sector, because the only code that
 * could is not linked.
 *
 * The instrument has never stored presets or calibration (docs/
 * v16-install-brick-restore-record.md), so failing the save is also the
 * honest answer rather than a silent loss.
 */
#include <stdint.h>

static int st_load(uint32_t obj, void *dst, uint32_t max)
{
    (void)obj; (void)dst; (void)max;
    return -1;                      /* no store: nothing to load */
}

static int st_save(uint32_t obj, const void *src, uint32_t len)
{
    (void)obj; (void)src; (void)len;
    return -1;                      /* no store: refuse every write */
}
/* The constants and object ids below are copied verbatim from FM-1's
 * storage.c (lines 14-24). They are layout constants, not behaviour: keeping
 * them lets project.c, editor.c and fm6_bank.c compile unchanged while the two
 * functions above refuse to do anything. Without these the build fails on
 * OBJ_SETTINGS, OBJ_PROJECT0 and the _Static_assert on ST_PAYLOAD_MAX. */
#define ST_MAGIC 0x554C4546u                   /* "FELU" */
#define ST_SECTOR 4096u
#define ST_PAYLOAD_OFF 256u
#define ST_PAYLOAD_MAX (ST_SECTOR - ST_PAYLOAD_OFF)

enum { OBJ_SETTINGS, OBJ_PROJECT0, OBJ_UPRESET0 = OBJ_PROJECT0 + 4,
       OBJ_AUTOSAVE = OBJ_UPRESET0 + 2, OBJ_FM6BANK, OBJ_COUNT };
/* fm6_bank.c reads the FM6 patch bank through st_current and st_buf. With no
 * store there is nothing to read, so st_current always fails; st_buf stays
 * declared only so fm6_bank.c compiles and reads zeros. */
typedef struct {
    uint32_t magic;
    uint16_t type, slot;
    uint32_t seq, len, crc, rsv[2];
    uint32_t hcrc;
} st_hdr_t;

static uint8_t st_buf[ST_PAYLOAD_MAX] __attribute__((aligned(4)));

static int st_current(uint32_t obj, st_hdr_t *h)
{
    (void)obj; (void)h;
    return -1;                      /* no store: no current copy */
}
/* editor.c's ed_bk_obj() maps an object to its flash offset before deciding
 * where to write. Returning UINT32_MAX marks every object as having no valid
 * location, which the caller treats as no store. */
#define ST_NO_OFFSET 0xFFFFFFFFu

static uint32_t st_sector(uint32_t obj, uint32_t copy)
{
    (void)obj; (void)copy;
    return ST_NO_OFFSET;
}

/* editor.c's ed_handle() stamps a CRC into the header it is about to write.
 * Nothing here is ever written, so the value only has to be the correct
 * CRC-32 (zlib form: reflected, init/xorout 0xFFFFFFFF) rather than a wrong
 * one that would look like a bug if it ever reached the screen. Bitwise form,
 * matching FM-1's storage.c without pulling in its table. */
static uint32_t st_crc32(const void *p, uint32_t n)
{
    static const uint32_t POLY = 0xEDB88320u;
    const uint8_t *b = (const uint8_t *)p;
    uint32_t c = 0xFFFFFFFFu;

    for (uint32_t i = 0; i < n; i++) {
        c ^= b[i];
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? (c >> 1) ^ POLY : c >> 1;
    }
    return c ^ 0xFFFFFFFFu;
}

