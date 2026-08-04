/* Exact-hash v15-only OTA wrapper for S1-C5 Marked Playback Note.
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0xcf, 0xaf, 0xa3, 0x27, 0x3c, 0xa0, 0xba, 0x74, 0x16, 0x16, 0xe5, 0xf3, 0xaa, 0x87, 0xf2, 0x62, 0xa4, 0x5e, 0xcd, 0x84, 0x44, 0x5b, 0xde, 0xfd, 0x96, 0x99, 0x00, 0xda, 0xd2, 0x56, 0xb4, 0x80 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C5-MARKED-PLAYBACK-CFAFA327";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C5 Marked Playback Note candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) { printf("exact v15 S1-C5 Marked Playback Note package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status = 0; } else fputs("offline check rejected: not exact S1-C5 Marked Playback Note package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc, char **argv) { if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C5 Marked Playback Note candidate installed"); fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM); return 2; }
