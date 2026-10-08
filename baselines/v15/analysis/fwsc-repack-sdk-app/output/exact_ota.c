/* Exact-hash v15-only OTA wrapper for SMK-OTA-RECOVERY.
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x67, 0x3d, 0xa1, 0xd5, 0x18, 0xef, 0xf4, 0x94, 0xd0, 0xcf, 0x63, 0xc5, 0x49, 0xd0, 0xcc, 0xff, 0xd6, 0x3f, 0x5a, 0x87, 0x64, 0xf4, 0x9f, 0xfa, 0x60, 0xd0, 0xd4, 0xd2, 0x83, 0xaf, 0x33, 0xbb };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-SMK-OTA-RECOVERY-673DA1D5";
static const char DESCRIPTION[] = "Jieli SDK app substitution";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) { printf("exact v15 SMK-OTA-RECOVERY package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status = 0; } else fputs("offline check rejected: not exact SMK-OTA-RECOVERY package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc, char **argv) { if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 SMK-OTA-RECOVERY installed"); fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM); return 2; }
