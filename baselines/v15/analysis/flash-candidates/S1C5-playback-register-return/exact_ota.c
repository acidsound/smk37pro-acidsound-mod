/* Exact-hash v15-only OTA wrapper for S1-C5 Playback Register Return.
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x0a, 0x6a, 0xc1, 0xae, 0x7d, 0x4b, 0xd3, 0x4e, 0x25, 0x2e, 0xb8, 0xf2, 0x3a, 0x4d, 0x2c, 0x5f, 0x39, 0xd7, 0x45, 0x43, 0x76, 0xad, 0xe1, 0xa3, 0xb7, 0x5f, 0xf7, 0xd0, 0x31, 0x55, 0xea, 0x91 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN-0A6AC1AE";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C5 Playback Register Return candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) { printf("exact v15 S1-C5 Playback Register Return package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status = 0; } else fputs("offline check rejected: not exact S1-C5 Playback Register Return package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc, char **argv) { if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C5 Playback Register Return candidate installed"); fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM); return 2; }
