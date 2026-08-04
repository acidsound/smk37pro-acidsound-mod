/* Exact-hash v15-only OTA wrapper for S1-C7 Current-Set Helper Checkpoint.
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x3d, 0xfb, 0x7e, 0x23, 0xde, 0xbb, 0xd3, 0xa3, 0x05, 0x59, 0x45, 0xb1, 0x21, 0x99, 0x1c, 0xf7, 0xa5, 0x8b, 0x5f, 0x1c, 0xb5, 0x9f, 0xf9, 0x8f, 0x6d, 0xfb, 0xa7, 0xdd, 0x08, 0x4f, 0x25, 0x93 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C7-CURRENT-SET-HELPER-CHECKPOINT-3DFB7E23";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C7 Current-Set Helper Checkpoint candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) { printf("exact v15 S1-C7 Current-Set Helper Checkpoint package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status = 0; } else fputs("offline check rejected: not exact S1-C7 package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc, char **argv) { if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C7 Current-Set Helper Checkpoint candidate installed"); fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM); return 2; }
