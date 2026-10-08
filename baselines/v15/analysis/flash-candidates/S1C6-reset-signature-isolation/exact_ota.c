/* Exact-hash v15-only OTA wrapper for S1-C6 Reset Signature Isolation (S16).
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0xfd, 0x44, 0x9b, 0x93, 0xaf, 0xc2, 0xa9, 0xab, 0xe7, 0x77, 0xce, 0xe1, 0x0f, 0x81, 0x0e, 0x3f, 0x46, 0x18, 0xb8, 0xa6, 0xb7, 0x45, 0x39, 0x1f, 0x73, 0xd8, 0xb7, 0xd5, 0x95, 0x9f, 0xa8, 0x86 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C6 Reset Signature Isolation candidate";
static int check_exact(const char *path) { struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) { printf("exact v15 S1-C6 Reset Signature Isolation package: PASS (%zu-byte OTA payload)\n", firmware.payload_length); status = 0; } else fputs("offline check rejected: not exact S1-C6 Reset Signature Isolation package\n", stderr); smk37_fwsc_free(&firmware); return status; }
int main(int argc, char **argv) { if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 S1-C6 Reset Signature Isolation candidate installed"); fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM); return 2; }
