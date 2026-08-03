/* Exact-hash v15-only OTA wrapper for S1-C3 16-slot functional candidate.
 * `check` is offline-only. `upload` is the only transport path and requires CONFIRM.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x97, 0x4c, 0x16, 0x75, 0x42, 0x6e, 0x5d, 0x43, 0xf6, 0xb4, 0x8e, 0x7a, 0xc7, 0xa1, 0x14, 0x2f, 0x40, 0x06, 0x2f, 0xca, 0x94, 0x5d, 0xc6, 0xba, 0x1b, 0x3a, 0xce, 0x8b, 0x0d, 0x14, 0x44, 0x96 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-974C1675";
static const char DESCRIPTION[] = "SMK37ProMod v15 S1-C3 16-slot functional candidate";
static int check_exact(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {
        printf("exact v15 S1-C3 16-slot functional package: PASS (%zu-byte OTA payload)\n", firmware.payload_length);
        status = 0;
    } else {
        fputs("offline check rejected: not exact S1-C3 16-slot functional package\n", stderr);
    }
    smk37_fwsc_free(&firmware);
    return status;
}
static void usage(const char *program) {
    fprintf(stderr, "usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", program, program, CONFIRM);
}
int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]);
    if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) {
        return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256,
            DESCRIPTION, CONFIRM, "v15 S1-C3 16-slot functional candidate installed");
    }
    usage(argv[0]);
    return 2;
}
