/* Exact-hash v15-only OTA wrapper for S1-C3 16-slot functional candidate.
 * `check` is offline-only. `upload` is the only transport path and requires CONFIRM.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0x0f, 0x1c, 0x4b, 0xf4, 0x23, 0x29, 0xa0, 0xca, 0x18, 0x4a, 0xc3, 0x8b, 0xb2, 0x28, 0x19, 0x5b, 0x23, 0x9e, 0xd0, 0x78, 0x20, 0xfc, 0xc0, 0xd3, 0x9b, 0xe3, 0x52, 0xc2, 0xf1, 0x59, 0x82, 0xb9 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-0F1C4BF4";
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
