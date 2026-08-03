/* Exact-hash v15-only OTA wrapper for S1-C3 16-slot functional candidate.
 * `check` is offline-only. `upload` is the only transport path and requires CONFIRM.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = { 0xff, 0x56, 0xa5, 0x6d, 0xc4, 0x64, 0x39, 0x03, 0x94, 0xa2, 0xa3, 0xa5, 0xb4, 0xb1, 0x5f, 0x50, 0xf9, 0xf7, 0x65, 0xa6, 0x7a, 0x6c, 0xd0, 0x8c, 0x95, 0x28, 0x12, 0x70, 0xdf, 0x7d, 0x37, 0xc4 };
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-FF56A56D";
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
