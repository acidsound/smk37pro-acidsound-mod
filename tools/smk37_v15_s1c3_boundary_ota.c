/* Exact-hash v15-only OTA uploader for S1-C3 16-slot boundary-only diagnostic. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x23, 0x45, 0x10, 0x2a, 0xad, 0xde, 0xd7, 0x32, 0xb1, 0x3e, 0x22, 0xd1, 0x41, 0x0d, 0x3f, 0x7b, 0x05, 0xf1, 0x04, 0xff, 0xc4, 0x08, 0xbd, 0x1d, 0x6e, 0xba, 0x03, 0xea, 0x2a, 0xfc, 0x05, 0x8c,
};
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C3-16SLOT-BOUNDARY-2345102A";
static const char DESCRIPTION[] =
    "SMK37ProMod v15 S1-C3 16-slot boundary-only diagnostic";
/* `check` is offline-only; `upload` is the only transport path and requires CONFIRM. */
static int check_exact(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {
        printf("exact v15 S1-C3 16-slot boundary-only package: PASS (%zu-byte OTA payload)\n", firmware.payload_length);
        status = 0;
    } else {
        fputs("offline check rejected: not exact S1-C3 16-slot boundary-only package\n", stderr);
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
        return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM,
            "v15 S1-C3 boundary diagnostic installed; S1-C2 behavior preserved, heap shifted to 0x01c46fb0");
    }
    usage(argv[0]);
    return 2;
}
