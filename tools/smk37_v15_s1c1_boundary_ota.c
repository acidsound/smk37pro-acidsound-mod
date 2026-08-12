/* Exact-hash v15-only OTA uploader for S1-C1 boundary-only discriminator. */
#include <stdio.h>
#include <string.h>
#include "../src/ota.c"

static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xae,0x8c,0x44,0xa4,0x93,0xe8,0x3d,0x0b,
    0x41,0xee,0x42,0x2f,0x21,0xbd,0xc1,0x15,
    0xc4,0xe1,0xff,0x23,0x23,0x76,0xfd,0x8a,
    0x8a,0xbf,0x60,0x9c,0x96,0xa3,0x76,0x5d,
};
static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C1-BOUNDARY-AE8C44A4";

static int check_exact(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {
        printf("exact v15 S1-C1 boundary-only package: PASS (%zu-byte OTA payload)\n", firmware.payload_length);
        status = 0;
    } else {
        fputs("offline check rejected: not exact S1-C1 boundary-only package\n", stderr);
    }
    smk37_fwsc_free(&firmware);
    return status;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]);
    if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0)
        return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256,
            "SMK37ProMod v15 S1-C1 additional-0xa0 boundary-only discriminator", CONFIRM,
            "v15 S1-C1 boundary-only installed; exact H2 behavior preserved, second slot unused");
    fprintf(stderr, "Usage:\n  %s check <fwsc>\n  %s upload <fwsc> <transcript> --confirm %s\n", argv[0], argv[0], CONFIRM);
    return 2;
}
