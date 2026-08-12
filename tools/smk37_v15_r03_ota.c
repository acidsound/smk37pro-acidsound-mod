/* Exact-hash, v15-only OTA uploader for the R03 controlled checkpoint.
 *
 * This deliberately includes the reviewed OTA implementation in the same
 * translation unit so the exact-package gate remains private to this isolated
 * executable. Do not link src/ota.c separately.
 */
#include <stdio.h>
#include <string.h>

#include "../src/ota.c"

static const uint8_t R03_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x00, 0x15, 0x82, 0xc0, 0x97, 0x27, 0x7d, 0x6a,
    0x4a, 0x61, 0x9e, 0xd4, 0x07, 0xcf, 0x12, 0x1d,
    0x5f, 0x30, 0x09, 0x7e, 0xf8, 0x2f, 0x31, 0x2d,
    0x53, 0xa2, 0xe4, 0x5c, 0x4a, 0x9a, 0x5a, 0x62,
};

static const char R03_CONFIRM[] =
    "INSTALL-SMK37PRO-V15-R03-001582C0";

static int exact_offline_check(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    if (strcmp(firmware.name, "SMK-37 Pro") != 0 ||
        firmware.version != 15 ||
        memcmp(firmware.file_sha256, R03_PACKAGE_SHA256,
               sizeof(R03_PACKAGE_SHA256)) != 0) {
        fputs("offline check rejected: not exact v15 R03 package\n", stderr);
        goto cleanup;
    }
    printf("exact v15 R03 package: PASS (%zu-byte OTA payload)\n",
           firmware.payload_length);
    status = 0;

cleanup:
    smk37_fwsc_free(&firmware);
    return status;
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "check") == 0) {
        return exact_offline_check(argv[2]);
    }
    if (argc == 6 && strcmp(argv[1], "upload") == 0 &&
        strcmp(argv[4], "--confirm") == 0) {
        return ota_upload_exact(
            argv[2], argv[3], argv[5], 15, R03_PACKAGE_SHA256,
            "SMK37ProMod v15 R03 atomic fixed-prefix checkpoint",
            R03_CONFIRM,
            "v15 R03 OTA install: USB identity 015 verified; stage exact packet before pad input");
    }

    fprintf(stderr,
            "Usage:\n"
            "  %s check <R03.fwsc>\n"
            "  %s upload <R03.fwsc> <new-transcript> --confirm %s\n",
            argv[0], argv[0], R03_CONFIRM);
    return 2;
}
