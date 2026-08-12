/* Exact-hash, v15-only OTA uploader/checker for the H0 memory-boundary diagnostic.
 *
 * This deliberately includes the reviewed OTA implementation in the same
 * translation unit so the exact-package gate remains private to this isolated
 * executable. Do not link src/ota.c separately.
 */
#include <stdio.h>
#include <string.h>

#include "../src/ota.c"

static const uint8_t H0_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x11, 0x4d, 0x81, 0x4b, 0x5d, 0xef, 0x64, 0x1c,
    0x97, 0x9a, 0x5f, 0x0f, 0xbd, 0x2e, 0x5d, 0xc0,
    0x6d, 0x98, 0x2c, 0x80, 0x76, 0x62, 0xd5, 0x22,
    0x1d, 0xc2, 0xe0, 0xe9, 0x36, 0xe5, 0xe5, 0x66,
};

static const char H0_CONFIRM[] =
    "INSTALL-SMK37PRO-V15-H0-114D814B";

static int exact_offline_check(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    if (strcmp(firmware.name, "SMK-37 Pro") != 0 ||
        firmware.version != 15 ||
        memcmp(firmware.file_sha256, H0_PACKAGE_SHA256,
               sizeof(H0_PACKAGE_SHA256)) != 0) {
        fputs("offline check rejected: not exact v15 H0 package\n", stderr);
        goto cleanup;
    }
    printf("exact v15 H0 package: PASS (%zu-byte OTA payload)\n",
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
            argv[2], argv[3], argv[5], 15, H0_PACKAGE_SHA256,
            "SMK37ProMod v15 H0 memory-boundary diagnostic",
            H0_CONFIRM,
            "v15 H0 OTA install: USB identity 015 verified; diagnostic changes only BSS/HEAP_BEGIN");
    }

    fprintf(stderr,
            "Usage:\n"
            "  %s check <H0.fwsc>\n"
            "  %s upload <H0.fwsc> <new-transcript> --confirm %s\n",
            argv[0], argv[0], H0_CONFIRM);
    return 2;
}
