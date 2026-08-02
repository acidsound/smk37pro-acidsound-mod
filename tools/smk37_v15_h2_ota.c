/* Exact-hash, v15-only OTA uploader/checker for the H2 owned-source corrected-fallback diagnostic.
 *
 * This deliberately includes the reviewed OTA implementation in the same
 * translation unit so the exact-package gate remains private to this isolated
 * executable. Do not link src/ota.c separately.
 */
#include <stdio.h>
#include <string.h>

#include "../src/ota.c"

static const uint8_t H2_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xc1, 0x75, 0x2a, 0x69, 0xed, 0x8f, 0x90, 0x5a,
    0xf5, 0x8d, 0xb0, 0xde, 0x7c, 0x3d, 0xef, 0x29,
    0xc4, 0x16, 0xb7, 0x1e, 0x83, 0x2e, 0x28, 0x34,
    0xe6, 0x64, 0xcd, 0x5d, 0x17, 0xb8, 0x50, 0x11,
};

static const char H2_CONFIRM[] =
    "INSTALL-SMK37PRO-V15-H2-C1752A69";

static int exact_offline_check(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    if (strcmp(firmware.name, "SMK-37 Pro") != 0 ||
        firmware.version != 15 ||
        memcmp(firmware.file_sha256, H2_PACKAGE_SHA256,
               sizeof(H2_PACKAGE_SHA256)) != 0) {
        fputs("offline check rejected: not exact v15 H2 package\n", stderr);
        goto cleanup;
    }
    printf("exact v15 H2 package: PASS (%zu-byte OTA payload)\n",
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
            argv[2], argv[3], argv[5], 15, H2_PACKAGE_SHA256,
            "SMK37ProMod v15 H2 owned-source corrected-fallback discriminator",
            H2_CONFIRM,
            "v15 H2 OTA install: USB identity 015 verified; Ch10 consumers source owned RAM only when valid with corrected fallback");
    }

    fprintf(stderr,
            "Usage:\n"
            "  %s check <H2.fwsc>\n"
            "  %s upload <H2.fwsc> <new-transcript> --confirm %s\n",
            argv[0], argv[0], H2_CONFIRM);
    return 2;
}
