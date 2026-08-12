/* Exact-hash, v15-only OTA uploader/checker for the H1 producer-unconsumed diagnostic.
 *
 * This deliberately includes the reviewed OTA implementation in the same
 * translation unit so the exact-package gate remains private to this isolated
 * executable. Do not link src/ota.c separately.
 */
#include <stdio.h>
#include <string.h>

#include "../src/ota.c"

static const uint8_t H1_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x13, 0x9a, 0xb4, 0x2b, 0x37, 0x46, 0x47, 0x7b,
    0x8b, 0xf4, 0x9e, 0x59, 0x2b, 0xa9, 0x4e, 0xfd,
    0x9f, 0x6c, 0x18, 0xb4, 0xa3, 0x60, 0xe0, 0xe6,
    0x28, 0x07, 0xbc, 0x12, 0xe5, 0x45, 0xda, 0xcf,
};

static const char H1_CONFIRM[] =
    "INSTALL-SMK37PRO-V15-H1-139AB42B";

static int exact_offline_check(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    if (strcmp(firmware.name, "SMK-37 Pro") != 0 ||
        firmware.version != 15 ||
        memcmp(firmware.file_sha256, H1_PACKAGE_SHA256,
               sizeof(H1_PACKAGE_SHA256)) != 0) {
        fputs("offline check rejected: not exact v15 H1 package\n", stderr);
        goto cleanup;
    }
    printf("exact v15 H1 package: PASS (%zu-byte OTA payload)\n",
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
            argv[2], argv[3], argv[5], 15, H1_PACKAGE_SHA256,
            "SMK37ProMod v15 H1 producer-unconsumed discriminator",
            H1_CONFIRM,
            "v15 H1 OTA install: USB identity 015 verified; consumers source staging, producer writes owned RAM");
    }

    fprintf(stderr,
            "Usage:\n"
            "  %s check <H1.fwsc>\n"
            "  %s upload <H1.fwsc> <new-transcript> --confirm %s\n",
            argv[0], argv[0], H1_CONFIRM);
    return 2;
}
