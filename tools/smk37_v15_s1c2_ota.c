/* Exact-hash v15-only OTA uploader for S1-C2 two-slot selector live v2. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/ota.c"

static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x63, 0xe3, 0xcf, 0xa3, 0x94, 0x73, 0xdf, 0x08,
    0xbd, 0x22, 0x5d, 0xf2, 0xc8, 0xae, 0x81, 0xdb,
    0xfe, 0x7a, 0xaf, 0xbd, 0x31, 0xda, 0x6c, 0xc6,
    0xdc, 0xf6, 0x4c, 0xa0, 0x34, 0x53, 0x68, 0x1e,
};

static const char CONFIRM[] = "INSTALL-SMK37PRO-V15-S1C2-LIVE-V2-63E3CFA3";
static const char DESCRIPTION[] =
    "SMK37ProMod v15 S1-C2 split-entry two-slot selector live v2";
/* `check` is offline-only; `upload` is the only transport path and requires CONFIRM. */

static int check_exact(const char *path) {
    struct smk37_fwsc firmware;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {
        printf("exact v15 S1-C2 live v2 package: PASS (%zu-byte OTA payload)\n",
               firmware.payload_length);
        status = 0;
    } else {
        fputs("offline check rejected: not exact S1-C2 live v2 package\n", stderr);
    }
    smk37_fwsc_free(&firmware);
    return status;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s check <fwsc>\n"
            "  %s upload <fwsc> <transcript> --confirm %s\n",
            program, program, CONFIRM);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "check") == 0) {
        return check_exact(argv[2]);
    }
    if (argc == 6 && strcmp(argv[1], "upload") == 0 &&
        strcmp(argv[4], "--confirm") == 0) {
        return ota_upload_exact(
            argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM,
            "v15 S1-C2 live v2 installed; split-entry two-slot selector armed");
    }
    usage(argv[0]);
    return 2;
}
