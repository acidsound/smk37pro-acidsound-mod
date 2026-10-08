#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device_info.h"
#include "flash_read.h"
#include "fwsc.h"
#include "ota.h"
#include "protocol.h"
#include "sha256.h"
#include "usb_probe.h"

static void usage(FILE *stream, const char *program) {
    fprintf(stream,
            "Usage: %s <command>\n"
            "\n"
            "Commands:\n"
            "  probe      Read USB descriptors only; sends no device command\n"
            "  claim-test Open and release interface 4; sends no device command\n"
            "  midi-monitor <seconds>\n"
            "             Read raw USB-MIDI input only; sends no device command\n"
            "  midi-channel-test\n"
            "             Send three Ch1 notes, then three Ch10 notes over raw USB-MIDI\n"
            "  device-info Send the read-only product/version query\n"
            "  flash-read <address> <length>\n"
            "             Read 1..1009 bytes from main flash and print them\n"
            "  dump <output> [length]\n"
            "             Save main flash; default length is 0x100000\n"
            "  inspect <firmware.fwsc> [payload-output]\n"
            "             Validate a package and optionally extract OTA payload\n"
            "  upload-check <firmware.fwsc>\n"
            "             Read-only device/package identity preflight\n"
            "  upload-dry-run <firmware.fwsc>\n"
            "             Offline packet and bounds validation\n"
            "  upload <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Execute same-version two-stage OTA restore\n"
            "  upload-m001 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact marker-only M001 package\n"
            "  upload-m02 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact three-character M02 package\n"
            "  upload-m03 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact Hello/acidsound M03 package\n"
            "  upload-m04 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact two-line Hello/acidsound M04 package\n"
            "  upload-m05 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact minimal two-timbre M05 package\n"
            "  upload-m06 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact local-pad channel-10 FM M06 package\n"
            "  upload-m07 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact per-note channel-10 FM M07 package\n"
            "  upload-m08 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact isolated fixed-map channel-10 M08 package\n"
            "  upload-m10 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install exact M08 data-only follow-up package\n"
            "  upload-v15 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Restore exact official v15 baseline package\n"
            "  upload-v15-r01 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Install evidence-based Ch10 HAND DRUM checkpoint\n"
            "  upload-resume-v12 <firmware.fwsc> <transcript> --confirm <token>\n"
            "             Resume stage 2 from the exact archived v12 image\n"
            "  self-test  Verify build-time invariants without a device\n",
            program);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(stderr, argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "probe") == 0) {
        if (argc != 2) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_probe();
    }

    if (strcmp(argv[1], "claim-test") == 0) {
        if (argc != 2) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_claim_test();
    }

    if (strcmp(argv[1], "midi-monitor") == 0) {
        char *end = NULL;
        unsigned long seconds;

        if (argc != 3) {
            usage(stderr, argv[0]);
            return 2;
        }
        seconds = strtoul(argv[2], &end, 0);
        if (*argv[2] == '\0' || *end != '\0' || seconds > 300) {
            fputs("invalid monitor duration\n", stderr);
            return 2;
        }
        return smk37_midi_monitor((unsigned)seconds);
    }

    if (strcmp(argv[1], "midi-channel-test") == 0) {
        if (argc != 2) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_midi_channel_test();
    }

    if (strcmp(argv[1], "device-info") == 0) {
        if (argc != 2) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_device_info();
    }

    if (strcmp(argv[1], "flash-read") == 0) {
        char *address_end = NULL;
        char *length_end = NULL;
        unsigned long address;
        unsigned long length;

        if (argc != 4) {
            usage(stderr, argv[0]);
            return 2;
        }
        address = strtoul(argv[2], &address_end, 0);
        length = strtoul(argv[3], &length_end, 0);
        if (*argv[2] == '\0' || *address_end != '\0' || *argv[3] == '\0' ||
            *length_end != '\0' || address > UINT32_MAX ||
            length > UINT32_MAX) {
            fputs("invalid address or length\n", stderr);
            return 2;
        }
        return smk37_flash_read_preview((uint32_t)address, (uint32_t)length);
    }

    if (strcmp(argv[1], "dump") == 0) {
        char *length_end = NULL;
        unsigned long length = 0x100000;

        if (argc != 3 && argc != 4) {
            usage(stderr, argv[0]);
            return 2;
        }
        if (argc == 4) {
            length = strtoul(argv[3], &length_end, 0);
            if (*argv[3] == '\0' || *length_end != '\0' ||
                length > UINT32_MAX) {
                fputs("invalid dump length\n", stderr);
                return 2;
            }
        }
        return smk37_flash_dump(argv[2], (uint32_t)length);
    }

    if (strcmp(argv[1], "inspect") == 0) {
        if (argc != 3 && argc != 4) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_fwsc_inspect(argv[2], argc == 4 ? argv[3] : NULL);
    }

    if (strcmp(argv[1], "upload-check") == 0) {
        if (argc != 3) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_preflight(argv[2]);
    }

    if (strcmp(argv[1], "upload-dry-run") == 0) {
        if (argc != 3) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_dry_run(argv[2]);
    }

    if (strcmp(argv[1], "upload") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m001") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m001(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m02") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m02(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m03") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m03(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m04") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m04(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m05") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m05(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m06") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m06(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m07") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m07(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m08") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m08(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-m10") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_m10(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-v15") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_v15(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-v15-r01") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_upload_v15_r01(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "upload-resume-v12") == 0) {
        if (argc != 6 || strcmp(argv[4], "--confirm") != 0) {
            usage(stderr, argv[0]);
            return 2;
        }
        return smk37_ota_resume_v12(argv[2], argv[3], argv[5]);
    }

    if (strcmp(argv[1], "self-test") == 0) {
        if (argc != 2) {
            usage(stderr, argv[0]);
            return 2;
        }
        if (smk37_protocol_self_test() != 0 ||
            smk37_fwsc_self_test() != 0 || smk37_sha256_self_test() != 0) {
            return 1;
        }
        puts("self-test: ok");
        return 0;
    }

    usage(stderr, argv[0]);
    return 2;
}
