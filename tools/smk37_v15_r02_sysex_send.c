#include <libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

enum {
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_MIDI_INTERFACE = 4,
    SMK37_MIDI_ENDPOINT_OUT = 0x04,
    R02_PACKET_SIZE = 163,
    USB_MIDI_PACKET_SIZE = 4,
};

static const uint8_t EXPECTED_SHA256[SMK37_SHA256_LENGTH] = {
    0x6a, 0x9b, 0x40, 0x97, 0xcc, 0xe1, 0xd2, 0x87,
    0x80, 0xef, 0x3a, 0x50, 0x7f, 0x42, 0x99, 0x97,
    0x43, 0xcc, 0x10, 0xe0, 0x97, 0x70, 0xc1, 0x7c,
    0x5c, 0x78, 0xd1, 0x85, 0xe9, 0xab, 0xff, 0x27,
};
static const uint8_t EXPECTED_HEADER[6] = {0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b};
static const char CONFIRM_TOKEN[] = "SEND-SMK37-V15-R02-MOOGER1-6A9B4097";

static int read_exact_packet(const char *path, uint8_t packet[R02_PACKET_SIZE]) {
    FILE *file = fopen(path, "rb");
    uint8_t digest[SMK37_SHA256_LENGTH];
    int extra;

    if (file == NULL) {
        perror(path);
        return 1;
    }
    if (fread(packet, 1, R02_PACKET_SIZE, file) != R02_PACKET_SIZE) {
        fprintf(stderr, "R02 packet must be exactly %d bytes\n", R02_PACKET_SIZE);
        fclose(file);
        return 1;
    }
    extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {
        fprintf(stderr, "R02 packet has trailing bytes\n");
        return 1;
    }
    if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 ||
        packet[R02_PACKET_SIZE - 1] != 0xf7) {
        fprintf(stderr, "R02 packet framing mismatch\n");
        return 1;
    }
    smk37_sha256(packet, R02_PACKET_SIZE, digest);
    if (memcmp(digest, EXPECTED_SHA256, sizeof(digest)) != 0) {
        fprintf(stderr, "R02 packet SHA-256 mismatch\n");
        return 1;
    }
    return 0;
}

static size_t packetize(const uint8_t *sysex, size_t length,
                        uint8_t *events, size_t capacity) {
    size_t input = 0;
    size_t output = 0;

    while (input < length) {
        size_t remaining = length - input;
        size_t count = remaining > 3 ? 3 : remaining;
        uint8_t cin;

        if (output + USB_MIDI_PACKET_SIZE > capacity) {
            return 0;
        }
        if (remaining > 3) {
            cin = 0x04;
        } else if (remaining == 1) {
            cin = 0x05;
        } else if (remaining == 2) {
            cin = 0x06;
        } else {
            cin = 0x07;
        }
        events[output] = cin; /* cable 0 */
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1 ? sysex[input + 1] : 0;
        events[output + 3] = count > 2 ? sysex[input + 2] : 0;
        input += count;
        output += USB_MIDI_PACKET_SIZE;
    }
    return output;
}

static int send_packet(const uint8_t *events, size_t length) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int transferred = 0;
    int result;
    int status = 1;

    result = libusb_init(&context);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }
    handle = libusb_open_device_with_vid_pid(context, SMK37_V15_VID, SMK37_V15_PID);
    if (handle == NULL) {
        fputs("exact v15 device 4353:cf4d could not be opened\n", stderr);
        status = 2;
        goto cleanup;
    }
    result = libusb_claim_interface(handle, SMK37_MIDI_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_MIDI_INTERFACE,
                libusb_error_name(result));
        status = 3;
        goto cleanup;
    }
    result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT,
                                  (unsigned char *)events, (int)length,
                                  &transferred, 2000);
    if (result != LIBUSB_SUCCESS || transferred != (int)length) {
        fprintf(stderr, "bulk OUT 0x04: %s, transferred %d/%zu\n",
                libusb_error_name(result), transferred, length);
        status = 4;
        goto release;
    }
    printf("sent exact R02 runtime product packet: %zu USB-MIDI bytes\n", length);
    status = 0;

release:
    libusb_release_interface(handle, SMK37_MIDI_INTERFACE);
cleanup:
    if (handle != NULL) {
        libusb_close(handle);
    }
    libusb_exit(context);
    return status;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s dry-run PACKET.syx\n"
            "  %s send PACKET.syx --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}

int main(int argc, char **argv) {
    uint8_t sysex[R02_PACKET_SIZE];
    uint8_t events[4 * ((R02_PACKET_SIZE + 2) / 3)];
    size_t event_length;

    if (argc < 3 || read_exact_packet(argv[2], sysex) != 0) {
        usage(argv[0]);
        return 2;
    }
    event_length = packetize(sysex, sizeof(sysex), events, sizeof(events));
    if (event_length != 220 || events[event_length - 4] != 0x05 ||
        events[event_length - 3] != 0xf7) {
        fputs("USB-MIDI packetization invariant failed\n", stderr);
        return 2;
    }
    if (strcmp(argv[1], "dry-run") == 0 && argc == 3) {
        printf("R02 packet dry-run PASS: %d SysEx bytes -> %zu USB-MIDI bytes\n",
               R02_PACKET_SIZE, event_length);
        return 0;
    }
    if (strcmp(argv[1], "send") == 0 && argc == 5 &&
        strcmp(argv[3], "--confirm") == 0 &&
        strcmp(argv[4], CONFIRM_TOKEN) == 0) {
        return send_packet(events, event_length);
    }
    usage(argv[0]);
    return 2;
}
