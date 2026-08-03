#include <libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"

#define S1C2_PACKET_SIZE 163u
#define USB_MIDI_PACKET_SIZE 4u
#define S1C2_USB_MIDI_BYTES 220u

static const uint16_t SMK37_V15_VID = 0x4353;
static const uint16_t SMK37_V15_PID = 0xcf4d;
static const int SMK37_MIDI_INTERFACE = 4;
static const unsigned char SMK37_MIDI_ENDPOINT_OUT = 0x04;

static const uint8_t EXPECTED_HEADER[6] = {0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b};
static const uint8_t SLOT0_SHA256[SMK37_SHA256_LENGTH] = {
    0x6a, 0x9b, 0x40, 0x97, 0xcc, 0xe1, 0xd2, 0x87,
    0x80, 0xef, 0x3a, 0x50, 0x7f, 0x42, 0x99, 0x97,
    0x43, 0xcc, 0x10, 0xe0, 0x97, 0x70, 0xc1, 0x7c,
    0x5c, 0x78, 0xd1, 0x85, 0xe9, 0xab, 0xff, 0x27,
};
static const uint8_t SLOT1_SHA256[SMK37_SHA256_LENGTH] = {
    0xc4, 0xe8, 0x45, 0x8e, 0xde, 0xb0, 0x4d, 0x81,
    0x06, 0xca, 0x60, 0xa3, 0x52, 0x43, 0x52, 0x5e,
    0x6b, 0x5f, 0x3f, 0x5d, 0xe2, 0x72, 0x09, 0x14,
    0x92, 0x40, 0x9a, 0x44, 0x0e, 0x3a, 0x9a, 0x8d,
};
static const char CONFIRM_TOKEN[] =
    "SEND-SMK37PRO-V15-S1C2-LIVE-V2-6A9B4097-C4E8458E";

enum packet_slot {
    PACKET_SLOT0 = 0,
    PACKET_SLOT1 = 1,
};

static int read_file_exact(const char *path, uint8_t packet[S1C2_PACKET_SIZE]) {
    FILE *file = fopen(path, "rb");
    int extra;

    if (file == NULL) {
        perror(path);
        return 1;
    }
    if (fread(packet, 1, S1C2_PACKET_SIZE, file) != S1C2_PACKET_SIZE) {
        fprintf(stderr, "S1-C2 packet must be exactly %u bytes: %s\n",
                (unsigned)S1C2_PACKET_SIZE, path);
        fclose(file);
        return 1;
    }
    extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {
        fprintf(stderr, "S1-C2 packet has trailing bytes: %s\n", path);
        return 1;
    }
    return 0;
}

static int verify_packet(const char *path, enum packet_slot slot,
                         uint8_t packet[S1C2_PACKET_SIZE]) {
    uint8_t digest[SMK37_SHA256_LENGTH];
    const uint8_t *expected = slot == PACKET_SLOT0 ? SLOT0_SHA256 : SLOT1_SHA256;
    const char *label = slot == PACKET_SLOT0 ? "slot0 note36" : "slot1 note45";

    if (read_file_exact(path, packet) != 0) {
        return 1;
    }
    if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 ||
        packet[S1C2_PACKET_SIZE - 1] != 0xf7) {
        fprintf(stderr, "S1-C2 %s packet framing mismatch\n", label);
        return 1;
    }
    smk37_sha256(packet, S1C2_PACKET_SIZE, digest);
    if (memcmp(digest, expected, sizeof(digest)) != 0) {
        fprintf(stderr, "S1-C2 %s packet SHA-256 mismatch\n", label);
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
        events[output] = cin;
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1 ? sysex[input + 1] : 0;
        events[output + 3] = count > 2 ? sysex[input + 2] : 0;
        input += count;
        output += USB_MIDI_PACKET_SIZE;
    }
    return output;
}

static int packetize_checked(const uint8_t packet[S1C2_PACKET_SIZE],
                             uint8_t events[S1C2_USB_MIDI_BYTES]) {
    size_t length = packetize(packet, S1C2_PACKET_SIZE, events, S1C2_USB_MIDI_BYTES);
    if (length != S1C2_USB_MIDI_BYTES || events[length - 4] != 0x05 ||
        events[length - 3] != 0xf7) {
        fputs("USB-MIDI packetization invariant failed\n", stderr);
        return 1;
    }
    return 0;
}

static int send_events(libusb_device_handle *handle, const uint8_t *events,
                       size_t length, const char *label) {
    int transferred = 0;
    int result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT,
                                      (unsigned char *)events, (int)length,
                                      &transferred, 2000);
    if (result != LIBUSB_SUCCESS || transferred != (int)length) {
        fprintf(stderr, "bulk OUT 0x04 for %s: %s, transferred %d/%zu\n",
                label, libusb_error_name(result), transferred, length);
        return 1;
    }
    printf("sent exact S1-C2 %s packet: %zu USB-MIDI bytes\n", label, length);
    return 0;
}

static int send_pair(const uint8_t slot0_events[S1C2_USB_MIDI_BYTES],
                     const uint8_t slot1_events[S1C2_USB_MIDI_BYTES]) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
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
    if (send_events(handle, slot0_events, S1C2_USB_MIDI_BYTES, "slot0 note36") != 0 ||
        send_events(handle, slot1_events, S1C2_USB_MIDI_BYTES, "slot1 note45") != 0) {
        status = 4;
    } else {
        status = 0;
    }
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
            "  %s dry-run <slot0-note36-163.bin> <slot1-note45-163.bin>\n"
            "  %s send <slot0-note36-163.bin> <slot1-note45-163.bin> --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}

int main(int argc, char **argv) {
    uint8_t slot0[S1C2_PACKET_SIZE];
    uint8_t slot1[S1C2_PACKET_SIZE];
    uint8_t slot0_events[S1C2_USB_MIDI_BYTES];
    uint8_t slot1_events[S1C2_USB_MIDI_BYTES];

    if (argc != 4 && argc != 6) {
        usage(argv[0]);
        return 2;
    }
    if (verify_packet(argv[2], PACKET_SLOT0, slot0) != 0 ||
        verify_packet(argv[3], PACKET_SLOT1, slot1) != 0 ||
        packetize_checked(slot0, slot0_events) != 0 ||
        packetize_checked(slot1, slot1_events) != 0) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "dry-run") == 0 && argc == 4) {
        printf("S1-C2 live v2 sender dry-run PASS: slot0 note36 then slot1 note45, each %u SysEx bytes -> %u USB-MIDI bytes\n",
               (unsigned)S1C2_PACKET_SIZE, (unsigned)S1C2_USB_MIDI_BYTES);
        return 0;
    }
    if (strcmp(argv[1], "send") == 0 && argc == 6 &&
        strcmp(argv[4], "--confirm") == 0 && strcmp(argv[5], CONFIRM_TOKEN) == 0) {
        return send_pair(slot0_events, slot1_events);
    }
    usage(argv[0]);
    return 2;
}
