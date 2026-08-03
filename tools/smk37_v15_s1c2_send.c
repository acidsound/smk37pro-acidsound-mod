#include <libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sha256.h"

enum {
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_MIDI_INTERFACE = 4,
    SMK37_MIDI_ENDPOINT_OUT = 0x04,
    S1C2_PACKET_SIZE = 163,
    USB_MIDI_EVENT_SIZE = 4,
    USB_MIDI_BYTES = 220,
};

static const uint8_t EXPECTED_SHA256[2][SMK37_SHA256_LENGTH] = {
    {0x6a,0x9b,0x40,0x97,0xcc,0xe1,0xd2,0x87,0x80,0xef,0x3a,0x50,0x7f,0x42,0x99,0x97,
     0x43,0xcc,0x10,0xe0,0x97,0x70,0xc1,0x7c,0x5c,0x78,0xd1,0x85,0xe9,0xab,0xff,0x27},
    {0xc4,0xe8,0x45,0x8e,0xde,0xb0,0x4d,0x81,0x06,0xca,0x60,0xa3,0x52,0x43,0x52,0x5e,
     0x6b,0x5f,0x3f,0x5d,0xe2,0x72,0x09,0x14,0x92,0x40,0x9a,0x44,0x0e,0x3a,0x9a,0x8d},
};
static const uint8_t EXPECTED_HEADER[6] = {0xf0,0x43,0x00,0x00,0x01,0x1b};
static const char CONFIRM[] = "SEND-SMK37-V15-S1C2-TWO-PACKETS-6A9B-C4E8";

static int read_exact(const char *path, int slot, uint8_t packet[S1C2_PACKET_SIZE]) {
    FILE *file = fopen(path, "rb");
    uint8_t digest[SMK37_SHA256_LENGTH];
    int extra;
    if (file == NULL) { perror(path); return 1; }
    if (fread(packet, 1, S1C2_PACKET_SIZE, file) != S1C2_PACKET_SIZE) {
        fprintf(stderr, "slot %d packet must be exactly %d bytes\n", slot, S1C2_PACKET_SIZE);
        fclose(file); return 1;
    }
    extra = fgetc(file); fclose(file);
    if (extra != EOF || memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 ||
        packet[S1C2_PACKET_SIZE - 1] != 0xf7) {
        fprintf(stderr, "slot %d packet framing/length mismatch\n", slot); return 1;
    }
    smk37_sha256(packet, S1C2_PACKET_SIZE, digest);
    if (memcmp(digest, EXPECTED_SHA256[slot], sizeof(digest)) != 0) {
        fprintf(stderr, "slot %d packet SHA-256 mismatch\n", slot); return 1;
    }
    return 0;
}

static size_t packetize(const uint8_t *sysex, size_t length, uint8_t *events, size_t capacity) {
    size_t input = 0, output = 0;
    while (input < length) {
        size_t remaining = length - input;
        size_t count = remaining > 3 ? 3 : remaining;
        uint8_t cin = remaining > 3 ? 0x04 : remaining == 1 ? 0x05 : remaining == 2 ? 0x06 : 0x07;
        if (output + USB_MIDI_EVENT_SIZE > capacity) return 0;
        events[output] = cin;
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1 ? sysex[input + 1] : 0;
        events[output + 3] = count > 2 ? sysex[input + 2] : 0;
        input += count; output += USB_MIDI_EVENT_SIZE;
    }
    return output;
}

static int send_both(uint8_t events[2][USB_MIDI_BYTES]) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result, transferred, status = 1;
    result = libusb_init(&context);
    if (result != LIBUSB_SUCCESS) { fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result)); return 1; }
    handle = libusb_open_device_with_vid_pid(context, SMK37_V15_VID, SMK37_V15_PID);
    if (handle == NULL) { fputs("exact v15 device 4353:cf4d could not be opened\n", stderr); status = 2; goto cleanup; }
    result = libusb_claim_interface(handle, SMK37_MIDI_INTERFACE);
    if (result != LIBUSB_SUCCESS) { fprintf(stderr, "claim interface 4: %s\n", libusb_error_name(result)); status = 3; goto cleanup; }
    for (int slot = 0; slot < 2; ++slot) {
        transferred = 0;
        result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT, events[slot], USB_MIDI_BYTES, &transferred, 2000);
        if (result != LIBUSB_SUCCESS || transferred != USB_MIDI_BYTES) {
            fprintf(stderr, "slot %d bulk OUT: %s, transferred %d/%d\n", slot, libusb_error_name(result), transferred, USB_MIDI_BYTES);
            status = 4; goto release;
        }
        printf("sent S1-C2 slot %d exact packet: %d USB-MIDI bytes\n", slot, USB_MIDI_BYTES);
        if (slot == 0) usleep(250000);
    }
    status = 0;
release:
    libusb_release_interface(handle, SMK37_MIDI_INTERFACE);
cleanup:
    if (handle != NULL) libusb_close(handle);
    libusb_exit(context);
    return status;
}

static void usage(const char *p) {
    fprintf(stderr, "usage:\n  %s dry-run SLOT0.bin SLOT1.bin\n  %s send SLOT0.bin SLOT1.bin --confirm %s\n", p, p, CONFIRM);
}

int main(int argc, char **argv) {
    uint8_t sysex[2][S1C2_PACKET_SIZE];
    uint8_t events[2][USB_MIDI_BYTES];
    if ((argc != 4 && argc != 6) || read_exact(argv[2], 0, sysex[0]) || read_exact(argv[3], 1, sysex[1])) {
        usage(argv[0]); return 2;
    }
    for (int slot = 0; slot < 2; ++slot) {
        size_t length = packetize(sysex[slot], S1C2_PACKET_SIZE, events[slot], USB_MIDI_BYTES);
        if (length != USB_MIDI_BYTES || events[slot][USB_MIDI_BYTES - 4] != 0x05 || events[slot][USB_MIDI_BYTES - 3] != 0xf7) {
            fputs("USB-MIDI packetization invariant failed\n", stderr); return 2;
        }
    }
    if (strcmp(argv[1], "dry-run") == 0 && argc == 4) {
        puts("S1-C2 two-packet dry-run PASS: 2 x 163 SysEx bytes -> 2 x 220 USB-MIDI bytes"); return 0;
    }
    if (strcmp(argv[1], "send") == 0 && argc == 6 && strcmp(argv[4], "--confirm") == 0 && strcmp(argv[5], CONFIRM) == 0)
        return send_both(events);
    usage(argv[0]); return 2;
}
