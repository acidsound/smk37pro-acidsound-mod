/* Guarded exact 16-packet C sender for S1-C3 functional.
 * Default validation builds without S1C3_ENABLE_LIVE_USB, so send is fail-closed.
 * If a future live run is explicitly authorized, compile with S1C3_ENABLE_LIVE_USB
 * and libusb, keep the exact hashes/order, and pass the confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef S1C3_ENABLE_LIVE_USB
#include <libusb.h>
#endif
#include "../../../../../src/sha256.h"

#define S1C3_PACKET_COUNT 16u
#define S1C3_PACKET_SIZE 163u
#define USB_MIDI_PACKET_SIZE 4u
#define S1C3_USB_MIDI_BYTES 220u
#define S1C3_MAX_PATH 4096u
#define S1C3_INTER_PACKET_DELAY_NS 100000000L

static const uint8_t EXPECTED_HEADER[6] = {0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b};
static const char CONFIRM_TOKEN[] = "SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7";

struct packet_spec {
    unsigned order;
    unsigned slot;
    unsigned note;
    const char *name;
    const char *file;
    uint8_t sha256[SMK37_SHA256_LENGTH];
};

static const struct packet_spec PACKETS[S1C3_PACKET_COUNT] = {
    { 1, 0, 36, "BUZZ BASS", "slot00-note36-direct-product-163.bin", { 0x1c, 0x92, 0x39, 0x62, 0x15, 0x63, 0x72, 0x2e, 0xaa, 0xc0, 0xa8, 0x5d, 0xb4, 0x11, 0x57, 0x19, 0x63, 0xf9, 0xeb, 0xbd, 0x0d, 0xbb, 0xb0, 0x0b, 0x21, 0x04, 0x4b, 0x76, 0xb1, 0x58, 0x14, 0x27 } },
    { 2, 1, 37, "Bang ?????", "slot01-note37-direct-product-163.bin", { 0xaf, 0xa8, 0x95, 0x70, 0x05, 0x34, 0x1e, 0x61, 0x44, 0x96, 0x2c, 0xe3, 0x12, 0x0b, 0xb1, 0xd8, 0x29, 0x47, 0x57, 0x14, 0x07, 0x76, 0x17, 0xea, 0x8d, 0xa2, 0xc3, 0xfe, 0xe4, 0xa0, 0xaa, 0x21 } },
    { 3, 2, 38, "BASSE BIEN", "slot02-note38-direct-product-163.bin", { 0x8a, 0x87, 0xa4, 0x09, 0x05, 0x64, 0x57, 0xe6, 0x19, 0x44, 0xd0, 0x1b, 0xf4, 0xbb, 0xc0, 0x26, 0x64, 0x14, 0xb8, 0x38, 0x5c, 0x3a, 0x84, 0x81, 0x25, 0x70, 0x0d, 0xa9, 0xe8, 0x41, 0x7d, 0xe3 } },
    { 4, 3, 39, "BASS-THING", "slot03-note39-direct-product-163.bin", { 0xa5, 0xc0, 0x86, 0xa7, 0x7b, 0x4d, 0xe1, 0xce, 0x95, 0x46, 0xe7, 0x47, 0xb7, 0x2f, 0x79, 0xd8, 0xf6, 0xad, 0x7b, 0x0d, 0xbd, 0x7c, 0x3b, 0x6e, 0x16, 0x65, 0xef, 0x7e, 0xdf, 0x83, 0xff, 0x58 } },
    { 5, 4, 40, "BASS SLAP", "slot04-note40-direct-product-163.bin", { 0xff, 0xd1, 0xbc, 0xc6, 0xc7, 0xa7, 0xc5, 0xd8, 0xa1, 0xbb, 0x35, 0xf5, 0xbf, 0x7e, 0x39, 0xbf, 0x63, 0x05, 0x8e, 0x62, 0xac, 0x57, 0x4e, 0x1e, 0x30, 0x8b, 0xa5, 0x3e, 0xdc, 0x66, 0x70, 0xff } },
    { 6, 5, 41, "BEAMER 2", "slot05-note41-direct-product-163.bin", { 0x57, 0x13, 0x67, 0x06, 0xfa, 0x63, 0x3b, 0x5b, 0x47, 0x00, 0x8e, 0xd2, 0x61, 0x64, 0x71, 0xf7, 0x2a, 0xe6, 0x29, 0xd6, 0x9e, 0x60, 0x1e, 0x33, 0xc6, 0x6d, 0xaa, 0xd9, 0x91, 0xdf, 0x94, 0xe9 } },
    { 7, 6, 42, "Onglon", "slot06-note42-direct-product-163.bin", { 0x0f, 0x20, 0x2d, 0x88, 0x57, 0x81, 0x52, 0xca, 0x02, 0x4b, 0x38, 0x22, 0xf5, 0x6a, 0x7c, 0x74, 0xc4, 0x85, 0xc4, 0x29, 0x96, 0x69, 0x50, 0x33, 0xa4, 0xc2, 0x39, 0x44, 0x9d, 0x30, 0xf3, 0x66 } },
    { 8, 7, 43, "SOFTSTEEL", "slot07-note43-direct-product-163.bin", { 0xd4, 0xee, 0x6f, 0x2c, 0xcf, 0xce, 0x2d, 0x0c, 0x54, 0x89, 0x17, 0xbb, 0x58, 0xea, 0xd4, 0x98, 0x8d, 0xc3, 0x03, 0x8c, 0x2b, 0x84, 0xed, 0xaa, 0xa3, 0x7f, 0x04, 0x7d, 0x2e, 0x00, 0x6e, 0xa2 } },
    { 9, 8, 44, "BASS-ROADS", "slot08-note44-direct-product-163.bin", { 0xc8, 0xc4, 0x89, 0xb7, 0x2b, 0x19, 0x5d, 0xfe, 0x5f, 0x37, 0x3b, 0x6a, 0x86, 0x0b, 0x32, 0xf0, 0xd0, 0x7a, 0x29, 0xa8, 0x3a, 0x9f, 0x2c, 0x07, 0x02, 0x99, 0xdf, 0x5a, 0xf8, 0x8a, 0x9c, 0xb3 } },
    { 10, 9, 45, "E.ORGAN 1", "slot09-note45-direct-product-163.bin", { 0x9c, 0x89, 0x5d, 0x92, 0x5a, 0x6c, 0xb7, 0x9c, 0x4d, 0xff, 0x9f, 0x9f, 0x27, 0x72, 0x7c, 0xce, 0x02, 0xf6, 0xdd, 0x0e, 0xd8, 0x64, 0x67, 0xc9, 0x94, 0xd7, 0xf4, 0x59, 0xf1, 0x03, 0x62, 0x58 } },
    { 11, 10, 46, "YEAAAHH", "slot10-note46-direct-product-163.bin", { 0x80, 0x29, 0x44, 0xd0, 0xe1, 0xa8, 0xf4, 0xe8, 0x5f, 0x1a, 0x3a, 0x69, 0x4e, 0x2a, 0x0d, 0xbb, 0xfe, 0x9b, 0xb5, 0x59, 0x72, 0x81, 0x4f, 0x11, 0xed, 0x4c, 0x7b, 0xe7, 0x57, 0x5b, 0x67, 0x04 } },
    { 12, 11, 47, "HAND DRUM", "slot11-note47-direct-product-163.bin", { 0xc4, 0xe8, 0x45, 0x8e, 0xde, 0xb0, 0x4d, 0x81, 0x06, 0xca, 0x60, 0xa3, 0x52, 0x43, 0x52, 0x5e, 0x6b, 0x5f, 0x3f, 0x5d, 0xe2, 0x72, 0x09, 0x14, 0x92, 0x40, 0x9a, 0x44, 0x0e, 0x3a, 0x9a, 0x8d } },
    { 13, 12, 48, "HAND CLAP1", "slot12-note48-direct-product-163.bin", { 0x62, 0x2a, 0x06, 0x87, 0x0f, 0x18, 0x9b, 0x6e, 0x45, 0x82, 0xf0, 0x09, 0x32, 0x55, 0xf4, 0x50, 0x40, 0x3d, 0x41, 0x12, 0x83, 0x6f, 0x09, 0x56, 0x3c, 0x0b, 0x46, 0x23, 0xc1, 0xb2, 0x87, 0xcd } },
    { 14, 13, 49, "Mooger #1", "slot13-note49-direct-product-163.bin", { 0x6a, 0x9b, 0x40, 0x97, 0xcc, 0xe1, 0xd2, 0x87, 0x80, 0xef, 0x3a, 0x50, 0x7f, 0x42, 0x99, 0x97, 0x43, 0xcc, 0x10, 0xe0, 0x97, 0x70, 0xc1, 0x7c, 0x5c, 0x78, 0xd1, 0x85, 0xe9, 0xab, 0xff, 0x27 } },
    { 15, 14, 50, "Moog Solo2", "slot14-note50-direct-product-163.bin", { 0xb1, 0x59, 0xdb, 0x61, 0x76, 0x16, 0x62, 0x17, 0x59, 0xbb, 0x99, 0x90, 0x99, 0x1a, 0x82, 0x14, 0xc5, 0x85, 0xd1, 0xf7, 0xec, 0xd1, 0xbe, 0x0f, 0x36, 0xd5, 0x3a, 0x0b, 0x71, 0xb1, 0x60, 0xc8 } },
    { 16, 15, 51, "Mooger Low", "slot15-note51-direct-product-163.bin", { 0x39, 0xa3, 0xe4, 0xec, 0xa1, 0xc7, 0x40, 0xf7, 0x19, 0xb3, 0x49, 0x5f, 0x2a, 0x88, 0xc6, 0x3e, 0x3b, 0x5d, 0x57, 0x5a, 0x16, 0xa9, 0x8c, 0x7b, 0x05, 0xfb, 0xc2, 0x11, 0xfb, 0xfa, 0x47, 0x75 } },
};

static int build_path(char *out, size_t out_size, const char *dir, const char *file) {
    int written = snprintf(out, out_size, "%s/%s", dir, file);
    if (written < 0 || (size_t)written >= out_size) {
        fputs("packet path too long\n", stderr);
        return 1;
    }
    return 0;
}

static int read_file_exact(const char *path, uint8_t packet[S1C3_PACKET_SIZE]) {
    FILE *file = fopen(path, "rb");
    int extra;
    if (file == NULL) {
        perror(path);
        return 1;
    }
    if (fread(packet, 1, S1C3_PACKET_SIZE, file) != S1C3_PACKET_SIZE) {
        fprintf(stderr, "S1-C3 packet must be exactly %u bytes: %s\n", (unsigned)S1C3_PACKET_SIZE, path);
        fclose(file);
        return 1;
    }
    extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {
        fprintf(stderr, "S1-C3 packet has trailing bytes: %s\n", path);
        return 1;
    }
    return 0;
}

static int verify_packet(const char *packet_dir, const struct packet_spec *spec, uint8_t packet[S1C3_PACKET_SIZE]) {
    uint8_t digest[SMK37_SHA256_LENGTH];
    char path[S1C3_MAX_PATH];
    if (build_path(path, sizeof(path), packet_dir, spec->file) != 0) return 1;
    if (read_file_exact(path, packet) != 0) return 1;
    if (memcmp(packet, EXPECTED_HEADER, sizeof(EXPECTED_HEADER)) != 0 || packet[S1C3_PACKET_SIZE - 1] != 0xf7) {
        fprintf(stderr, "S1-C3 order %u slot %u note %u packet framing mismatch\n", spec->order, spec->slot, spec->note);
        return 1;
    }
    smk37_sha256(packet, S1C3_PACKET_SIZE, digest);
    if (memcmp(digest, spec->sha256, sizeof(digest)) != 0) {
        fprintf(stderr, "S1-C3 order %u slot %u note %u packet SHA-256 mismatch\n", spec->order, spec->slot, spec->note);
        return 1;
    }
    return 0;
}

static size_t packetize(const uint8_t *sysex, size_t length, uint8_t *events, size_t capacity) {
    size_t input = 0;
    size_t output = 0;
    while (input < length) {
        size_t remaining = length - input;
        size_t count = remaining > 3 ? 3 : remaining;
        uint8_t cin;
        if (output + USB_MIDI_PACKET_SIZE > capacity) return 0;
        if (remaining > 3) cin = 0x04;
        else if (remaining == 1) cin = 0x05;
        else if (remaining == 2) cin = 0x06;
        else cin = 0x07;
        events[output] = cin;
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1 ? sysex[input + 1] : 0;
        events[output + 3] = count > 2 ? sysex[input + 2] : 0;
        input += count;
        output += USB_MIDI_PACKET_SIZE;
    }
    return output;
}

static int packetize_checked(const uint8_t packet[S1C3_PACKET_SIZE], uint8_t events[S1C3_USB_MIDI_BYTES]) {
    size_t length = packetize(packet, S1C3_PACKET_SIZE, events, S1C3_USB_MIDI_BYTES);
    if (length != S1C3_USB_MIDI_BYTES || events[length - 4] != 0x05 || events[length - 3] != 0xf7) {
        fputs("USB-MIDI packetization invariant failed\n", stderr);
        return 1;
    }
    return 0;
}

#ifdef S1C3_ENABLE_LIVE_USB
static const uint16_t SMK37_V15_VID = 0x4353;
static const uint16_t SMK37_V15_PID = 0xcf4d;
static const int SMK37_MIDI_INTERFACE = 4;
static const unsigned char SMK37_MIDI_ENDPOINT_OUT = 0x04;
static int send_verified(uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES]) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);
    int status = 1;
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
        fprintf(stderr, "claim interface %d: %s\n", SMK37_MIDI_INTERFACE, libusb_error_name(result));
        status = 3;
        goto cleanup;
    }
    for (unsigned i = 0; i < S1C3_PACKET_COUNT; ++i) {
        int transferred = 0;
        result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT, events[i], S1C3_USB_MIDI_BYTES, &transferred, 2000);
        if (result != LIBUSB_SUCCESS || transferred != (int)S1C3_USB_MIDI_BYTES) {
            fprintf(stderr, "bulk OUT order %u: %s transferred %d/%u\n", PACKETS[i].order, libusb_error_name(result), transferred, (unsigned)S1C3_USB_MIDI_BYTES);
            status = 4;
            break;
        }
        printf("sent exact S1-C3 order %u slot %u note %u: %u USB-MIDI bytes\n", PACKETS[i].order, PACKETS[i].slot, PACKETS[i].note, (unsigned)S1C3_USB_MIDI_BYTES);
        if (i + 1u < S1C3_PACKET_COUNT) {
            const struct timespec delay = {0, S1C3_INTER_PACKET_DELAY_NS};
            if (nanosleep(&delay, NULL) != 0) {
                perror("nanosleep between S1-C3 packets");
                status = 5;
                break;
            }
        }
    }
    if (status == 1) status = 0;
    libusb_release_interface(handle, SMK37_MIDI_INTERFACE);
cleanup:
    if (handle != NULL) libusb_close(handle);
    libusb_exit(context);
    return status;
}
#else
static int send_verified(uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES]) {
    (void)events;
    fputs("send BLOCK: live USB sender is disabled in the offline validation build; compile with S1C3_ENABLE_LIVE_USB only after explicit authorization\n", stderr);
    return 2;
}
#endif

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s dry-run <packet-dir>\n"
            "  %s send <packet-dir> --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}

int main(int argc, char **argv) {
    uint8_t packets[S1C3_PACKET_COUNT][S1C3_PACKET_SIZE];
    uint8_t events[S1C3_PACKET_COUNT][S1C3_USB_MIDI_BYTES];
    if (argc != 3 && argc != 5) {
        usage(argv[0]);
        return 2;
    }
    for (unsigned i = 0; i < S1C3_PACKET_COUNT; ++i) {
        if (verify_packet(argv[2], &PACKETS[i], packets[i]) != 0 || packetize_checked(packets[i], events[i]) != 0) {
            usage(argv[0]);
            return 2;
        }
    }
    if (strcmp(argv[1], "dry-run") == 0 && argc == 3) {
        puts("S1-C3 16-slot sender dry-run PASS: note order slots 0..15 -> notes 36..51, 16 exact packets, no USB/MIDI opened");
        return 0;
    }
    if (strcmp(argv[1], "send") == 0 && argc == 5 && strcmp(argv[3], "--confirm") == 0 && strcmp(argv[4], CONFIRM_TOKEN) == 0) {
        return send_verified(events);
    }
    usage(argv[0]);
    return 2;
}
