#include <libusb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef SENDER_SOURCE
#define SENDER_SOURCE "../../../../../tools/smk37_v15_s1c2_send.c"
#endif
#define main smk37_sender_program_main
#include SENDER_SOURCE
#undef main

static const uint8_t *expected_transfer[2];
static int bulk_calls;

int libusb_init(libusb_context **ctx) {
    *ctx = (libusb_context *)(uintptr_t)1;
    return LIBUSB_SUCCESS;
}

libusb_device_handle *libusb_open_device_with_vid_pid(libusb_context *ctx,
                                                       uint16_t vendor_id,
                                                       uint16_t product_id) {
    if (ctx == NULL || vendor_id != 0x4353 || product_id != 0xcf4d) {
        return NULL;
    }
    return (libusb_device_handle *)(uintptr_t)2;
}

int libusb_claim_interface(libusb_device_handle *dev_handle, int interface_number) {
    return dev_handle != NULL && interface_number == 4 ? LIBUSB_SUCCESS : LIBUSB_ERROR_OTHER;
}

int libusb_bulk_transfer(libusb_device_handle *dev_handle, unsigned char endpoint,
                         unsigned char *data, int length, int *transferred,
                         unsigned int timeout) {
    if (dev_handle == NULL || endpoint != 0x04 || length != 220 || timeout != 2000 ||
        bulk_calls >= 2 || memcmp(data, expected_transfer[bulk_calls], 220) != 0) {
        return LIBUSB_ERROR_OTHER;
    }
    *transferred = length;
    ++bulk_calls;
    return LIBUSB_SUCCESS;
}

int libusb_release_interface(libusb_device_handle *dev_handle, int interface_number) {
    return dev_handle != NULL && interface_number == 4 ? LIBUSB_SUCCESS : LIBUSB_ERROR_OTHER;
}

void libusb_close(libusb_device_handle *dev_handle) { (void)dev_handle; }
void libusb_exit(libusb_context *ctx) { (void)ctx; }
const char *libusb_error_name(int errcode) { (void)errcode; return "stub"; }

static int verify_events(const uint8_t packet[163], const uint8_t events[220]) {
    uint8_t reconstructed[163];
    size_t out = 0;
    for (size_t index = 0; index < 54; ++index) {
        size_t base = index * 4;
        if (events[base] != 0x04) return 1;
        reconstructed[out++] = events[base + 1];
        reconstructed[out++] = events[base + 2];
        reconstructed[out++] = events[base + 3];
    }
    if (events[216] != 0x05 || events[217] != 0xf7 ||
        events[218] != 0 || events[219] != 0) return 1;
    reconstructed[out++] = events[217];
    return out != 163 || memcmp(packet, reconstructed, 163) != 0;
}

static void print_digest(const char *label, const uint8_t *data, size_t length) {
    uint8_t digest[SMK37_SHA256_LENGTH];
    smk37_sha256(data, length, digest);
    printf("%s=", label);
    for (size_t i = 0; i < sizeof(digest); ++i) printf("%02x", digest[i]);
    putchar('\n');
}

int main(int argc, char **argv) {
    uint8_t slot0[163], slot1[163], events0[220], events1[220];
    if (argc != 3) return 2;
    if (verify_packet(argv[1], PACKET_SLOT0, slot0) != 0 ||
        verify_packet(argv[2], PACKET_SLOT1, slot1) != 0 ||
        packetize_checked(slot0, events0) != 0 ||
        packetize_checked(slot1, events1) != 0 ||
        verify_events(slot0, events0) != 0 || verify_events(slot1, events1) != 0) {
        return 3;
    }
    print_digest("slot0_usb_midi_sha256", events0, sizeof(events0));
    print_digest("slot1_usb_midi_sha256", events1, sizeof(events1));
    printf("events_per_packet=55\ncontinuation_events=54\nfinal_event=05f70000\n");
    expected_transfer[0] = events0;
    expected_transfer[1] = events1;
    if (send_pair(events0, events1) != 0 || bulk_calls != 2) return 4;
    printf("stubbed_bulk_transfer_order=slot0,slot1\nbulk_transfer_calls=%d\n", bulk_calls);
    return 0;
}
