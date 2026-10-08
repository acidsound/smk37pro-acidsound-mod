#include "usb_probe.h"

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

enum {
    SMK37_V12_VID = 0x4c4a,
    SMK37_V12_PID = 0xc755,
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_UPDATE_INTERFACE = 4,
    SMK37_MIDI_ENDPOINT_OUT = 0x04,
    SMK37_MIDI_ENDPOINT_IN = 0x84,
};

static bool is_supported_device(uint16_t vid, uint16_t pid) {
    return (vid == SMK37_V12_VID && pid == SMK37_V12_PID) ||
           (vid == SMK37_V15_VID && pid == SMK37_V15_PID);
}

static libusb_device_handle *open_supported_device(libusb_context *context) {
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(
        context, SMK37_V15_VID, SMK37_V15_PID);

    if (handle == NULL) {
        handle = libusb_open_device_with_vid_pid(context, SMK37_V12_VID,
                                                 SMK37_V12_PID);
    }
    return handle;
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void sleep_milliseconds(unsigned milliseconds) {
    struct timespec delay = {
        .tv_sec = milliseconds / 1000u,
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
    };

    nanosleep(&delay, NULL);
}

static int send_usb_midi_note(libusb_device_handle *handle,
                              unsigned channel,
                              unsigned note,
                              unsigned velocity,
                              bool note_on) {
    unsigned char packet[4];
    int transferred = 0;
    int result;

    packet[0] = note_on ? 0x09 : 0x08; /* cable 0, Note On/Off CIN */
    packet[1] = (unsigned char)((note_on ? 0x90 : 0x80) | (channel - 1u));
    packet[2] = (unsigned char)note;
    packet[3] = (unsigned char)(note_on ? velocity : 0x40);
    result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT, packet,
                                  sizeof(packet), &transferred, 1000);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "bulk OUT 0x%02x: %s\n", SMK37_MIDI_ENDPOINT_OUT,
                libusb_error_name(result));
        return 1;
    }
    if (transferred != (int)sizeof(packet)) {
        fprintf(stderr, "short USB-MIDI OUT transfer: %d/4\n", transferred);
        return 1;
    }
    return 0;
}

static const char *speed_name(int speed) {
    switch (speed) {
        case LIBUSB_SPEED_LOW: return "low (1.5 Mbit/s)";
        case LIBUSB_SPEED_FULL: return "full (12 Mbit/s)";
        case LIBUSB_SPEED_HIGH: return "high (480 Mbit/s)";
        case LIBUSB_SPEED_SUPER: return "super (5 Gbit/s)";
        case LIBUSB_SPEED_SUPER_PLUS: return "super+";
        default: return "unknown";
    }
}

static const char *transfer_name(uint8_t attributes) {
    switch (attributes & LIBUSB_TRANSFER_TYPE_MASK) {
        case LIBUSB_TRANSFER_TYPE_CONTROL: return "control";
        case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: return "isochronous";
        case LIBUSB_TRANSFER_TYPE_BULK: return "bulk";
        case LIBUSB_TRANSFER_TYPE_INTERRUPT: return "interrupt";
        default: return "unknown";
    }
}

static void print_string(libusb_device_handle *handle,
                         const char *label,
                         uint8_t descriptor_index) {
    unsigned char value[256];
    int result;

    if (descriptor_index == 0) {
        return;
    }

    result = libusb_get_string_descriptor_ascii(handle, descriptor_index,
                                                 value, sizeof(value));
    if (result >= 0) {
        printf("  %s: %.*s\n", label, result, value);
    }
}

static void print_configuration(const struct libusb_config_descriptor *config) {
    printf("  configuration %u: %u interfaces\n",
           config->bConfigurationValue, config->bNumInterfaces);

    for (int interface_index = 0;
         interface_index < config->bNumInterfaces;
         ++interface_index) {
        const struct libusb_interface *interface = &config->interface[interface_index];

        for (int alt_index = 0; alt_index < interface->num_altsetting; ++alt_index) {
            const struct libusb_interface_descriptor *alt =
                &interface->altsetting[alt_index];

            printf("    interface %u alt %u: class 0x%02x subclass 0x%02x, "
                   "%u endpoints\n",
                   alt->bInterfaceNumber, alt->bAlternateSetting,
                   alt->bInterfaceClass, alt->bInterfaceSubClass,
                   alt->bNumEndpoints);

            for (int endpoint_index = 0;
                 endpoint_index < alt->bNumEndpoints;
                 ++endpoint_index) {
                const struct libusb_endpoint_descriptor *endpoint =
                    &alt->endpoint[endpoint_index];
                const char *direction =
                    (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ==
                            LIBUSB_ENDPOINT_IN
                        ? "IN"
                        : "OUT";

                printf("      endpoint 0x%02x %s %-11s max-packet %u interval %u\n",
                       endpoint->bEndpointAddress, direction,
                       transfer_name(endpoint->bmAttributes),
                       endpoint->wMaxPacketSize, endpoint->bInterval);
            }
        }
    }
}

int smk37_probe(void) {
    libusb_context *context = NULL;
    libusb_device **devices = NULL;
    ssize_t device_count;
    int matches = 0;
    int result = libusb_init(&context);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }

    device_count = libusb_get_device_list(context, &devices);
    if (device_count < 0) {
        fprintf(stderr, "libusb_get_device_list: %s\n",
                libusb_error_name((int)device_count));
        libusb_exit(context);
        return 1;
    }

    for (ssize_t index = 0; index < device_count; ++index) {
        libusb_device *device = devices[index];
        struct libusb_device_descriptor descriptor;
        struct libusb_config_descriptor *config = NULL;
        libusb_device_handle *handle = NULL;

        result = libusb_get_device_descriptor(device, &descriptor);
        if (result != LIBUSB_SUCCESS ||
            !is_supported_device(descriptor.idVendor, descriptor.idProduct)) {
            continue;
        }

        ++matches;
        printf("SMK-37 Pro USB device\n");
        printf("  VID:PID: %04x:%04x\n", descriptor.idVendor,
               descriptor.idProduct);
        printf("  bus/address: %u/%u\n", libusb_get_bus_number(device),
               libusb_get_device_address(device));
        printf("  speed: %s\n", speed_name(libusb_get_device_speed(device)));
        printf("  USB version: %x.%02x\n", descriptor.bcdUSB >> 8,
               descriptor.bcdUSB & 0xff);
        printf("  device version: %x.%02x\n", descriptor.bcdDevice >> 8,
               descriptor.bcdDevice & 0xff);

        result = libusb_open(device, &handle);
        if (result == LIBUSB_SUCCESS) {
            print_string(handle, "manufacturer", descriptor.iManufacturer);
            print_string(handle, "product", descriptor.iProduct);
            print_string(handle, "serial", descriptor.iSerialNumber);
            libusb_close(handle);
        } else {
            printf("  open: %s (descriptor inspection continues)\n",
                   libusb_error_name(result));
        }

        result = libusb_get_active_config_descriptor(device, &config);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "  active configuration: %s\n",
                    libusb_error_name(result));
            continue;
        }

        print_configuration(config);
        libusb_free_config_descriptor(config);
    }

    libusb_free_device_list(devices, 1);
    libusb_exit(context);

    if (matches == 0) {
        fprintf(stderr,
                "SMK-37 Pro not found (expected %04x:%04x or %04x:%04x)\n",
                SMK37_V12_VID, SMK37_V12_PID, SMK37_V15_VID, SMK37_V15_PID);
        return 3;
    }

    return 0;
}

int smk37_claim_test(void) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }

    handle = open_supported_device(context);
    if (handle == NULL) {
        fputs("SMK-37 Pro v12/v15 could not be opened\n", stderr);
        libusb_exit(context);
        return 3;
    }

    result = libusb_claim_interface(handle, SMK37_UPDATE_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_UPDATE_INTERFACE,
                libusb_error_name(result));
        libusb_close(handle);
        libusb_exit(context);
        return 4;
    }

    puts("interface 4 claim: ok (no transfer sent)");

    result = libusb_release_interface(handle, SMK37_UPDATE_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "release interface %d: %s\n", SMK37_UPDATE_INTERFACE,
                libusb_error_name(result));
        libusb_close(handle);
        libusb_exit(context);
        return 5;
    }

    puts("interface 4 release: ok");
    libusb_close(handle);
    libusb_exit(context);
    return 0;
}

int smk37_midi_monitor(unsigned seconds) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    unsigned char buffer[256];
    uint64_t deadline;
    unsigned event_count = 0;
    int result = libusb_init(&context);

    if (seconds == 0 || seconds > 300) {
        fputs("monitor duration must be 1..300 seconds\n", stderr);
        return 2;
    }
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }

    handle = open_supported_device(context);
    if (handle == NULL) {
        fputs("SMK-37 Pro v12/v15 could not be opened\n", stderr);
        libusb_exit(context);
        return 3;
    }
    result = libusb_claim_interface(handle, SMK37_UPDATE_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_UPDATE_INTERFACE,
                libusb_error_name(result));
        libusb_close(handle);
        libusb_exit(context);
        return 4;
    }

    printf("direct USB MIDI monitor: %u seconds; press and release pads now\n",
           seconds);
    fflush(stdout);
    deadline = monotonic_milliseconds() + (uint64_t)seconds * 1000u;
    while (monotonic_milliseconds() < deadline) {
        int transferred = 0;
        result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_IN, buffer,
                                      sizeof(buffer), &transferred, 100);
        if (result == LIBUSB_ERROR_TIMEOUT) {
            continue;
        }
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "bulk IN 0x%02x: %s\n", SMK37_MIDI_ENDPOINT_IN,
                    libusb_error_name(result));
            break;
        }
        if (transferred % 4 != 0) {
            fprintf(stderr, "non-USB-MIDI transfer length: %d\n", transferred);
        }
        for (int offset = 0; offset + 3 < transferred; offset += 4) {
            unsigned cable = buffer[offset] >> 4;
            unsigned cin = buffer[offset] & 0x0f;
            unsigned status = buffer[offset + 1];
            unsigned channel = (status & 0x0f) + 1;

            printf("usb-midi cable=%u cin=0x%x bytes=%02x %02x %02x",
                   cable, cin, status, buffer[offset + 2], buffer[offset + 3]);
            if (status >= 0x80 && status < 0xf0) {
                printf(" channel=%u", channel);
            }
            putchar('\n');
            event_count++;
        }
        fflush(stdout);
    }

    printf("direct USB MIDI monitor complete: %u events\n", event_count);
    libusb_release_interface(handle, SMK37_UPDATE_INTERFACE);
    libusb_close(handle);
    libusb_exit(context);
    return result == LIBUSB_SUCCESS || result == LIBUSB_ERROR_TIMEOUT ? 0 : 5;
}

int smk37_midi_channel_test(void) {
    static const unsigned channels[] = {1, 10};
    static const unsigned notes[][3] = {
        {60, 64, 67},
        {36, 40, 43},
    };
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);
    int status = 1;

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }
    handle = open_supported_device(context);
    if (handle == NULL) {
        fputs("SMK-37 Pro v12/v15 could not be opened\n", stderr);
        status = 3;
        goto cleanup;
    }
    result = libusb_claim_interface(handle, SMK37_UPDATE_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_UPDATE_INTERFACE,
                libusb_error_name(result));
        status = 4;
        goto cleanup;
    }

    puts("raw MIDI channel test: Ch1 notes 60,64,67 then Ch10 notes 36,40,43");
    for (size_t group = 0; group < 2; ++group) {
        if (group != 0) {
            puts("waiting 2 seconds before Ch10");
            fflush(stdout);
            sleep_milliseconds(2000);
        }
        for (size_t index = 0; index < 3; ++index) {
            unsigned channel = channels[group];
            unsigned note = notes[group][index];

            printf("send Ch%u note %u on\n", channel, note);
            fflush(stdout);
            if (send_usb_midi_note(handle, channel, note, 100, true) != 0) {
                status = 5;
                goto release;
            }
            sleep_milliseconds(300);
            printf("send Ch%u note %u off\n", channel, note);
            fflush(stdout);
            if (send_usb_midi_note(handle, channel, note, 0, false) != 0) {
                status = 5;
                goto release;
            }
            if (index != 2) {
                sleep_milliseconds(700);
            }
        }
    }
    puts("raw MIDI channel test complete");
    status = 0;

release:
    libusb_release_interface(handle, SMK37_UPDATE_INTERFACE);
cleanup:
    if (handle != NULL) {
        libusb_close(handle);
    }
    libusb_exit(context);
    return status;
}
