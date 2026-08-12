#include "ota.h"

#include "device_info.h"
#include "fwsc.h"
#include "protocol.h"

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
    SMK37_V12_VID = 0x4c4a,
    SMK37_V12_PID = 0xc755,
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_OTA_VID = 0x4d4a,
    SMK37_OTA_PID = 0x4155,
    SMK37_MAX_OTA_CHUNK = 0x10000 - 15,
};

static const uint32_t SMK37_VERIFY_COMPLETE = UINT32_C(0xe0000000);
static const uint32_t SMK37_UPGRADE_COMPLETE = UINT32_C(0xf0000000);
static const uint8_t SMK37_V012_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xc6, 0xa9, 0x18, 0x7e, 0x70, 0x6a, 0xea, 0xe9,
    0x21, 0x44, 0x7e, 0xc8, 0x8e, 0x29, 0xfe, 0xcb,
    0xc6, 0x18, 0xe3, 0xf1, 0xfc, 0x3d, 0xe5, 0x4c,
    0x74, 0x3c, 0x78, 0xe4, 0x17, 0x81, 0x58, 0x0a,
};
static const uint8_t SMK37_M001_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xaf, 0x9e, 0xf7, 0x8c, 0x80, 0x39, 0x1d, 0x5a,
    0x7e, 0xaa, 0x9d, 0x8d, 0x8b, 0xd5, 0xd6, 0xb3,
    0xe7, 0x7e, 0x89, 0x1c, 0x53, 0x21, 0x50, 0xfb,
    0x80, 0x57, 0x8b, 0xdc, 0xaa, 0x28, 0xa6, 0xa2,
};
static const uint8_t SMK37_M02_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xc2, 0xaa, 0x5e, 0xe8, 0xe8, 0x2a, 0x5c, 0x1a,
    0x85, 0xf5, 0x8c, 0x33, 0x61, 0x40, 0x48, 0x38,
    0xa9, 0xf3, 0xbd, 0x9a, 0x76, 0x57, 0x69, 0x8d,
    0xb2, 0x3e, 0x8f, 0xd5, 0x2b, 0xf1, 0x49, 0xb1,
};
static const uint8_t SMK37_M03_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x21, 0x7b, 0xbd, 0xc3, 0x56, 0xc6, 0x03, 0x22,
    0x70, 0x45, 0xdc, 0xa2, 0x95, 0xe9, 0x2e, 0x9f,
    0xc0, 0x1b, 0x82, 0xb8, 0x97, 0x2b, 0x95, 0x47,
    0x97, 0x35, 0xe6, 0x6e, 0x13, 0x4c, 0x9f, 0xd0,
};
static const uint8_t SMK37_M04_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xff, 0xfb, 0x95, 0x52, 0xd3, 0xea, 0x84, 0x33,
    0xb9, 0x8e, 0x15, 0x0d, 0x4c, 0x52, 0x9e, 0x95,
    0xe3, 0xdd, 0x6b, 0x2b, 0xb1, 0x03, 0xb8, 0x83,
    0x9b, 0xe0, 0x6f, 0x2f, 0x5f, 0x7e, 0x62, 0x46,
};
static const uint8_t SMK37_M05_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x0b, 0xea, 0xb9, 0x77, 0x97, 0x7b, 0xd1, 0x75,
    0xea, 0x48, 0x4b, 0xe4, 0x48, 0x51, 0xc7, 0x69,
    0x58, 0xd2, 0x2d, 0xe4, 0xe7, 0x87, 0xb9, 0xcb,
    0xc3, 0x4d, 0xdf, 0xaa, 0x84, 0x00, 0xc1, 0xf6,
};
static const uint8_t SMK37_M06_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x61, 0xb2, 0xf5, 0x70, 0x7a, 0x2b, 0x57, 0x79,
    0xff, 0xa1, 0x18, 0x61, 0x29, 0x57, 0xb2, 0x32,
    0x02, 0x7d, 0xe7, 0x2f, 0x37, 0x7d, 0x56, 0xad,
    0xc9, 0xd6, 0x8d, 0x6e, 0xd3, 0x02, 0xaa, 0xc4,
};
static const uint8_t SMK37_M07_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xb8, 0x0e, 0xd7, 0x48, 0x01, 0x52, 0xf0, 0x76,
    0x52, 0xeb, 0x8f, 0x80, 0x93, 0x05, 0xf5, 0x0d,
    0x2b, 0xdb, 0x29, 0x90, 0xfb, 0x89, 0x87, 0x5c,
    0x31, 0x7f, 0x27, 0xd5, 0xe9, 0x9d, 0xe0, 0x82,
};
static const uint8_t SMK37_M08_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x44, 0x98, 0xa9, 0x35, 0x95, 0x1e, 0x32, 0xd2,
    0x1b, 0x85, 0x16, 0x7e, 0x5b, 0xa3, 0x69, 0xa5,
    0x05, 0x1d, 0x32, 0xd9, 0x3b, 0xa6, 0x6e, 0x51,
    0x22, 0x9d, 0x5d, 0x25, 0x5c, 0x8d, 0xc3, 0x1f,
};
static const uint8_t SMK37_M10_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x6a, 0xd9, 0x9e, 0xd1, 0x52, 0x32, 0xa5, 0xd8,
    0xe5, 0x5b, 0xe8, 0x36, 0xf3, 0xcb, 0x13, 0x56,
    0x1b, 0x68, 0xb1, 0x52, 0xaa, 0xae, 0x26, 0x42,
    0x96, 0x4e, 0x68, 0x55, 0xbd, 0x66, 0x28, 0xb5,
};
static const uint8_t SMK37_V015_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0xf7, 0xf1, 0x83, 0x1c, 0xd7, 0xc9, 0xad, 0x8b,
    0x48, 0x31, 0xb6, 0xe7, 0x1e, 0xa0, 0xbd, 0xbc,
    0xdf, 0xf9, 0xae, 0x4c, 0x40, 0x77, 0x27, 0x6b,
    0x3c, 0x96, 0x55, 0x11, 0xbf, 0x4d, 0x4f, 0xff,
};
static const uint8_t SMK37_V15_R01_PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {
    0x29, 0x28, 0x09, 0x38, 0x3e, 0x89, 0xba, 0x70,
    0x32, 0x61, 0x9a, 0xe3, 0x38, 0xdf, 0xb5, 0xbd,
    0x19, 0x54, 0x09, 0x60, 0x0f, 0x41, 0x7d, 0xe5,
    0xe8, 0xed, 0xb9, 0x81, 0x49, 0xf6, 0x64, 0x62,
};

struct ota_usb {
    libusb_context *context;
    libusb_device_handle *handle;
    uint8_t bus_number;
    uint8_t port_numbers[8];
    int port_count;
    int interface_number;
    uint8_t endpoint_out;
    uint8_t endpoint_in;
    bool transition_started;
};

static void sleep_ms(unsigned milliseconds) {
    struct timespec duration = {
        .tv_sec = milliseconds / 1000,
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&duration, &duration) != 0) {
    }
}

static int ota_usb_init(struct ota_usb *usb) {
    memset(usb, 0, sizeof(*usb));
    int result = libusb_init(&usb->context);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }
    return 0;
}

static bool same_usb_path(const struct ota_usb *usb, libusb_device *device) {
    uint8_t ports[8];
    int count;

    if (libusb_get_bus_number(device) != usb->bus_number) {
        return false;
    }
    count = libusb_get_port_numbers(device, ports, sizeof(ports));
    return count == usb->port_count && count > 0 &&
           memcmp(ports, usb->port_numbers, (size_t)count) == 0;
}

static int find_midi_streaming_transport(libusb_device *device,
                                         int *interface_number,
                                         uint8_t *endpoint_out,
                                         uint8_t *endpoint_in) {
    struct libusb_config_descriptor *config = NULL;
    int result = libusb_get_active_config_descriptor(device, &config);

    if (result != LIBUSB_SUCCESS) {
        return 1;
    }
    for (int interface_index = 0;
         interface_index < config->bNumInterfaces; ++interface_index) {
        const struct libusb_interface *interface =
            &config->interface[interface_index];
        for (int alt_index = 0; alt_index < interface->num_altsetting;
             ++alt_index) {
            const struct libusb_interface_descriptor *alt =
                &interface->altsetting[alt_index];
            uint8_t found_out = 0;
            uint8_t found_in = 0;

            if (alt->bInterfaceClass != LIBUSB_CLASS_AUDIO ||
                alt->bInterfaceSubClass != 3) {
                continue;
            }
            for (int endpoint_index = 0;
                 endpoint_index < alt->bNumEndpoints; ++endpoint_index) {
                const struct libusb_endpoint_descriptor *endpoint =
                    &alt->endpoint[endpoint_index];
                if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) !=
                    LIBUSB_TRANSFER_TYPE_BULK) {
                    continue;
                }
                if ((endpoint->bEndpointAddress &
                     LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
                    found_in = endpoint->bEndpointAddress;
                } else {
                    found_out = endpoint->bEndpointAddress;
                }
            }
            if (found_out != 0 && found_in != 0) {
                *interface_number = alt->bInterfaceNumber;
                *endpoint_out = found_out;
                *endpoint_in = found_in;
                libusb_free_config_descriptor(config);
                return 0;
            }
        }
    }
    libusb_free_config_descriptor(config);
    return 1;
}

static int claim_device(struct ota_usb *usb, libusb_device *device,
                        bool remember_path) {
    struct libusb_device_descriptor descriptor;
    int result;

    if (find_midi_streaming_transport(device, &usb->interface_number,
                                      &usb->endpoint_out,
                                      &usb->endpoint_in) != 0) {
        return 3;
    }
    result = libusb_open(device, &usb->handle);

    if (result != LIBUSB_SUCCESS) {
        usb->handle = NULL;
        return result == LIBUSB_ERROR_ACCESS ? 1 : 3;
    }
    result = libusb_claim_interface(usb->handle, usb->interface_number);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", usb->interface_number,
                libusb_error_name(result));
        libusb_close(usb->handle);
        usb->handle = NULL;
        return 1;
    }
    if (remember_path) {
        usb->bus_number = libusb_get_bus_number(device);
        usb->port_count = libusb_get_port_numbers(
            device, usb->port_numbers, sizeof(usb->port_numbers));
        if (usb->port_count <= 0) {
            fputs("could not record USB physical port path\n", stderr);
            libusb_release_interface(usb->handle, usb->interface_number);
            libusb_close(usb->handle);
            usb->handle = NULL;
            return 1;
        }
    }
    if (libusb_get_device_descriptor(device, &descriptor) == LIBUSB_SUCCESS) {
        printf("direct USB claim: %04x:%04x at bus %u port",
               descriptor.idVendor, descriptor.idProduct,
               usb->bus_number);
        for (int index = 0; index < usb->port_count; ++index) {
            printf("%s%u", index == 0 ? " " : ".",
                   usb->port_numbers[index]);
        }
        printf(" interface %d endpoints 0x%02x/0x%02x\n",
               usb->interface_number, usb->endpoint_out, usb->endpoint_in);
    }
    return 0;
}

static int ota_usb_open_normal(struct ota_usb *usb) {
    libusb_device **devices = NULL;
    ssize_t count = libusb_get_device_list(usb->context, &devices);
    int status = 3;

    if (count < 0) {
        return 1;
    }
    for (ssize_t index = 0; index < count; ++index) {
        struct libusb_device_descriptor descriptor;
        if (libusb_get_device_descriptor(devices[index], &descriptor) ==
                LIBUSB_SUCCESS &&
            ((descriptor.idVendor == SMK37_V12_VID &&
              descriptor.idProduct == SMK37_V12_PID) ||
             (descriptor.idVendor == SMK37_V15_VID &&
              descriptor.idProduct == SMK37_V15_PID))) {
            status = claim_device(usb, devices[index], true);
            break;
        }
    }
    libusb_free_device_list(devices, 1);
    return status;
}

static int ota_usb_open_same_path(struct ota_usb *usb) {
    libusb_device **devices = NULL;
    ssize_t count = libusb_get_device_list(usb->context, &devices);
    int status = 3;

    if (count < 0) {
        return 1;
    }
    for (ssize_t index = 0; index < count; ++index) {
        if (same_usb_path(usb, devices[index])) {
            status = claim_device(usb, devices[index], false);
            break;
        }
    }
    libusb_free_device_list(devices, 1);
    return status;
}

static int ota_usb_open_update(struct ota_usb *usb) {
    libusb_device **devices = NULL;
    ssize_t count = libusb_get_device_list(usb->context, &devices);
    int status = 3;

    if (count < 0) {
        return 1;
    }
    for (ssize_t index = 0; index < count; ++index) {
        struct libusb_device_descriptor descriptor;
        if (libusb_get_device_descriptor(devices[index], &descriptor) ==
                LIBUSB_SUCCESS &&
            descriptor.idVendor == SMK37_OTA_VID &&
            descriptor.idProduct == SMK37_OTA_PID) {
            status = claim_device(usb, devices[index], true);
            break;
        }
    }
    libusb_free_device_list(devices, 1);
    return status;
}

static void ota_usb_close_handle(struct ota_usb *usb) {
    if (usb->handle != NULL) {
        int result = libusb_release_interface(usb->handle,
                                              usb->interface_number);
        if (result != LIBUSB_SUCCESS && result != LIBUSB_ERROR_NO_DEVICE) {
            fprintf(stderr, "release interface %d: %s\n",
                    usb->interface_number,
                    libusb_error_name(result));
        }
        libusb_close(usb->handle);
        usb->handle = NULL;
    }
}

static void ota_usb_shutdown(struct ota_usb *usb, bool stable_device) {
    ota_usb_close_handle(usb);
    if (usb->context != NULL) {
        if (usb->transition_started && !stable_device) {
            fputs("skipping libusb_exit after detached OTA transition\n",
                  stderr);
        } else {
            libusb_exit(usb->context);
        }
    }
    memset(usb, 0, sizeof(*usb));
}

static int ota_send_stream(struct ota_usb *usb, const uint8_t *stream,
                           size_t stream_length) {
    size_t capacity = ((stream_length + 2) / 3) * 4;
    uint8_t *packets = malloc(capacity);
    size_t packet_length;
    int transferred = 0;
    int result;

    if (packets == NULL) {
        return 1;
    }
    packet_length =
        smk37_usb_packetize(stream, stream_length, packets, capacity);
    if (packet_length == 0 || packet_length > INT32_MAX) {
        free(packets);
        return 1;
    }
    result = libusb_bulk_transfer(usb->handle, usb->endpoint_out, packets,
                                  (int)packet_length, &transferred, 5000);
    free(packets);
    if (result != LIBUSB_SUCCESS || transferred != (int)packet_length) {
        fprintf(stderr, "bulk OUT: %s, transferred %d/%zu\n",
                libusb_error_name(result), transferred, packet_length);
        return 1;
    }
    return 0;
}

static int ota_send_binary(struct ota_usb *usb, const uint8_t *binary,
                           size_t binary_length) {
    size_t framed_capacity = 2 + (binary_length * 8 + 6) / 7;
    uint8_t *framed = malloc(framed_capacity);
    size_t framed_length;
    int status;

    if (framed == NULL) {
        return 1;
    }
    framed_length = smk37_frame_binary(binary, binary_length, framed,
                                       framed_capacity);
    status = framed_length == 0
                 ? 1
                 : ota_send_stream(usb, framed, framed_length);
    free(framed);
    return status;
}

static int ota_receive_binary(struct ota_usb *usb, uint8_t *binary,
                              size_t capacity, size_t *binary_length,
                              unsigned timeout_ms) {
    uint8_t input[64];
    uint8_t stream[64];
    uint8_t framed[4096];
    size_t framed_length = 0;
    bool started = false;

    for (unsigned elapsed = 0; elapsed < timeout_ms; elapsed += 100) {
        int transferred = 0;
        int result = libusb_bulk_transfer(usb->handle, usb->endpoint_in,
                                          input, sizeof(input), &transferred,
                                          100);
        if (result == LIBUSB_ERROR_TIMEOUT) {
            continue;
        }
        if (result == LIBUSB_ERROR_NO_DEVICE) {
            return 2;
        }
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "bulk IN: %s\n", libusb_error_name(result));
            return 1;
        }
        size_t stream_length = smk37_usb_unpacketize(
            input, (size_t)transferred, stream, sizeof(stream));
        for (size_t index = 0; index < stream_length; ++index) {
            uint8_t value = stream[index];
            if (!started) {
                if (value != 0xf0) {
                    continue;
                }
                started = true;
                framed_length = 0;
            }
            if (framed_length >= sizeof(framed)) {
                fputs("OTA request exceeds framing buffer\n", stderr);
                return 1;
            }
            framed[framed_length++] = value;
            if (value == 0xf7) {
                *binary_length = smk37_unpack_7_to_8(
                    framed + 1, framed_length - 2, binary, capacity);
                return *binary_length == 0 ? 1 : 0;
            }
        }
    }
    return 3;
}

static int make_and_send_response(struct ota_usb *usb, uint8_t flash_type,
                                  uint32_t address, const uint8_t *data,
                                  uint32_t length) {
    size_t capacity = (size_t)length + 15;
    uint8_t *packet = malloc(capacity);
    size_t packet_length;
    int status;

    if (packet == NULL) {
        return 1;
    }
    packet_length = smk37_make_flash_update_packet(
        flash_type, address, data, length, packet, capacity);
    status = packet_length == 0 ? 1 : ota_send_binary(usb, packet, packet_length);
    free(packet);
    return status;
}

static int serve_ota_stage(struct ota_usb *usb,
                           const struct smk37_fwsc *firmware,
                           uint32_t expected_completion, FILE *transcript) {
    static const uint8_t success[8] = "success";
    uint8_t packet[64];
    unsigned request_count = 0;

    for (;;) {
        size_t packet_length = 0;
        struct smk37_ota_request request;
        int received = ota_receive_binary(usb, packet, sizeof(packet),
                                          &packet_length, 10000);
        if (received != 0) {
            fprintf(stderr, "OTA request receive failed (%d)\n", received);
            return 1;
        }
        if (smk37_parse_ota_request(packet, packet_length, &request) != 0) {
            fputs("invalid OTA request\n", stderr);
            return 1;
        }
        ++request_count;
        fprintf(transcript,
                "request %u flash=%u address=0x%08x length=%u\n",
                request_count, request.flash_type, request.address,
                request.length);
        fflush(transcript);

        if (request.address == SMK37_VERIFY_COMPLETE ||
            request.address == SMK37_UPGRADE_COMPLETE) {
            if (request.address != expected_completion) {
                fprintf(stderr,
                        "unexpected completion request 0x%08x length %u\n",
                        request.address, request.length);
                return 1;
            }
            if (make_and_send_response(usb, request.flash_type,
                                       request.address, success,
                                       sizeof(success)) != 0) {
                return 1;
            }
            fprintf(transcript, "completion 0x%08x acknowledged\n",
                    request.address);
            fflush(transcript);
            return 0;
        }

        if (request.length == 0 || request.length > SMK37_MAX_OTA_CHUNK ||
            request.address > firmware->payload_length ||
            request.length > firmware->payload_length - request.address) {
            fprintf(stderr,
                    "refusing out-of-range request address=0x%08x length=%u "
                    "payload=%zu\n",
                    request.address, request.length, firmware->payload_length);
            return 1;
        }
        if (make_and_send_response(usb, request.flash_type, request.address,
                                   firmware->payload + request.address,
                                   request.length) != 0) {
            return 1;
        }
    }
}

static int wait_for_ota_usb(struct ota_usb *usb, unsigned timeout_ms) {
    for (unsigned elapsed = 0; elapsed < timeout_ms; elapsed += 250) {
        int result = ota_usb_open_same_path(usb);
        if (result == 0) {
            return 0;
        }
        if (result != 3) {
            return 1;
        }
        sleep_ms(250);
    }
    fputs("timed out waiting for OTA USB device\n", stderr);
    return 1;
}

static int validate_exact_same_version(
    const struct smk37_fwsc *firmware,
    struct smk37_device_identity *device,
    unsigned expected_version,
    const uint8_t expected_sha256[SMK37_SHA256_LENGTH],
    const char *package_description) {
    if (strcmp(firmware->name, "SMK-37 Pro") != 0 ||
        firmware->version != expected_version ||
        memcmp(firmware->file_sha256, expected_sha256,
               SMK37_SHA256_LENGTH) != 0) {
        fprintf(stderr, "package is not the exact %s image\n",
                package_description);
        return 1;
    }
    if (smk37_read_device_identity(device, false) != 0) {
        return 1;
    }
    if (strcmp(device->name, firmware->name) != 0 ||
        device->version != firmware->version ||
        strcmp(device->name, "SMK-37 Pro") != 0) {
        fputs("device/package same-version validation failed\n", stderr);
        return 1;
    }
    return 0;
}

static int validate_resume_package(const struct smk37_fwsc *firmware) {
    if (strcmp(firmware->name, "SMK-37 Pro") != 0 ||
        firmware->version != 12 ||
        memcmp(firmware->file_sha256, SMK37_V012_PACKAGE_SHA256,
               sizeof(SMK37_V012_PACKAGE_SHA256)) != 0) {
        fputs("resume rejected: package is not the archived SMK-37 Pro v12 "
              "image\n", stderr);
        return 1;
    }
    return 0;
}

int smk37_ota_preflight(const char *firmware_path) {
    struct smk37_fwsc firmware;
    struct smk37_device_identity device;
    int status = 1;

    if (!smk37_fwsc_load(firmware_path, &firmware)) {
        return 1;
    }
    if (smk37_read_device_identity(&device, false) != 0) {
        goto cleanup;
    }

    printf("device:  %s_%03u\n", device.name, device.version);
    printf("package: %s_%03u (%zu-byte OTA payload)\n", firmware.name,
           firmware.version, firmware.payload_length);

    if (strcmp(device.name, firmware.name) != 0) {
        fputs("preflight rejected: product names do not match\n", stderr);
        goto cleanup;
    }
    if (device.version != firmware.version) {
        fputs("preflight rejected: this build permits same-version recovery "
              "only\n",
              stderr);
        goto cleanup;
    }
    if (strcmp(device.name, "SMK-37 Pro") != 0) {
        fputs("preflight rejected: unsupported product\n", stderr);
        goto cleanup;
    }

    puts("preflight: ok (read-only; OTA mode command was not sent)");
    status = 0;

cleanup:
    smk37_fwsc_free(&firmware);
    return status;
}

int smk37_ota_dry_run(const char *firmware_path) {
    struct smk37_fwsc firmware;
    static const uint32_t lengths[] = {1, 1009};
    uint8_t *packet = NULL;
    int status = 1;

    if (!smk37_fwsc_load(firmware_path, &firmware)) {
        return 1;
    }
    packet = malloc(SMK37_MAX_OTA_CHUNK + 15);
    if (packet == NULL) {
        goto cleanup;
    }
    for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]);
         ++index) {
        uint32_t length = lengths[index];
        uint32_t address = (uint32_t)(firmware.payload_length - length);
        size_t made = smk37_make_flash_update_packet(
            0, address, firmware.payload + address, length, packet,
            SMK37_MAX_OTA_CHUNK + 15);
        if (made != (size_t)length + 15) {
            goto cleanup;
        }
    }
    if (firmware.payload_length > UINT32_MAX ||
        firmware.payload_length < 1009) {
        goto cleanup;
    }
    puts("upload dry-run: packet generation and payload bounds ok");
    printf("package: %s_%03u, payload %zu bytes\n", firmware.name,
           firmware.version, firmware.payload_length);
    status = 0;

cleanup:
    free(packet);
    smk37_fwsc_free(&firmware);
    return status;
}

static int ota_upload_exact(
    const char *firmware_path, const char *transcript_path,
    const char *confirmation,
    unsigned expected_version,
    const uint8_t expected_sha256[SMK37_SHA256_LENGTH],
    const char *package_description, const char *expected_confirmation,
    const char *completion_message) {
    static const uint8_t upgrade_command[] = {0xf0, 0x22, 0x24,
                                               0x35, 0x7f, 0xf7};
    struct smk37_fwsc firmware;
    struct smk37_device_identity device;
    struct ota_usb usb;
    FILE *transcript = NULL;
    int status = 1;
    bool usb_initialized = false;
    bool stable_device = true;

    if (!smk37_fwsc_load(firmware_path, &firmware)) {
        return 1;
    }
    if (validate_exact_same_version(&firmware, &device, expected_version,
                                    expected_sha256,
                                    package_description) != 0) {
        goto cleanup;
    }
    if (strcmp(confirmation, expected_confirmation) != 0) {
        fprintf(stderr, "confirmation mismatch; required: %s\n",
                expected_confirmation);
        goto cleanup;
    }
    transcript = fopen(transcript_path, "wx");
    if (transcript == NULL) {
        perror(transcript_path);
        goto cleanup;
    }
    fprintf(transcript,
            "policy=%s device=%s_%03u package=%s_%03u payload=%zu\n",
            package_description,
            device.name, device.version, firmware.name, firmware.version,
            firmware.payload_length);
    fflush(transcript);

    puts("OTA stage 1/2: package verification");
    if (ota_usb_init(&usb) != 0) {
        goto cleanup;
    }
    usb_initialized = true;
    if (ota_usb_open_normal(&usb) != 0 ||
        ota_send_stream(&usb, upgrade_command, sizeof(upgrade_command)) != 0) {
        goto usb_cleanup;
    }
    sleep_ms(2000);
    if (serve_ota_stage(&usb, &firmware, SMK37_VERIFY_COMPLETE,
                        transcript) != 0) {
        goto usb_cleanup;
    }
    usb.transition_started = true;
    stable_device = false;
    ota_usb_close_handle(&usb);

    puts("OTA stage 2/2: waiting for update mode");
    sleep_ms(3000);
    if (wait_for_ota_usb(&usb, 15000) != 0 ||
        ota_send_stream(&usb, upgrade_command, sizeof(upgrade_command)) != 0 ||
        serve_ota_stage(&usb, &firmware, SMK37_UPGRADE_COMPLETE,
                        transcript) != 0) {
        goto usb_cleanup;
    }
    ota_usb_close_handle(&usb);

    puts("OTA completed; waiting for normal firmware");
    sleep_ms(5000);
    if (smk37_read_device_identity(&device, false) != 0 ||
        strcmp(device.name, firmware.name) != 0 ||
        device.version != firmware.version) {
        fputs("post-update identity verification failed\n", stderr);
        goto cleanup;
    }
    fprintf(transcript, "post-update=%s_%03u verified\n", device.name,
            device.version);
    puts(completion_message);
    stable_device = true;
    status = 0;
    goto usb_cleanup;

usb_cleanup:
    if (usb_initialized) {
        ota_usb_shutdown(&usb, stable_device);
    }
cleanup:
    if (transcript != NULL && fclose(transcript) != 0) {
        perror(transcript_path);
        status = 1;
    }
    smk37_fwsc_free(&firmware);
    return status;
}

int smk37_ota_upload(const char *firmware_path, const char *transcript_path,
                     const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_V012_PACKAGE_SHA256, "archived SMK-37 Pro v12",
        "SMK-37-Pro-012",
        "same-version OTA restore: completed and identity verified");
}

int smk37_ota_upload_m001(const char *firmware_path,
                          const char *transcript_path,
                          const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M001_PACKAGE_SHA256, "SMK37ProMod M001 marker-only",
        "INSTALL-SMK37PRO-M001-AF9EF78C",
        "M001 OTA install: USB identity 012 verified; check display for M001");
}

int smk37_ota_upload_m02(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M02_PACKAGE_SHA256, "SMK37ProMod M02 three-character marker",
        "INSTALL-SMK37PRO-M02-C2AA5EE8",
        "M02 OTA install: USB identity 012 verified; check display for M02");
}

int smk37_ota_upload_m03(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M03_PACKAGE_SHA256, "SMK37ProMod M03 Hello/acidsound display",
        "INSTALL-SMK37PRO-M03-217BBDC3",
        "M03 OTA install: USB identity 012 verified; check display for M03");
}

int smk37_ota_upload_m04(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M04_PACKAGE_SHA256, "SMK37ProMod M04 exact two-line display",
        "INSTALL-SMK37PRO-M04-FFFB9552",
        "M04 OTA install: USB identity 012 verified; check display for M04");
}

int smk37_ota_upload_m05(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M05_PACKAGE_SHA256, "SMK37ProMod M05 minimal two-timbre",
        "INSTALL-SMK37PRO-M05-0BEAB977",
        "M05 OTA install: USB identity 012 verified; test MIDI channels 1/2");
}

int smk37_ota_upload_m06(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M06_PACKAGE_SHA256, "SMK37ProMod M06 local-pad channel-10 FM",
        "INSTALL-SMK37PRO-M06-61B2F570",
        "M06 OTA install: USB identity 012 verified; test local keys/pads");
}

int smk37_ota_upload_m07(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M07_PACKAGE_SHA256, "SMK37ProMod M07 per-note channel-10 FM",
        "INSTALL-SMK37PRO-M07-B80ED748",
        "M07 OTA install: USB identity 012 verified; test all 16 pads");
}

int smk37_ota_upload_m08(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M08_PACKAGE_SHA256, "SMK37ProMod M08 isolated fixed Ch10 map",
        "INSTALL-SMK37PRO-M08-4498A935",
        "M08 OTA install: USB identity 012 verified; test Ch1/Ch10 isolation");
}

int smk37_ota_upload_m10(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        12,
        SMK37_M10_PACKAGE_SHA256, "SMK37ProMod M10 data-only M08 follow-up",
        "INSTALL-SMK37PRO-M10-6AD99ED1",
        "M10 OTA install: USB identity 012 verified; data-only boot probe");
}

int smk37_ota_upload_v15(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        15, SMK37_V015_PACKAGE_SHA256,
        "official SMK-37 Pro v15 baseline",
        "RESTORE-SMK37PRO-OFFICIAL-V15-F7F1831C",
        "official v15 restore: USB identity 015 verified");
}

int smk37_ota_upload_v15_r01(const char *firmware_path,
                             const char *transcript_path,
                             const char *confirmation) {
    return ota_upload_exact(
        firmware_path, transcript_path, confirmation,
        15, SMK37_V15_R01_PACKAGE_SHA256,
        "v15 R01 evidence-based Channel-10 HAND DRUM",
        "INSTALL-SMK37PRO-V15-R01-29280938",
        "v15 R01 install: USB identity 015 verified; test Ch1 and Ch10");
}

int smk37_ota_resume_v12(const char *firmware_path,
                         const char *transcript_path,
                         const char *confirmation) {
    static const uint8_t upgrade_command[] = {0xf0, 0x22, 0x24,
                                               0x35, 0x7f, 0xf7};
    struct smk37_fwsc firmware;
    struct smk37_device_identity device;
    struct ota_usb usb;
    FILE *transcript = NULL;
    int status = 1;
    bool usb_initialized = false;
    bool stable_device = false;

    if (!smk37_fwsc_load(firmware_path, &firmware)) {
        return 1;
    }
    if (validate_resume_package(&firmware) != 0) {
        goto cleanup;
    }
    if (strcmp(confirmation, "RESUME-SMK-37-Pro-012-STAGE2") != 0) {
        fputs("confirmation mismatch; required: "
              "RESUME-SMK-37-Pro-012-STAGE2\n", stderr);
        goto cleanup;
    }
    transcript = fopen(transcript_path, "wx");
    if (transcript == NULL) {
        perror(transcript_path);
        goto cleanup;
    }
    fprintf(transcript,
            "resume-stage2 package=%s_%03u payload=%zu\n",
            firmware.name, firmware.version, firmware.payload_length);
    fflush(transcript);

    if (ota_usb_init(&usb) != 0) {
        goto cleanup;
    }
    usb_initialized = true;
    usb.transition_started = true;
    puts("OTA resume stage 2/2: claiming update-mode device");
    if (ota_usb_open_update(&usb) != 0 ||
        ota_send_stream(&usb, upgrade_command, sizeof(upgrade_command)) != 0 ||
        serve_ota_stage(&usb, &firmware, SMK37_UPGRADE_COMPLETE,
                        transcript) != 0) {
        goto usb_cleanup;
    }
    ota_usb_close_handle(&usb);

    puts("OTA completed; waiting for normal firmware");
    sleep_ms(5000);
    if (smk37_read_device_identity(&device, false) != 0 ||
        strcmp(device.name, firmware.name) != 0 ||
        device.version != firmware.version) {
        fputs("post-update identity verification failed\n", stderr);
        goto usb_cleanup;
    }
    fprintf(transcript, "post-update=%s_%03u verified\n", device.name,
            device.version);
    puts("same-version OTA restore: completed and identity verified");
    stable_device = true;
    status = 0;

usb_cleanup:
    if (usb_initialized) {
        ota_usb_shutdown(&usb, stable_device);
    }
cleanup:
    if (transcript != NULL && fclose(transcript) != 0) {
        perror(transcript_path);
        status = 1;
    }
    smk37_fwsc_free(&firmware);
    return status;
}
