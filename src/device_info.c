#include "device_info.h"

#include "protocol.h"

#include <libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    SMK37_V12_VID = 0x4c4a,
    SMK37_V12_PID = 0xc755,
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_INTERFACE = 4,
    SMK37_ENDPOINT_OUT = 0x04,
    SMK37_ENDPOINT_IN = 0x84,
    SMK37_INFO_TYPE = 0x11,
    SMK37_TIMEOUT_MS = 2500,
};

static libusb_device_handle *open_supported_device(libusb_context *context) {
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(
        context, SMK37_V15_VID, SMK37_V15_PID);

    if (handle == NULL) {
        handle = libusb_open_device_with_vid_pid(context, SMK37_V12_VID,
                                                 SMK37_V12_PID);
    }
    return handle;
}

static int receive_response(libusb_device_handle *handle, uint8_t *binary,
                            size_t binary_capacity, size_t *binary_length) {
    uint8_t usb_input[64];
    uint8_t stream_chunk[64];
    uint8_t framed[256];
    size_t framed_length = 0;
    bool started = false;
    int elapsed_ms = 0;

    while (elapsed_ms < SMK37_TIMEOUT_MS) {
        int transferred = 0;
        int result = libusb_bulk_transfer(handle, SMK37_ENDPOINT_IN, usb_input,
                                          sizeof(usb_input), &transferred, 100);
        elapsed_ms += 100;

        if (result == LIBUSB_ERROR_TIMEOUT) {
            continue;
        }
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "bulk IN: %s\n", libusb_error_name(result));
            return 1;
        }
        if (transferred == 0) {
            continue;
        }

        size_t chunk_length = smk37_usb_unpacketize(
            usb_input, (size_t)transferred, stream_chunk, sizeof(stream_chunk));
        if (chunk_length == 0) {
            continue;
        }

        for (size_t index = 0; index < chunk_length; ++index) {
            uint8_t value = stream_chunk[index];

            if (!started) {
                if (value != 0xf0) {
                    continue;
                }
                started = true;
                framed_length = 0;
            }

            if (framed_length >= sizeof(framed)) {
                fputs("device response exceeds buffer\n", stderr);
                return 1;
            }
            framed[framed_length++] = value;

            if (value == 0xf7) {
                if (framed_length < 2) {
                    return 1;
                }
                *binary_length = smk37_unpack_7_to_8(
                    framed + 1, framed_length - 2, binary, binary_capacity);
                return *binary_length == 0 ? 1 : 0;
            }
        }
    }

    fputs("device info response timed out\n", stderr);
    return 1;
}

static void print_hex(const uint8_t *data, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        printf("%02x%s", data[index], index + 1 == length ? "\n" : " ");
    }
}

int smk37_read_device_identity(struct smk37_device_identity *identity,
                               bool print_raw_response) {
    static const uint8_t query[] = {
        0x00, 0x59, SMK37_INFO_TYPE, 0x00, 0x00, 0x00, 0xff,
    };
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    uint8_t framed[32];
    uint8_t usb_output[64];
    uint8_t response[256];
    size_t framed_length;
    size_t output_length;
    size_t response_length = 0;
    int transferred = 0;
    int result;
    int status = 1;

    if (identity == NULL) {
        return 2;
    }
    memset(identity, 0, sizeof(*identity));
    result = libusb_init(&context);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }

    handle = open_supported_device(context);
    if (handle == NULL) {
        fputs("SMK-37 Pro could not be opened\n", stderr);
        goto cleanup;
    }

    result = libusb_claim_interface(handle, SMK37_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_INTERFACE,
                libusb_error_name(result));
        goto cleanup;
    }

    framed_length = smk37_frame_binary(query, sizeof(query), framed,
                                       sizeof(framed));
    output_length = smk37_usb_packetize(framed, framed_length, usb_output,
                                        sizeof(usb_output));
    if (framed_length == 0 || output_length == 0) {
        fputs("could not encode device info query\n", stderr);
        goto release;
    }

    result = libusb_bulk_transfer(handle, SMK37_ENDPOINT_OUT, usb_output,
                                  (int)output_length, &transferred, 1000);
    if (result != LIBUSB_SUCCESS || transferred != (int)output_length) {
        fprintf(stderr, "bulk OUT: %s, transferred %d/%zu\n",
                libusb_error_name(result), transferred, output_length);
        goto release;
    }

    if (receive_response(handle, response, sizeof(response),
                         &response_length) != 0) {
        goto release;
    }

    if (print_raw_response) {
        printf("device info response: %zu bytes\n", response_length);
        print_hex(response, response_length);
    }

    if (response_length < 7 || response[0] != 0x00 || response[1] != 0x59 ||
        response[2] != SMK37_INFO_TYPE) {
        fputs("unexpected device info response header\n", stderr);
        goto release;
    }

    uint32_t payload_length = (uint32_t)response[3] |
                              ((uint32_t)response[4] << 8) |
                              ((uint32_t)response[5] << 16);
    if (payload_length < 2 || response_length != (size_t)payload_length + 7 ||
        smk37_complement_checksum(response + 6, payload_length - 1) !=
            response[response_length - 1]) {
        fputs("device info response validation failed\n", stderr);
        goto release;
    }

    size_t text_length = payload_length - 1;
    if (text_length > 25) {
        text_length = 25;
    }
    const uint8_t *nul = memchr(response + 6, 0, text_length);
    if (nul != NULL) {
        text_length = (size_t)(nul - (response + 6));
    }
    if (text_length == 0 || text_length >= SMK37_DEVICE_NAME_CAPACITY) {
        fputs("device info name is invalid\n", stderr);
        goto release;
    }
    memcpy(identity->name, response + 6, text_length);
    identity->name[text_length] = '\0';

    char *separator = strrchr(identity->name, '_');
    if (separator == NULL || strlen(separator + 1) != 3) {
        fputs("device info version suffix is invalid\n", stderr);
        goto release;
    }
    char *version_end = NULL;
    unsigned long version = strtoul(separator + 1, &version_end, 10);
    if (*version_end != '\0' || version > 999) {
        fputs("device info version is invalid\n", stderr);
        goto release;
    }
    *separator = '\0';
    identity->version = (unsigned)version;

    status = 0;

release:
    result = libusb_release_interface(handle, SMK37_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "release interface %d: %s\n", SMK37_INTERFACE,
                libusb_error_name(result));
        status = 1;
    }
cleanup:
    if (handle != NULL) {
        libusb_close(handle);
    }
    libusb_exit(context);
    return status;
}

int smk37_device_info(void) {
    struct smk37_device_identity identity;
    int status = smk37_read_device_identity(&identity, true);

    if (status == 0) {
        printf("name: %s\n", identity.name);
        printf("version: %03u\n", identity.version);
    }
    return status;
}
