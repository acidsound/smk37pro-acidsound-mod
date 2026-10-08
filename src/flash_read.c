#include "flash_read.h"

#include "protocol.h"

#include <libusb.h>
#include <stdbool.h>
#include <stddef.h>
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
    SMK37_FLASH_READ_TYPE = 0x23,
    SMK37_FLASH_TYPE_MAIN = 0,
    SMK37_MAX_READ_DATA = 0x400 - 15,
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

static int receive_binary(libusb_device_handle *handle, uint8_t *binary,
                          size_t capacity, size_t *binary_length) {
    uint8_t usb_input[64];
    uint8_t stream_chunk[64];
    uint8_t framed[2048];
    size_t framed_length = 0;
    bool started = false;

    for (int elapsed_ms = 0; elapsed_ms < 2500; elapsed_ms += 100) {
        int transferred = 0;
        int result = libusb_bulk_transfer(handle, SMK37_ENDPOINT_IN, usb_input,
                                          sizeof(usb_input), &transferred, 100);
        if (result == LIBUSB_ERROR_TIMEOUT) {
            continue;
        }
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "bulk IN: %s\n", libusb_error_name(result));
            return 1;
        }

        size_t chunk_length = smk37_usb_unpacketize(
            usb_input, (size_t)transferred, stream_chunk, sizeof(stream_chunk));
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
                fputs("flash response exceeds framing buffer\n", stderr);
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

    fputs("flash read response timed out\n", stderr);
    return 1;
}

static int send_binary(libusb_device_handle *handle, const uint8_t *binary,
                       size_t binary_length) {
    uint8_t framed[64];
    uint8_t usb_output[128];
    size_t framed_length = smk37_frame_binary(binary, binary_length, framed,
                                              sizeof(framed));
    size_t output_length = smk37_usb_packetize(framed, framed_length,
                                               usb_output, sizeof(usb_output));
    int transferred = 0;
    int result;

    if (framed_length == 0 || output_length == 0) {
        return 1;
    }

    result = libusb_bulk_transfer(handle, SMK37_ENDPOINT_OUT, usb_output,
                                  (int)output_length, &transferred, 1000);
    if (result != LIBUSB_SUCCESS || transferred != (int)output_length) {
        fprintf(stderr, "bulk OUT: %s, transferred %d/%zu\n",
                libusb_error_name(result), transferred, output_length);
        return 1;
    }
    return 0;
}

static void print_hex_dump(uint32_t base, const uint8_t *data, size_t length) {
    for (size_t offset = 0; offset < length; offset += 16) {
        size_t row_length = length - offset > 16 ? 16 : length - offset;
        printf("%08x  ", base + (uint32_t)offset);
        for (size_t column = 0; column < 16; ++column) {
            if (column < row_length) {
                printf("%02x ", data[offset + column]);
            } else {
                fputs("   ", stdout);
            }
        }
        fputs(" |", stdout);
        for (size_t column = 0; column < row_length; ++column) {
            uint8_t value = data[offset + column];
            putchar(value >= 0x20 && value <= 0x7e ? value : '.');
        }
        puts("|");
    }
}

static int open_flash_device(libusb_context **context,
                             libusb_device_handle **handle) {
    int result = libusb_init(context);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }

    *handle = open_supported_device(*context);
    if (*handle == NULL) {
        fputs("SMK-37 Pro could not be opened\n", stderr);
        libusb_exit(*context);
        *context = NULL;
        return 1;
    }

    result = libusb_claim_interface(*handle, SMK37_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", SMK37_INTERFACE,
                libusb_error_name(result));
        libusb_close(*handle);
        libusb_exit(*context);
        *handle = NULL;
        *context = NULL;
        return 1;
    }
    return 0;
}

static int close_flash_device(libusb_context *context,
                              libusb_device_handle *handle) {
    int status = 0;
    int result = libusb_release_interface(handle, SMK37_INTERFACE);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "release interface %d: %s\n", SMK37_INTERFACE,
                libusb_error_name(result));
        status = 1;
    }
    libusb_close(handle);
    libusb_exit(context);
    return status;
}

static int read_flash_chunk(libusb_device_handle *handle, uint32_t address,
                            uint32_t length, uint8_t *data) {
    uint8_t request[15];
    uint8_t response[0x400];
    size_t response_length = 0;
    uint32_t payload_length;
    uint32_t returned_address;
    uint32_t returned_length;

    if (length == 0 || length > SMK37_MAX_READ_DATA) {
        fprintf(stderr, "length must be 1..%u bytes\n", SMK37_MAX_READ_DATA);
        return 2;
    }

    if (smk37_make_flash_read_request(SMK37_FLASH_TYPE_MAIN, address, length,
                                      request, sizeof(request)) !=
        sizeof(request)) {
        return 1;
    }

    if (send_binary(handle, request, sizeof(request)) != 0 ||
        receive_binary(handle, response, sizeof(response), &response_length) !=
            0) {
        return 1;
    }

    if (response_length != (size_t)length + 15 || response[0] != 0x00 ||
        response[1] != 0x59 || response[2] != SMK37_FLASH_READ_TYPE) {
        fprintf(stderr, "unexpected flash response (%zu bytes)\n",
                response_length);
        return 1;
    }

    payload_length = (uint32_t)response[3] |
                     ((uint32_t)response[4] << 8) |
                     ((uint32_t)response[5] << 16);
    returned_address = (uint32_t)response[7] |
                       ((uint32_t)response[8] << 8) |
                       ((uint32_t)response[9] << 16) |
                       ((uint32_t)response[10] << 24);
    returned_length = (uint32_t)response[11] |
                      ((uint32_t)response[12] << 8) |
                      ((uint32_t)response[13] << 16);

    if (payload_length != length + 8 || response[6] != SMK37_FLASH_TYPE_MAIN ||
        returned_address != address || returned_length != length ||
        smk37_complement_checksum(response + 6, response_length - 7) !=
            response[response_length - 1]) {
        fputs("flash response validation failed\n", stderr);
        return 1;
    }

    memcpy(data, response + 14, length);
    return 0;
}

int smk37_flash_read_preview(uint32_t address, uint32_t length) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    uint8_t data[SMK37_MAX_READ_DATA];
    int status;

    if (length == 0 || length > SMK37_MAX_READ_DATA) {
        fprintf(stderr, "length must be 1..%u bytes\n", SMK37_MAX_READ_DATA);
        return 2;
    }
    if (open_flash_device(&context, &handle) != 0) {
        return 1;
    }
    status = read_flash_chunk(handle, address, length, data);
    if (status == 0) {
        printf("flash type 0, address 0x%08x, length %u\n", address, length);
        print_hex_dump(address, data, length);
    }
    if (close_flash_device(context, handle) != 0) {
        status = 1;
    }
    return status;
}

int smk37_flash_dump(const char *output_path, uint32_t length) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    uint8_t data[SMK37_MAX_READ_DATA];
    char *partial_path;
    size_t path_length;
    FILE *output = NULL;
    uint32_t address = 0;
    int status = 1;

    if (length == 0) {
        fputs("dump length must be non-zero\n", stderr);
        return 2;
    }

    path_length = strlen(output_path);
    partial_path = malloc(path_length + sizeof(".partial"));
    if (partial_path == NULL) {
        return 1;
    }
    memcpy(partial_path, output_path, path_length);
    memcpy(partial_path + path_length, ".partial", sizeof(".partial"));

    output = fopen(partial_path, "wb");
    if (output == NULL) {
        perror(partial_path);
        goto cleanup;
    }
    if (open_flash_device(&context, &handle) != 0) {
        goto cleanup;
    }

    while (address < length) {
        uint32_t remaining = length - address;
        uint32_t chunk_length =
            remaining > SMK37_MAX_READ_DATA ? SMK37_MAX_READ_DATA : remaining;

        if (read_flash_chunk(handle, address, chunk_length, data) != 0) {
            fprintf(stderr, "dump failed at address 0x%08x\n", address);
            goto cleanup;
        }
        if (fwrite(data, 1, chunk_length, output) != chunk_length) {
            perror(partial_path);
            goto cleanup;
        }
        address += chunk_length;
        if (address == length || address % 0x10000 < chunk_length) {
            fprintf(stderr, "read 0x%08x / 0x%08x\n", address, length);
        }
    }

    if (fflush(output) != 0 || fclose(output) != 0) {
        output = NULL;
        perror(partial_path);
        goto cleanup;
    }
    output = NULL;
    if (rename(partial_path, output_path) != 0) {
        perror(output_path);
        goto cleanup;
    }
    printf("flash type 0, range 0x%08x..0x%08x, length %u\n", 0u,
           length, length);
    printf("saved: %s\n", output_path);
    status = 0;

cleanup:
    if (handle != NULL && close_flash_device(context, handle) != 0) {
        status = 1;
    }
    if (output != NULL) {
        fclose(output);
    }
    if (status != 0) {
        fprintf(stderr, "partial dump retained: %s\n", partial_path);
    }
    free(partial_path);
    return status;
}
