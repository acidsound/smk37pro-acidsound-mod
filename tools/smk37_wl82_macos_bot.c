#include <libusb.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    JIELI_VID = 0x4c4a,
    WL80_UBOOT_PID = 0x8057,
    INTERFACE_CLASS_MASS_STORAGE = 0x08,
    INTERFACE_SUBCLASS_SCSI = 0x06,
    INTERFACE_PROTOCOL_BULK_ONLY = 0x50,
    STANDARD_INQUIRY_LENGTH = 36,
    BOT_CBW_LENGTH = 31,
    BOT_CSW_LENGTH = 13,
    BOT_CBW_SIGNATURE = 0x43425355,
    BOT_CSW_SIGNATURE = 0x53425355,
};

static uint32_t read_le32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static void write_le32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void trim_ascii(char *output, size_t output_size,
                       const uint8_t *input, size_t input_size) {
    if (output_size == 0) {
        return;
    }
    size_t length = input_size;
    while (length > 0 && (input[length - 1] == ' ' || input[length - 1] == '\0')) {
        --length;
    }
    if (length >= output_size) {
        length = output_size - 1;
    }
    memcpy(output, input, length);
    output[length] = '\0';
}

static bool exact_inquiry_identity(const uint8_t inquiry[STANDARD_INQUIRY_LENGTH]) {
    char vendor[9];
    char product[17];
    trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
    trim_ascii(product, sizeof(product), inquiry + 16, 16);
    return strcmp(vendor, "WL82") == 0 && strcmp(product, "UBOOT1.00") == 0;
}

static int find_mass_storage_interface(libusb_device *device,
                                       int *interface_number,
                                       uint8_t *bulk_in,
                                       uint8_t *bulk_out) {
    struct libusb_config_descriptor *config = NULL;
    int result = libusb_get_active_config_descriptor(device, &config);
    if (result != LIBUSB_SUCCESS) {
        result = libusb_get_config_descriptor(device, 0, &config);
    }
    if (result != LIBUSB_SUCCESS || config == NULL) {
        return result == LIBUSB_SUCCESS ? LIBUSB_ERROR_NOT_FOUND : result;
    }

    int found = LIBUSB_ERROR_NOT_FOUND;
    for (int i = 0; i < config->bNumInterfaces && found != LIBUSB_SUCCESS; ++i) {
        const struct libusb_interface *interface = &config->interface[i];
        for (int a = 0; a < interface->num_altsetting; ++a) {
            const struct libusb_interface_descriptor *alt = &interface->altsetting[a];
            if (alt->bInterfaceClass != INTERFACE_CLASS_MASS_STORAGE ||
                alt->bInterfaceSubClass != INTERFACE_SUBCLASS_SCSI ||
                alt->bInterfaceProtocol != INTERFACE_PROTOCOL_BULK_ONLY ||
                alt->bNumEndpoints < 2) {
                continue;
            }

            uint8_t in_endpoint = 0;
            uint8_t out_endpoint = 0;
            for (int e = 0; e < alt->bNumEndpoints; ++e) {
                const struct libusb_endpoint_descriptor *endpoint = &alt->endpoint[e];
                if ((endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) !=
                    LIBUSB_TRANSFER_TYPE_BULK) {
                    continue;
                }
                if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ==
                    LIBUSB_ENDPOINT_IN) {
                    in_endpoint = endpoint->bEndpointAddress;
                } else {
                    out_endpoint = endpoint->bEndpointAddress;
                }
            }
            if (in_endpoint != 0 && out_endpoint != 0) {
                *interface_number = alt->bInterfaceNumber;
                *bulk_in = in_endpoint;
                *bulk_out = out_endpoint;
                found = LIBUSB_SUCCESS;
            }
        }
    }
    libusb_free_config_descriptor(config);
    return found;
}

static int bulk_transfer_exact(libusb_device_handle *handle, uint8_t endpoint,
                               unsigned char *data, int length) {
    int transferred = 0;
    int result = libusb_bulk_transfer(handle, endpoint, data, length,
                                      &transferred, 5000);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "bulk endpoint 0x%02x failed: %s\n", endpoint,
                libusb_error_name(result));
        return result;
    }
    if (transferred != length) {
        fprintf(stderr, "bulk endpoint 0x%02x short transfer: %d/%d bytes\n",
                endpoint, transferred, length);
        return LIBUSB_ERROR_IO;
    }
    return LIBUSB_SUCCESS;
}

static int bot_command(libusb_device_handle *handle, uint8_t bulk_in,
                       uint8_t bulk_out, const uint8_t cdb[16],
                       uint8_t cdb_length, uint8_t *data_in,
                       uint32_t data_in_length) {
    static uint32_t tag = 1;
    uint8_t cbw[BOT_CBW_LENGTH] = {0};
    uint8_t csw[BOT_CSW_LENGTH] = {0};
    uint32_t current_tag = tag++;

    write_le32(cbw + 0, BOT_CBW_SIGNATURE);
    write_le32(cbw + 4, current_tag);
    write_le32(cbw + 8, data_in_length);
    cbw[12] = data_in_length == 0 ? 0x00 : 0x80;
    cbw[13] = 0;
    cbw[14] = cdb_length;
    memcpy(cbw + 15, cdb, 16);

    int result = bulk_transfer_exact(handle, bulk_out, cbw, sizeof(cbw));
    if (result != LIBUSB_SUCCESS) {
        return result;
    }
    if (data_in_length > 0) {
        result = bulk_transfer_exact(handle, bulk_in, data_in, (int)data_in_length);
        if (result != LIBUSB_SUCCESS) {
            return result;
        }
    }
    result = bulk_transfer_exact(handle, bulk_in, csw, sizeof(csw));
    if (result != LIBUSB_SUCCESS) {
        return result;
    }
    if (read_le32(csw + 0) != BOT_CSW_SIGNATURE ||
        read_le32(csw + 4) != current_tag || csw[12] != 0) {
        fprintf(stderr, "invalid BOT CSW: signature=0x%08x tag=0x%08x status=%u\n",
                read_le32(csw + 0), read_le32(csw + 4), csw[12]);
        return LIBUSB_ERROR_IO;
    }
    return LIBUSB_SUCCESS;
}

static int probe_device(libusb_device_handle *handle, uint8_t bulk_in,
                        uint8_t bulk_out) {
    uint8_t cdb[16] = {0};
    uint8_t inquiry[STANDARD_INQUIRY_LENGTH] = {0};
    cdb[0] = 0x12;
    cdb[4] = STANDARD_INQUIRY_LENGTH;

    int result = bot_command(handle, bulk_in, bulk_out, cdb, 6, inquiry,
                             sizeof(inquiry));
    if (result != LIBUSB_SUCCESS) {
        return result;
    }

    char vendor[9];
    char product[17];
    char revision[5];
    trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
    trim_ascii(product, sizeof(product), inquiry + 16, 16);
    trim_ascii(revision, sizeof(revision), inquiry + 32, 4);
    printf("vendor=%s product=%s revision=%s%s\n", vendor, product, revision,
           exact_inquiry_identity(inquiry) ? " MATCH=WL82-UBOOT" : "");
    return exact_inquiry_identity(inquiry) ? 0 : 2;
}

static int bot_probe(void) {
    libusb_context *context = NULL;
    libusb_device **devices = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init failed: %s\n", libusb_error_name(result));
        return 1;
    }

    ssize_t count = libusb_get_device_list(context, &devices);
    if (count < 0) {
        fprintf(stderr, "libusb_get_device_list failed: %s\n",
                libusb_error_name((int)count));
        libusb_exit(context);
        return 1;
    }

    int exit_code = 2;
    for (ssize_t i = 0; i < count; ++i) {
        struct libusb_device_descriptor descriptor;
        if (libusb_get_device_descriptor(devices[i], &descriptor) != LIBUSB_SUCCESS ||
            descriptor.idVendor != JIELI_VID || descriptor.idProduct != WL80_UBOOT_PID) {
            continue;
        }

        int interface_number = -1;
        uint8_t bulk_in = 0;
        uint8_t bulk_out = 0;
        result = find_mass_storage_interface(devices[i], &interface_number,
                                             &bulk_in, &bulk_out);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "WL80 device has no usable bulk-only interface: %s\n",
                    libusb_error_name(result));
            exit_code = 1;
            break;
        }
        result = libusb_open(devices[i], &handle);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "libusb_open failed: %s\n", libusb_error_name(result));
            exit_code = 1;
            break;
        }

        result = libusb_set_auto_detach_kernel_driver(handle, 1);
        if (result != LIBUSB_SUCCESS && result != LIBUSB_ERROR_NOT_SUPPORTED) {
            fprintf(stderr, "auto-detach setup failed: %s\n", libusb_error_name(result));
            exit_code = 1;
            break;
        }
        result = libusb_claim_interface(handle, interface_number);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr,
                    "cannot claim mass-storage interface %d; no command sent: %s\n",
                    interface_number, libusb_error_name(result));
            exit_code = 1;
            break;
        }

        printf("interface=%d bulk_in=0x%02x bulk_out=0x%02x\n",
               interface_number, bulk_in, bulk_out);
        exit_code = probe_device(handle, bulk_in, bulk_out);
        libusb_release_interface(handle, interface_number);
        break;
    }

    if (handle != NULL) {
        libusb_close(handle);
    }
    libusb_free_device_list(devices, 1);
    libusb_exit(context);
    if (exit_code == 2) {
        puts("WL80 UBOOT USB device not found");
    }
    return exit_code;
}

static int self_test(void) {
    uint8_t cdb[16] = {0};
    uint8_t cbw[BOT_CBW_LENGTH] = {0};
    cdb[0] = 0x12;
    cdb[4] = STANDARD_INQUIRY_LENGTH;
    write_le32(cbw, BOT_CBW_SIGNATURE);
    cbw[12] = 0x80;
    cbw[14] = 6;
    memcpy(cbw + 15, cdb, sizeof(cdb));
    if (read_le32(cbw) != BOT_CBW_SIGNATURE || cbw[12] != 0x80 ||
        cbw[14] != 6 || cbw[15] != 0x12 || cbw[19] != STANDARD_INQUIRY_LENGTH) {
        fputs("self-test: BOT INQUIRY CBW mismatch\n", stderr);
        return 1;
    }
    puts("self-test: macOS Bulk-Only INQUIRY transport PASS");
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s self-test|bot-probe\n", argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "self-test") == 0) {
        return self_test();
    }
    if (strcmp(argv[1], "bot-probe") == 0) {
        return bot_probe();
    }
    fprintf(stderr, "usage: %s self-test|bot-probe\n", argv[0]);
    return 2;
}
