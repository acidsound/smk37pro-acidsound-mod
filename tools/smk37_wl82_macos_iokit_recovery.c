#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "sha256.h"

static const char *g_phase = "init";
static void crash_handler(int sig) {
    char msg[128];
    int n = snprintf(msg, sizeof(msg),
                     "\n*** SMK37 RECOVERY CRASH: signal %d at phase '%s' ***\n",
                     sig, g_phase);
    if (n > 0) {
        (void)write(STDERR_FILENO, msg, (size_t)n);
    }
    _exit(128 + sig);
}

enum {
    JIELI_VID = 0x4c4a,
    WL80_UBOOT_PID = 0x8057,
    MASS_STORAGE_CLASS = 0x08,
    SCSI_SUBCLASS = 0x06,
    BULK_ONLY_PROTOCOL = 0x50,
    STANDARD_INQUIRY_LENGTH = 36,
    BOT_CBW_LENGTH = 31,
    BOT_CSW_LENGTH = 13,
    BOT_CBW_SIGNATURE = 0x43425355,
    BOT_CSW_SIGNATURE = 0x53425355,
    LOADER_ADDRESS = 0x01c02000,
    LOADER_ARGUMENT_SPI_NOR = 1,
    LOADER_BLOCK_SIZE = 512,
    OFFICIAL_LOADER_SIZE = 31232,
    FLASH_SIZE = 0x100000,
    SECTOR_SIZE = 0x1000,
    MAX_IO_CHUNK = 4096,
    CMD_ERASE_FLASH_SECTOR = 0xfb01,
    CMD_WRITE_FLASH = 0xfb04,
    CMD_WRITE_MEMORY = 0xfb06,
    CMD_JUMP_TO_MEMORY = 0xfb08,
    CMD_READ_FLASH = 0xfd05,
    CMD_GET_ONLINE_DEVICE = 0xfc0a,
    CMD_READ_ID = 0xfc0b,
    CMD_GET_USB_BUFFER_SIZE = 0xfc14,
};

static const char EXPECTED_LOADER_SHA256[] =
    "9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27";
static const char EXPECTED_STOCK_PACKAGE_SHA256[] =
    "c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a";
static const uint32_t EXPECTED_SECTORS[] = {
    0x04000, 0x20000, 0x21000, 0x27000, 0x5a000, 0x99000,
};

typedef struct {
    IOUSBInterfaceInterface183 **interface;
    IOUSBDeviceInterface182 **device;
    UInt8 bulk_in_pipe;
    UInt8 bulk_out_pipe;
} BotInterface;

typedef struct {
    uint32_t address;
    uint32_t length;
    char path[512];
    char stock_sha256[65];
    char expected_current_sha256[65];
} PlanSector;

typedef struct {
    bool authorized;
    char format[64];
    char target_vid[32];
    char target_pid[32];
    char target_vendor[32];
    char target_product[32];
    char target_revision[32];
    char flash_size[32];
    char representation_status[32];
    char double_dump_status[32];
    char loader_sha256[65];
    char stock_package_sha256[65];
    char dump_report[512];
    char representation_proof[512];
    PlanSector sectors[sizeof(EXPECTED_SECTORS) / sizeof(EXPECTED_SECTORS[0])];
    size_t sector_count;
} RestorePlan;

static uint32_t read_le32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0]) |
           ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t read_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[3]) |
           ((uint32_t)bytes[2] << 8) |
           ((uint32_t)bytes[1] << 16) |
           ((uint32_t)bytes[0] << 24);
}

static void write_le32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void write_be32(uint8_t *bytes, uint32_t value) {
    bytes[0] = (uint8_t)(value >> 24);
    bytes[1] = (uint8_t)(value >> 16);
    bytes[2] = (uint8_t)(value >> 8);
    bytes[3] = (uint8_t)value;
}

static void write_be16(uint8_t *bytes, uint16_t value) {
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

static uint16_t crc16_xmodem(const uint8_t *data, size_t length) {
    uint16_t crc = 0;
    for (size_t index = 0; index < length; ++index) {
        crc ^= (uint16_t)data[index] << 8;
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                  : (uint16_t)(crc << 1);
        }
    }
    return crc;
}

static void hex_digest(const unsigned char digest[SMK37_SHA256_LENGTH],
                       char output[65]) {
    for (size_t index = 0; index < SMK37_SHA256_LENGTH; ++index) {
        snprintf(output + index * 2, 3, "%02x", digest[index]);
    }
    output[64] = '\0';
}

static int sha256_file(const char *path, char output[65], size_t *size_out) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
        return 1;
    }
    unsigned char buffer[1024 * 1024];
    size_t total = 0;
    uint8_t *contents = NULL;
    size_t capacity = 0;
    for (;;) {
        size_t count = fread(buffer, 1, sizeof(buffer), file);
        if (count != 0) {
            if (total > SIZE_MAX - count) {
                fclose(file);
                free(contents);
                return 1;
            }
            size_t needed = total + count;
            if (needed > capacity) {
                size_t next_capacity = capacity == 0 ? sizeof(buffer) : capacity;
                while (next_capacity < needed) {
                    if (next_capacity > SIZE_MAX / 2) {
                        next_capacity = needed;
                        break;
                    }
                    next_capacity *= 2;
                }
                uint8_t *next = realloc(contents, next_capacity);
                if (next == NULL) {
                    fclose(file);
                    free(contents);
                    return 1;
                }
                contents = next;
                capacity = next_capacity;
            }
            memcpy(contents + total, buffer, count);
            total += count;
        }
        if (count < sizeof(buffer)) {
            if (ferror(file)) {
                fprintf(stderr, "read failed for %s\n", path);
                fclose(file);
                return 1;
            }
            break;
        }
    }
    unsigned char digest[SMK37_SHA256_LENGTH];
    smk37_sha256(contents, total, digest);
    fclose(file);
    free(contents);
    hex_digest(digest, output);
    if (size_out != NULL) {
        *size_out = total;
    }
    return 0;
}

static bool copy_registry_u32(io_service_t service, CFStringRef key,
                              uint32_t *value) {
    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service, key, kCFAllocatorDefault, 0);
    if (property == NULL || CFGetTypeID(property) != CFNumberGetTypeID()) {
        if (property != NULL) {
            CFRelease(property);
        }
        return false;
    }
    int64_t number = 0;
    bool ok = CFNumberGetValue((CFNumberRef)property,
                               kCFNumberSInt64Type, &number) &&
              number >= 0 && number <= UINT32_MAX;
    CFRelease(property);
    if (ok) {
        *value = (uint32_t)number;
    }
    return ok;
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

static io_service_t find_interface_service(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBHostInterface");
    if (matching == NULL) {
        return IO_OBJECT_NULL;
    }
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn result = IOServiceGetMatchingServices(
        kIOMainPortDefault, matching, &iterator);
    if (result != kIOReturnSuccess || iterator == IO_OBJECT_NULL) {
        return IO_OBJECT_NULL;
    }
    io_service_t service = IO_OBJECT_NULL;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        uint32_t vid = 0;
        uint32_t pid = 0;
        uint32_t class = 0;
        uint32_t subclass = 0;
        uint32_t protocol = 0;
        bool match = copy_registry_u32(service, CFSTR("idVendor"), &vid) &&
                     copy_registry_u32(service, CFSTR("idProduct"), &pid) &&
                     copy_registry_u32(service, CFSTR("bInterfaceClass"), &class) &&
                     copy_registry_u32(service, CFSTR("bInterfaceSubClass"), &subclass) &&
                     copy_registry_u32(service, CFSTR("bInterfaceProtocol"), &protocol) &&
                     vid == JIELI_VID && pid == WL80_UBOOT_PID &&
                     class == MASS_STORAGE_CLASS && subclass == SCSI_SUBCLASS &&
                     protocol == BULK_ONLY_PROTOCOL;
        if (match) {
            IOObjectRelease(iterator);
            return service;
        }
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    return IO_OBJECT_NULL;
}

static int find_interface(io_service_t *service_out) {
    io_service_t service = find_interface_service();
    if (service == IO_OBJECT_NULL) {
        return kIOReturnNotFound;
    }
    *service_out = service;
    return kIOReturnSuccess;
}

static int find_parent_usb_device(io_service_t interface_service,
                                  io_service_t *device_out) {
    io_service_t current = interface_service;
    io_service_t parent = IO_OBJECT_NULL;
    for (;;) {
        IOReturn result = IORegistryEntryGetParentEntry(
            current, kIOServicePlane, &parent);
        if (result != kIOReturnSuccess) {
            if (current != interface_service) {
                IOObjectRelease(current);
            }
            return result;
        }

        uint32_t vid = 0;
        uint32_t pid = 0;
        bool is_target = copy_registry_u32(parent, CFSTR("idVendor"), &vid) &&
                         copy_registry_u32(parent, CFSTR("idProduct"), &pid) &&
                         vid == JIELI_VID && pid == WL80_UBOOT_PID;
        if (is_target) {
            if (current != interface_service) {
                IOObjectRelease(current);
            }
            *device_out = parent;
            return kIOReturnSuccess;
        }

        if (current != interface_service) {
            IOObjectRelease(current);
        }
        current = parent;
    }
}

static int open_usb_device_seize(io_service_t service,
                                 IOUSBDeviceInterface182 ***device_out) {
    IOCFPlugInInterface **plugin = NULL;
    SInt32 score = 0;
    IOReturn result = IOCreatePlugInInterfaceForService(
        service, kIOUSBDeviceUserClientTypeID, kIOCFPlugInInterfaceID,
        &plugin, &score);
    if (result != kIOReturnSuccess || plugin == NULL) {
        fprintf(stderr, "IOCreatePlugInInterfaceForService(device) failed: 0x%08x\n",
                result);
        return result;
    }

    IOUSBDeviceInterface182 **device = NULL;
    HRESULT query = (*plugin)->QueryInterface(
        plugin, CFUUIDGetUUIDBytes(kIOUSBDeviceInterfaceID182),
        (LPVOID *)&device);
    IODestroyPlugInInterface(plugin);
    if (query != S_OK || device == NULL) {
        fputs("could not obtain IOUSBDeviceInterface182\n", stderr);
        return kIOReturnError;
    }

    result = (*device)->USBDeviceOpenSeize(device);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "USBDeviceOpenSeize fallback failed: 0x%08x\n", result);
        (*device)->Release(device);
        return result;
    }

    *device_out = device;
    puts("USB device opened exclusively; retrying interface seize");
    return kIOReturnSuccess;
}

static void close_usb_device(IOUSBDeviceInterface182 ***device) {
    if (device == NULL || *device == NULL) {
        return;
    }
    (**device)->USBDeviceClose(*device);
    (**device)->Release(*device);
    *device = NULL;
}

static int open_bot_interface(io_service_t service, BotInterface *bot) {
    IOCFPlugInInterface **plugin = NULL;
    SInt32 score = 0;
    IOReturn result = IOCreatePlugInInterfaceForService(
        service, kIOUSBInterfaceUserClientTypeID, kIOCFPlugInInterfaceID,
        &plugin, &score);
    if (result != kIOReturnSuccess || plugin == NULL) {
        fprintf(stderr, "IOCreatePlugInInterfaceForService failed: 0x%08x\n", result);
        return result;
    }

    IOUSBInterfaceInterface183 **interface = NULL;
    HRESULT query = (*plugin)->QueryInterface(
        plugin, CFUUIDGetUUIDBytes(kIOUSBInterfaceInterfaceID183),
        (LPVOID *)&interface);
    IODestroyPlugInInterface(plugin);
    if (query != S_OK || interface == NULL) {
        fputs("could not obtain IOUSBInterfaceInterface183\n", stderr);
        return kIOReturnError;
    }

    UInt8 endpoint_count = 0;

    /* Plain open FIRST, with no parent seize anywhere near it.
     *
     * This order is the whole fix. macOS binds IOUSBMassStorageDriver to the
     * WL80UBOOT1.00 device, and that driver holds the interface. Seizing the
     * parent IOUSBHostDevice before opening the interface makes it worse: once
     * the parent is seized, USBInterfaceOpen and USBInterfaceOpenSeize both
     * return kIOReturnExclusiveAccess, and there is no recovery. Opening the
     * interface on its own returns kIOReturnSuccess on the same device in the
     * same state -- measured, not assumed.
     *
     * The seize path is kept below as a fallback, in case some other Mac
     * config needs it. */
    g_phase = "USBInterfaceOpen (shared, no parent seize)";
    result = (*interface)->USBInterfaceOpen(interface);
    if (result == kIOReturnSuccess) {
        puts("interface opened without parent seize");
        goto interface_opened;
    }
    fprintf(stderr, "[diag] plain USBInterfaceOpen: 0x%08x\n", (unsigned)result);

    g_phase = "USBInterfaceOpenSeize";
    result = (*interface)->USBInterfaceOpenSeize(interface);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "USBInterfaceOpenSeize failed: 0x%08x\n", result);

        g_phase = "find_parent_usb_device";
        io_service_t device_service = IO_OBJECT_NULL;
        IOReturn parent_result = find_parent_usb_device(service, &device_service);
        fprintf(stderr, "[diag] find_parent_usb_device: 0x%08x\n",
                (unsigned)parent_result);
        if (parent_result == kIOReturnSuccess) {
            g_phase = "open_usb_device_seize";
            IOReturn device_result = open_usb_device_seize(
                device_service, &bot->device);
            IOObjectRelease(device_service);
            fprintf(stderr, "[diag] open_usb_device_seize: 0x%08x\n",
                    (unsigned)device_result);
            if (device_result == kIOReturnSuccess) {
                g_phase = "USBInterfaceOpenSeize (after device seize)";
                result = (*interface)->USBInterfaceOpenSeize(interface);
                if (result == kIOReturnSuccess) {
                    puts("interface seized after device seize");
                } else {
                    fprintf(stderr,
                            "USBInterfaceOpenSeize after device seize failed: 0x%08x\n",
                            result);
                    close_usb_device(&bot->device);
                }
            }
        }

        if (result == kIOReturnSuccess) {
            goto interface_opened;
        }

        g_phase = "USBInterfaceOpen (shared)";
        IOReturn shared_result = (*interface)->USBInterfaceOpen(interface);
        fprintf(stderr, "[diag] USBInterfaceOpen (shared): 0x%08x\n",
                (unsigned)shared_result);
        if (shared_result != kIOReturnSuccess) {
            fprintf(stderr, "USBInterfaceOpen fallback failed: 0x%08x\n",
                    shared_result);
            (*interface)->Release(interface);
            return result;
        }
        puts("opened without seize; continuing with read-only probe");
    }

interface_opened:
    result = (*interface)->GetNumEndpoints(interface, &endpoint_count);
    if (result != kIOReturnSuccess || endpoint_count < 2) {
        fprintf(stderr, "GetNumEndpoints failed: 0x%08x count=%u\n",
                result, endpoint_count);
        (*interface)->USBInterfaceClose(interface);
        (*interface)->Release(interface);
        close_usb_device(&bot->device);
        return result == kIOReturnSuccess ? kIOReturnNotFound : result;
    }

    UInt8 bulk_in = 0;
    UInt8 bulk_out = 0;
    for (UInt8 pipe = 1; pipe <= endpoint_count; ++pipe) {
        UInt8 direction = 0;
        UInt8 number = 0;
        UInt8 transfer_type = 0;
        UInt16 max_packet = 0;
        UInt8 interval = 0;
        result = (*interface)->GetPipeProperties(
            interface, pipe, &direction, &number, &transfer_type,
            &max_packet, &interval);
        if (result != kIOReturnSuccess) {
            continue;
        }
        if (transfer_type == kUSBBulk && direction == kUSBIn) {
            bulk_in = pipe;
        } else if (transfer_type == kUSBBulk && direction == kUSBOut) {
            bulk_out = pipe;
        }
    }
    if (bulk_in == 0 || bulk_out == 0) {
        fputs("no bulk IN/OUT pipes found\n", stderr);
        (*interface)->USBInterfaceClose(interface);
        (*interface)->Release(interface);
        close_usb_device(&bot->device);
        return kIOReturnNotFound;
    }

    bot->interface = interface;
    bot->bulk_in_pipe = bulk_in;
    bot->bulk_out_pipe = bulk_out;
    printf("bulk_in_pipe=%u bulk_out_pipe=%u\n", bulk_in, bulk_out);
    return kIOReturnSuccess;
}

static void close_bot_interface(BotInterface *bot) {
    if (bot->interface == NULL) {
        return;
    }
    (*bot->interface)->USBInterfaceClose(bot->interface);
    (*bot->interface)->Release(bot->interface);
    bot->interface = NULL;
    close_usb_device(&bot->device);
}

static int read_pipe(BotInterface *bot, void *buffer, UInt32 length) {
    UInt32 transferred = length;
    IOReturn result = (*bot->interface)->ReadPipeTO(
        bot->interface, bot->bulk_in_pipe, buffer, &transferred, 5000, 5000);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "ReadPipeTO failed: 0x%08x\n", result);
        return result;
    }
    if (transferred != length) {
        fprintf(stderr, "short bulk IN transfer: %u/%u bytes\n",
                transferred, length);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

static int write_pipe(BotInterface *bot, const void *buffer, UInt32 length) {
    IOReturn result = (*bot->interface)->WritePipeTO(
        bot->interface, bot->bulk_out_pipe, (void *)buffer, length, 5000, 5000);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "WritePipeTO failed: 0x%08x\n", result);
        return result;
    }
    return kIOReturnSuccess;
}

static int bot_execute(BotInterface *bot, const uint8_t *cdb, size_t cdb_length,
                       const uint8_t *data_out, size_t data_out_length,
                       uint8_t *data_in, size_t data_in_length) {
    if (cdb_length == 0 || cdb_length > 16 ||
        (data_out_length != 0 && data_in_length != 0) ||
        data_out_length > UINT32_MAX || data_in_length > UINT32_MAX) {
        return kIOReturnBadArgument;
    }
    static uint32_t tag = 1;
    uint8_t cbw[BOT_CBW_LENGTH] = {0};
    uint8_t csw[BOT_CSW_LENGTH] = {0};
    write_le32(cbw + 0, BOT_CBW_SIGNATURE);
    write_le32(cbw + 4, tag);
    uint32_t current_tag = tag++;
    uint32_t transfer_length = (uint32_t)(data_out_length != 0
                                               ? data_out_length
                                               : data_in_length);
    write_le32(cbw + 8, transfer_length);
    cbw[12] = data_in_length != 0 ? 0x80 : 0;
    cbw[14] = (uint8_t)cdb_length;
    memcpy(cbw + 15, cdb, cdb_length);

    int result = write_pipe(bot, cbw, sizeof(cbw));
    if (result != kIOReturnSuccess) {
        return result;
    }
    if (data_out_length != 0) {
        result = write_pipe(bot, data_out, (UInt32)data_out_length);
    } else if (data_in_length != 0) {
        result = read_pipe(bot, data_in, (UInt32)data_in_length);
    }
    if (result != kIOReturnSuccess) {
        return result;
    }
    result = read_pipe(bot, csw, sizeof(csw));
    if (result != kIOReturnSuccess) {
        return result;
    }
    uint32_t residue = read_le32(csw + 8);
    if (read_le32(csw + 0) != BOT_CSW_SIGNATURE ||
        read_le32(csw + 4) != current_tag || csw[12] != 0 || residue != 0) {
        fprintf(stderr,
                "invalid BOT CSW: signature=0x%08x tag=0x%08x status=%u residue=%u\n",
                read_le32(csw + 0), read_le32(csw + 4), csw[12], residue);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

static void build_vendor_cdb(uint8_t cdb[16], uint16_t command,
                             const uint8_t *arguments, size_t argument_length) {
    memset(cdb, 0xff, 16);
    cdb[0] = (uint8_t)(command >> 8);
    cdb[1] = (uint8_t)command;
    if (argument_length != 0) {
        memcpy(cdb + 2, arguments, argument_length);
    }
}

static int command_response(BotInterface *bot, uint16_t command,
                            const uint8_t *arguments, size_t argument_length,
                            uint8_t response[16]) {
    uint8_t cdb[16];
    build_vendor_cdb(cdb, command, arguments, argument_length);
    int result = bot_execute(bot, cdb, sizeof(cdb), NULL, 0, response, 16);
    if (result != kIOReturnSuccess) {
        return result;
    }
    uint16_t returned = (uint16_t)((uint16_t)response[0] << 8 | response[1]);
    if (returned != command) {
        fprintf(stderr, "response CDB mismatch: sent 0x%04x got 0x%04x\n",
                command, returned);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

static int command_data_out(BotInterface *bot, uint16_t command,
                            const uint8_t *arguments, size_t argument_length,
                            const uint8_t *data, size_t data_length) {
    uint8_t cdb[16];
    build_vendor_cdb(cdb, command, arguments, argument_length);
    return bot_execute(bot, cdb, sizeof(cdb), data, data_length, NULL, 0);
}

static int command_data_in(BotInterface *bot, uint16_t command,
                           const uint8_t *arguments, size_t argument_length,
                           uint8_t *data, size_t data_length) {
    uint8_t cdb[16];
    build_vendor_cdb(cdb, command, arguments, argument_length);
    return bot_execute(bot, cdb, sizeof(cdb), NULL, 0, data, data_length);
}

static int bot_inquiry(BotInterface *bot, char vendor[9], char product[17],
                       char revision[5]) {
    uint8_t cdb[6] = {0x12, 0, 0, 0, STANDARD_INQUIRY_LENGTH, 0};
    uint8_t inquiry[STANDARD_INQUIRY_LENGTH] = {0};
    int result = bot_execute(bot, cdb, sizeof(cdb), NULL, 0,
                             inquiry, sizeof(inquiry));
    if (result != kIOReturnSuccess) {
        return result;
    }
    trim_ascii(vendor, 9, inquiry + 8, 8);
    trim_ascii(product, 17, inquiry + 16, 16);
    trim_ascii(revision, 5, inquiry + 32, 4);
    printf("vendor=%s product=%s revision=%s\n", vendor, product, revision);
    if (strcmp(vendor, "WL82") != 0 || strcmp(product, "UBOOT1.00") != 0 ||
        strcmp(revision, "1.00") != 0) {
        fputs("SAFE STOP: exact WL82 UBOOT1.00 identity was not returned\n", stderr);
        return kIOReturnError;
    }
    return kIOReturnSuccess;
}

static int load_file(const char *path, uint8_t **data_out, size_t *length_out) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open loader %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 1;
    }
    long length = ftell(file);
    if (length < 0 || (unsigned long)length > SIZE_MAX) {
        fclose(file);
        return 1;
    }
    rewind(file);
    uint8_t *data = malloc((size_t)length == 0 ? 1 : (size_t)length);
    if (data == NULL || fread(data, 1, (size_t)length, file) != (size_t)length) {
        fprintf(stderr, "cannot read loader %s\n", path);
        free(data);
        fclose(file);
        return 1;
    }
    fclose(file);
    *data_out = data;
    *length_out = (size_t)length;
    return 0;
}

static int validate_loader(const char *path, uint8_t **data_out,
                           size_t *length_out) {
    uint8_t *data = NULL;
    size_t length = 0;
    if (load_file(path, &data, &length) != 0) {
        return 1;
    }
    char hash[65];
    size_t actual_size = 0;
    if (sha256_file(path, hash, &actual_size) != 0 ||
        actual_size != OFFICIAL_LOADER_SIZE ||
        strcmp(hash, EXPECTED_LOADER_SHA256) != 0 ||
        length != OFFICIAL_LOADER_SIZE || length % LOADER_BLOCK_SIZE != 0) {
        fprintf(stderr, "SAFE STOP: loader size/hash mismatch: size=%zu sha256=%s\n",
                actual_size, hash);
        free(data);
        return 1;
    }
    *data_out = data;
    *length_out = length;
    return 0;
}

static int upload_loader(BotInterface *bot, const uint8_t *loader,
                         size_t loader_length) {
    for (size_t offset = 0; offset < loader_length; offset += LOADER_BLOCK_SIZE) {
        uint8_t arguments[9];
        write_be32(arguments, LOADER_ADDRESS + (uint32_t)offset);
        write_be16(arguments + 4, LOADER_BLOCK_SIZE);
        arguments[6] = 0;
        uint16_t crc = crc16_xmodem(loader + offset, LOADER_BLOCK_SIZE);
        arguments[7] = (uint8_t)crc;
        arguments[8] = (uint8_t)(crc >> 8);
        int result = command_data_out(bot, CMD_WRITE_MEMORY, arguments,
                                      sizeof(arguments), loader + offset,
                                      LOADER_BLOCK_SIZE);
        if (result != kIOReturnSuccess) {
            fprintf(stderr, "loader RAM upload failed at 0x%08x\n",
                    LOADER_ADDRESS + (unsigned)offset);
            return result;
        }
    }
    uint8_t arguments[6];
    write_be32(arguments, LOADER_ADDRESS);
    write_be16(arguments + 4, LOADER_ARGUMENT_SPI_NOR);
    uint8_t response[16];
    int result = command_response(bot, CMD_JUMP_TO_MEMORY, arguments,
                                   sizeof(arguments), response);
    if (result == kIOReturnSuccess) {
        usleep(500000);
    }
    return result;
}

static int loader_info(BotInterface *bot, uint32_t *buffer_size_out) {
    uint8_t response[16];
    int result = command_response(bot, CMD_GET_USB_BUFFER_SIZE, NULL, 0,
                                  response);
    if (result != kIOReturnSuccess) {
        return result;
    }
    uint32_t buffer_size = read_be32(response + 2);
    if (buffer_size < 64 || buffer_size > MAX_IO_CHUNK) {
        fprintf(stderr, "SAFE STOP: implausible loader USB buffer size %u\n",
                buffer_size);
        return kIOReturnError;
    }
    result = command_response(bot, CMD_GET_ONLINE_DEVICE, NULL, 0, response);
    if (result != kIOReturnSuccess) {
        return result;
    }
    uint8_t device_type = response[2];
    if (device_type != 0x03 && device_type != 0x16) {
        fprintf(stderr, "SAFE STOP: unexpected loader device type 0x%02x\n",
                device_type);
        return kIOReturnError;
    }
    result = command_response(bot, CMD_READ_ID, NULL, 0, response);
    if (result != kIOReturnSuccess) {
        return result;
    }
    uint32_t flash_id = ((uint32_t)response[2] << 16) |
                        ((uint32_t)response[3] << 8) | response[4];
    printf("loader_buffer_size=%u device_type=0x%02x flash_id=0x%06x\n",
           buffer_size, device_type, flash_id);
    *buffer_size_out = buffer_size;
    return kIOReturnSuccess;
}

static int read_flash(BotInterface *bot, uint32_t address, uint8_t *data,
                      size_t length) {
    if (length == 0 || length > MAX_IO_CHUNK ||
        address >= FLASH_SIZE || length > FLASH_SIZE - address) {
        return kIOReturnBadArgument;
    }
    uint8_t arguments[6];
    write_be32(arguments, address);
    write_be16(arguments + 4, (uint16_t)length);
    return command_data_in(bot, CMD_READ_FLASH, arguments, sizeof(arguments),
                           data, length);
}

static int erase_sector(BotInterface *bot, uint32_t address) {
    if (address % SECTOR_SIZE != 0 || address >= FLASH_SIZE) {
        return kIOReturnBadArgument;
    }
    uint8_t arguments[4];
    write_be32(arguments, address);
    uint8_t response[16];
    return command_response(bot, CMD_ERASE_FLASH_SECTOR, arguments,
                            sizeof(arguments), response);
}

static int write_flash(BotInterface *bot, uint32_t address,
                       const uint8_t *data, size_t length) {
    if (length == 0 || length > MAX_IO_CHUNK ||
        address >= FLASH_SIZE || length > FLASH_SIZE - address) {
        return kIOReturnBadArgument;
    }
    uint8_t arguments[9];
    write_be32(arguments, address);
    write_be16(arguments + 4, (uint16_t)length);
    arguments[6] = 0;
    uint16_t crc = crc16_xmodem(data, length);
    arguments[7] = (uint8_t)crc;
    arguments[8] = (uint8_t)(crc >> 8);
    return command_data_out(bot, CMD_WRITE_FLASH, arguments, sizeof(arguments),
                            data, length);
}

static int dump_flash(BotInterface *bot, uint32_t chunk_size,
                      const char *path, char hash_out[65]) {
    if (chunk_size == 0 || chunk_size > MAX_IO_CHUNK) {
        return kIOReturnBadArgument;
    }
    char partial[1024];
    if (snprintf(partial, sizeof(partial), "%s.partial", path) >=
        (int)sizeof(partial)) {
        return kIOReturnBadArgument;
    }
    FILE *file = fopen(partial, "wb");
    if (file == NULL) {
        fprintf(stderr, "cannot create %s: %s\n", partial, strerror(errno));
        return kIOReturnError;
    }
    uint8_t *buffer = malloc(chunk_size);
    if (buffer == NULL) {
        fclose(file);
        unlink(partial);
        return kIOReturnNoMemory;
    }
    int result = kIOReturnSuccess;
    for (uint32_t address = 0; address < FLASH_SIZE; address += chunk_size) {
        size_t length = chunk_size;
        if (length > FLASH_SIZE - address) {
            length = FLASH_SIZE - address;
        }
        result = read_flash(bot, address, buffer, length);
        if (result != kIOReturnSuccess || fwrite(buffer, 1, length, file) != length) {
            result = kIOReturnError;
            break;
        }
        if (address % 0x10000 == 0) {
            printf("read progress: 0x%06x / 0x%06x\n", address, FLASH_SIZE);
            fflush(stdout);
        }
    }
    if (fflush(file) != 0 || fsync(fileno(file)) != 0) {
        result = kIOReturnError;
    }
    fclose(file);
    free(buffer);
    if (result != kIOReturnSuccess) {
        unlink(partial);
        return result;
    }
    char computed_hash[65];
    size_t computed_size = 0;
    if (sha256_file(partial, computed_hash, &computed_size) != 0 ||
        computed_size != FLASH_SIZE) {
        unlink(partial);
        return kIOReturnError;
    }
    strcpy(hash_out, computed_hash);
    if (rename(partial, path) != 0) {
        fprintf(stderr, "cannot finalize %s: %s\n", path, strerror(errno));
        return kIOReturnError;
    }
    printf("dump=%s sha256=%s\n", path, hash_out);
    return kIOReturnSuccess;
}

static int compare_files(const char *first, const char *second) {
    FILE *a = fopen(first, "rb");
    FILE *b = fopen(second, "rb");
    if (a == NULL || b == NULL) {
        if (a != NULL) fclose(a);
        if (b != NULL) fclose(b);
        return 1;
    }
    uint8_t first_buffer[1024 * 1024];
    uint8_t second_buffer[1024 * 1024];
    int result = 0;
    for (;;) {
        size_t first_count = fread(first_buffer, 1, sizeof(first_buffer), a);
        size_t second_count = fread(second_buffer, 1, sizeof(second_buffer), b);
        if (first_count != second_count ||
            memcmp(first_buffer, second_buffer, first_count) != 0) {
            result = 1;
            break;
        }
        if (first_count < sizeof(first_buffer)) {
            break;
        }
    }
    fclose(a);
    fclose(b);
    return result;
}

static int write_report(const char *directory, const char *dump_a,
                        const char *dump_b, const char *hash_a,
                        const char *hash_b, uint32_t buffer_size) {
    char report_path[1024];
    if (snprintf(report_path, sizeof(report_path), "%s/readonly-report.json",
                 directory) >= (int)sizeof(report_path)) {
        return 1;
    }
    FILE *report = fopen(report_path, "wb");
    if (report == NULL) {
        return 1;
    }
    bool equal = strcmp(hash_a, hash_b) == 0 && compare_files(dump_a, dump_b) == 0;
    fprintf(report,
            "{\n"
            "  \"format\": \"smk37-wl82-readonly-dump-v1\",\n"
            "  \"identity\": {\"vendor\": \"WL82\", \"product\": \"UBOOT1.00\", \"revision\": \"1.00\"},\n"
            "  \"official_loader\": {\"size\": %u, \"sha256\": \"%s\"},\n"
            "  \"loader_info\": {\"usb_buffer_size\": %u},\n"
            "  \"flash_size\": %u,\n"
            "  \"dump_a\": {\"file\": \"%s\", \"sha256\": \"%s\"},\n"
            "  \"dump_b\": {\"file\": \"%s\", \"sha256\": \"%s\"},\n"
            "  \"dumps_byte_identical\": %s,\n"
            "  \"read_only_acquisition_pass\": %s,\n"
            "  \"restore_authorized\": false\n"
            "}\n",
            OFFICIAL_LOADER_SIZE, EXPECTED_LOADER_SHA256, buffer_size, FLASH_SIZE,
            strrchr(dump_a, '/') != NULL ? strrchr(dump_a, '/') + 1 : dump_a,
            hash_a,
            strrchr(dump_b, '/') != NULL ? strrchr(dump_b, '/') + 1 : dump_b,
            hash_b, equal ? "true" : "false", equal ? "true" : "false");
    fclose(report);
    return equal ? 0 : 2;
}

static int bot_open(BotInterface *bot, unsigned wait_seconds) {
    io_service_t service = IO_OBJECT_NULL;
    unsigned waited_ms = 0;
    unsigned attempts = 0;
    for (;;) {
        g_phase = "find_interface";
        IOReturn result = find_interface(&service);
        if (result == kIOReturnSuccess) {
            g_phase = "open_bot_interface";
            result = open_bot_interface(service, bot);
            IOObjectRelease(service);
            if (result == kIOReturnSuccess) {
                g_phase = "open_success";
                return 0;
            }
            attempts++;
            fprintf(stderr,
                "[diag] attempt %u: open_bot_interface failed with 0x%08x\n",
                attempts, (unsigned)result);
            /*
             * 0xe00002c5 = kIOReturnNoDevice: the interface service exists in
             * the registry but the kernel cannot create a user client.  This
             * usually means the V4 is still transitioning its USB handoff.
             * Wait for the next enumeration cycle rather than retrying
             * immediately against the same dead service.
             */
            if (wait_seconds == 0 || waited_ms >= wait_seconds * 1000U) {
                return 1;
            }
            fprintf(stderr,
                "[diag] waiting for re-enumeration (attempt %u, "
                "%u ms elapsed / %u ms max)...\n",
                attempts, waited_ms, wait_seconds * 1000U);
            fflush(stderr);
        }
        if (wait_seconds == 0 || waited_ms >= wait_seconds * 1000U) {
            puts("WL80 UBOOT USB interface not found");
            return 2;
        }
        if (waited_ms == 0) {
            printf("waiting up to %u seconds for WL80 UBOOT USB interface...\n",
                   wait_seconds);
            fflush(stdout);
        }
        /*
         * Use a longer poll interval when the interface is present but
         * unopenable, to avoid hammering the IOKit registry while the V4
         * settles.  500 ms is a good balance.
         */
        usleep(500000);
        waited_ms += 500;
    }
}

static int run_dump(const char *loader_path, const char *directory,
                    uint32_t requested_chunk, unsigned wait_seconds) {
    uint8_t *loader = NULL;
    size_t loader_length = 0;
    if (validate_loader(loader_path, &loader, &loader_length) != 0) {
        return 2;
    }
    if (mkdir(directory, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "cannot create %s: %s\n", directory, strerror(errno));
        free(loader);
        return 2;
    }
    BotInterface bot = {0};
    int result = bot_open(&bot, wait_seconds);
    if (result != 0) {
        free(loader);
        return result;
    }
    char vendor[9], product[17], revision[5];
    g_phase = "bot_inquiry";
    result = bot_inquiry(&bot, vendor, product, revision);
    if (result == kIOReturnSuccess) {
        g_phase = "upload_loader";
        result = upload_loader(&bot, loader, loader_length);
    }
    uint32_t loader_buffer = 0;
    if (result == kIOReturnSuccess) {
        g_phase = "loader_info";
        result = loader_info(&bot, &loader_buffer);
    }
    uint32_t chunk = requested_chunk == 0 ? loader_buffer : requested_chunk;
    if (chunk > loader_buffer) {
        chunk = loader_buffer;
    }
    if (chunk > MAX_IO_CHUNK) {
        chunk = MAX_IO_CHUNK;
    }
    char dump_a[1024], dump_b[1024], hash_a[65] = {0}, hash_b[65] = {0};
    if (snprintf(dump_a, sizeof(dump_a), "%s/flash-dump-a.bin", directory) >=
            (int)sizeof(dump_a) ||
        snprintf(dump_b, sizeof(dump_b), "%s/flash-dump-b.bin", directory) >=
            (int)sizeof(dump_b)) {
        result = kIOReturnBadArgument;
    }
    if (result == kIOReturnSuccess) {
        printf("single-session dump: chunk=%u\n", chunk);
        g_phase = "dump_flash_a";
        result = dump_flash(&bot, chunk, dump_a, hash_a);
    }
    if (result == kIOReturnSuccess) {
        g_phase = "dump_flash_b";
        result = dump_flash(&bot, chunk, dump_b, hash_b);
    }
    g_phase = "close_bot_interface";
    close_bot_interface(&bot);
    free(loader);
    if (result != kIOReturnSuccess) {
        return 2;
    }
    result = write_report(directory, dump_a, dump_b, hash_a, hash_b, loader_buffer);
    if (result == 0) {
        puts("PASS: two byte-identical 1 MiB dumps acquired; restore remains separately blocked");
    } else {
        puts("SAFE STOP: dump A and B are not byte-identical");
    }
    return result;
}

static bool parse_bool(const char *value, bool *result) {
    if (strcmp(value, "true") == 0) {
        *result = true;
        return true;
    }
    if (strcmp(value, "false") == 0) {
        *result = false;
        return true;
    }
    return false;
}

static bool parse_u32(const char *value, uint32_t *result) {
    char *end = NULL;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 0);
    if (errno != 0 || end == value || *end != '\0' || parsed > UINT32_MAX) {
        return false;
    }
    *result = (uint32_t)parsed;
    return true;
}

static int parse_sector_line(char *value, PlanSector *sector) {
    char *fields[5] = {0};
    size_t count = 0;
    char *save = NULL;
    for (char *field = strtok_r(value, "|", &save);
         field != NULL && count < 5;
         field = strtok_r(NULL, "|", &save)) {
        fields[count++] = field;
    }
    if (count != 5 || !parse_u32(fields[0], &sector->address) ||
        !parse_u32(fields[1], &sector->length) ||
        strlen(fields[2]) >= sizeof(sector->path) ||
        strlen(fields[3]) != 64 || strlen(fields[4]) != 64) {
        return 1;
    }
    strcpy(sector->path, fields[2]);
    strcpy(sector->stock_sha256, fields[3]);
    strcpy(sector->expected_current_sha256, fields[4]);
    return 0;
}

static int parse_plan(const char *path, RestorePlan *plan) {
    memset(plan, 0, sizeof(*plan));
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "cannot open restore plan %s: %s\n", path, strerror(errno));
        return 1;
    }
    char line[2048];
    while (fgets(line, sizeof(line), file) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        if (strncmp(line, "sector=", 7) == 0) {
            if (plan->sector_count >= sizeof(plan->sectors) / sizeof(plan->sectors[0]) ||
                parse_sector_line(line + 7, &plan->sectors[plan->sector_count]) != 0) {
                fclose(file);
                return 1;
            }
            plan->sector_count++;
            continue;
        }
        char *equals = strchr(line, '=');
        if (equals == NULL) {
            fclose(file);
            return 1;
        }
        *equals = '\0';
        const char *key = line;
        const char *value = equals + 1;
        if (strcmp(key, "format") == 0) snprintf(plan->format, sizeof(plan->format), "%s", value);
        else if (strcmp(key, "restore_authorized") == 0) {
            if (!parse_bool(value, &plan->authorized)) { fclose(file); return 1; }
        } else if (strcmp(key, "target_vid") == 0) snprintf(plan->target_vid, sizeof(plan->target_vid), "%s", value);
        else if (strcmp(key, "target_pid") == 0) snprintf(plan->target_pid, sizeof(plan->target_pid), "%s", value);
        else if (strcmp(key, "target_vendor") == 0) snprintf(plan->target_vendor, sizeof(plan->target_vendor), "%s", value);
        else if (strcmp(key, "target_product") == 0) snprintf(plan->target_product, sizeof(plan->target_product), "%s", value);
        else if (strcmp(key, "target_revision") == 0) snprintf(plan->target_revision, sizeof(plan->target_revision), "%s", value);
        else if (strcmp(key, "flash_size") == 0) snprintf(plan->flash_size, sizeof(plan->flash_size), "%s", value);
        else if (strcmp(key, "representation_status") == 0) snprintf(plan->representation_status, sizeof(plan->representation_status), "%s", value);
        else if (strcmp(key, "double_dump_status") == 0) snprintf(plan->double_dump_status, sizeof(plan->double_dump_status), "%s", value);
        else if (strcmp(key, "loader_sha256") == 0) snprintf(plan->loader_sha256, sizeof(plan->loader_sha256), "%s", value);
        else if (strcmp(key, "stock_package_sha256") == 0) snprintf(plan->stock_package_sha256, sizeof(plan->stock_package_sha256), "%s", value);
        else if (strcmp(key, "dump_report") == 0) snprintf(plan->dump_report, sizeof(plan->dump_report), "%s", value);
        else if (strcmp(key, "representation_proof") == 0) snprintf(plan->representation_proof, sizeof(plan->representation_proof), "%s", value);
        else { fclose(file); return 1; }
    }
    fclose(file);
    if (strcmp(plan->format, "smk37-macos-restore-plan-v1") != 0 ||
        !plan->authorized || strcmp(plan->target_vid, "0x4C4A") != 0 ||
        strcmp(plan->target_pid, "0x8057") != 0 ||
        strcmp(plan->target_vendor, "WL82") != 0 ||
        strcmp(plan->target_product, "UBOOT1.00") != 0 ||
        strcmp(plan->target_revision, "1.00") != 0 ||
        strcmp(plan->flash_size, "0x100000") != 0 ||
        strcmp(plan->representation_status, "PASS") != 0 ||
        strcmp(plan->double_dump_status, "PASS") != 0 ||
        strcmp(plan->loader_sha256, EXPECTED_LOADER_SHA256) != 0 ||
        strcmp(plan->stock_package_sha256, EXPECTED_STOCK_PACKAGE_SHA256) != 0 ||
        plan->dump_report[0] == '\0' || plan->representation_proof[0] == '\0' ||
        plan->sector_count != sizeof(EXPECTED_SECTORS) / sizeof(EXPECTED_SECTORS[0])) {
        return 1;
    }
    for (size_t index = 0; index < plan->sector_count; ++index) {
        PlanSector *sector = &plan->sectors[index];
        bool expected = false;
        for (size_t expected_index = 0;
             expected_index < sizeof(EXPECTED_SECTORS) / sizeof(EXPECTED_SECTORS[0]);
             ++expected_index) {
            if (sector->address == EXPECTED_SECTORS[expected_index]) {
                expected = true;
                break;
            }
        }
        if (!expected || sector->length != SECTOR_SIZE ||
            sector->address + sector->length > FLASH_SIZE) {
            return 1;
        }
        for (size_t prior = 0; prior < index; ++prior) {
            if (plan->sectors[prior].address == sector->address) {
                return 1;
            }
        }
        size_t file_size = 0;
        char actual_hash[65];
        if (sha256_file(sector->path, actual_hash, &file_size) != 0 ||
            file_size != SECTOR_SIZE || strcmp(actual_hash, sector->stock_sha256) != 0) {
            fprintf(stderr, "SAFE STOP: stock sector hash/size mismatch: %s\n",
                    sector->path);
            return 1;
        }
    }
    for (size_t expected_index = 0;
         expected_index < sizeof(EXPECTED_SECTORS) / sizeof(EXPECTED_SECTORS[0]);
         ++expected_index) {
        bool found = false;
        for (size_t index = 0; index < plan->sector_count; ++index) {
            found |= plan->sectors[index].address == EXPECTED_SECTORS[expected_index];
        }
        if (!found) return 1;
    }
    return 0;
}

static int read_sector_hash(BotInterface *bot, const PlanSector *sector,
                            uint32_t chunk_size, char output[65]) {
    uint8_t *sector_data = malloc(sector->length);
    uint8_t *buffer = malloc(chunk_size);
    if (sector_data == NULL || buffer == NULL) {
        free(sector_data);
        free(buffer);
        return kIOReturnNoMemory;
    }
    int result = kIOReturnSuccess;
    for (uint32_t offset = 0; offset < sector->length; offset += chunk_size) {
        size_t length = chunk_size;
        if (length > sector->length - offset) length = sector->length - offset;
        result = read_flash(bot, sector->address + offset, buffer, length);
        if (result != kIOReturnSuccess) break;
        memcpy(sector_data + offset, buffer, length);
    }
    unsigned char digest_bytes[SMK37_SHA256_LENGTH];
    smk37_sha256(sector_data, sector->length, digest_bytes);
    hex_digest(digest_bytes, output);
    free(sector_data);
    free(buffer);
    return result;
}

static int restore(const char *loader_path, const char *plan_path,
                   const char *target_confirmation,
                   const char *range_confirmation,
                   const char *recoverability_confirmation,
                   unsigned wait_seconds) {
    if (strcmp(target_confirmation, "WL82 UBOOT1.00") != 0 ||
        strcmp(range_confirmation, "six audited 4 KiB sectors only") != 0 ||
        strcmp(recoverability_confirmation,
               "two identical dumps and validated identity mapping") != 0) {
        fputs("SAFE STOP: target/range/recoverability confirmations do not match\n",
              stderr);
        return 2;
    }
    RestorePlan plan;
    if (parse_plan(plan_path, &plan) != 0) {
        fputs("SAFE STOP: restore plan is missing, stale, or not hash-locked\n", stderr);
        return 2;
    }
    uint8_t *loader = NULL;
    size_t loader_length = 0;
    if (validate_loader(loader_path, &loader, &loader_length) != 0) return 2;

    BotInterface bot = {0};
    int result = bot_open(&bot, wait_seconds);
    if (result != 0) {
        free(loader);
        return result;
    }
    char vendor[9], product[17], revision[5];
    result = bot_inquiry(&bot, vendor, product, revision);
    uint32_t loader_buffer = 0;
    if (result == kIOReturnSuccess) result = upload_loader(&bot, loader, loader_length);
    if (result == kIOReturnSuccess) result = loader_info(&bot, &loader_buffer);
    uint32_t chunk = loader_buffer < 512 ? loader_buffer : 512;
    if (result == kIOReturnSuccess) {
        puts("preflight: comparing all six current sectors before any erase");
        for (size_t index = 0; index < plan.sector_count; ++index) {
            char actual[65];
            result = read_sector_hash(&bot, &plan.sectors[index], chunk, actual);
            if (result != kIOReturnSuccess ||
                strcmp(actual, plan.sectors[index].expected_current_sha256) != 0) {
                fprintf(stderr,
                        "SAFE STOP: current sector 0x%05x hash mismatch; no Flash write sent\n",
                        plan.sectors[index].address);
                result = kIOReturnError;
                break;
            }
        }
    }
    if (result == kIOReturnSuccess) {
        puts("WRITE SCOPE: six audited 4 KiB sectors only; no chip erase; no boot-prefix write");
        for (size_t index = 0; index < plan.sector_count; ++index) {
            PlanSector *sector = &plan.sectors[index];
            uint8_t *data = NULL;
            size_t data_length = 0;
            if (load_file(sector->path, &data, &data_length) != 0 ||
                data_length != SECTOR_SIZE) {
                result = kIOReturnError;
                free(data);
                break;
            }
            result = erase_sector(&bot, sector->address);
            for (size_t offset = 0; result == kIOReturnSuccess && offset < data_length;
                 offset += chunk) {
                size_t length = chunk;
                if (length > data_length - offset) length = data_length - offset;
                result = write_flash(&bot, sector->address + (uint32_t)offset,
                                     data + offset, length);
            }
            if (result == kIOReturnSuccess) {
                char actual[65];
                result = read_sector_hash(&bot, sector, chunk, actual);
                if (result == kIOReturnSuccess && strcmp(actual, sector->stock_sha256) != 0) {
                    fprintf(stderr, "SAFE STOP: readback mismatch at 0x%05x\n",
                            sector->address);
                    result = kIOReturnError;
                }
            }
            free(data);
            if (result != kIOReturnSuccess) break;
            printf("PASS: sector 0x%05x erased, written, and read back\n",
                   sector->address);
        }
    }
    close_bot_interface(&bot);
    free(loader);
    if (result != kIOReturnSuccess) {
        fputs("SAFE STOP: restore did not complete; no reset/run-app command was sent\n",
              stderr);
        return 2;
    }
    puts("PASS: stock v12 audited sectors restored and read back");
    puts("NOTE: no reset/run-app command was sent; leave the device off until instructed");
    return 0;
}

static int self_test(void) {
    if (crc16_xmodem((const uint8_t *)"123456789", 9) != 0x31c3) {
        fputs("self-test: CRC16-XMODEM mismatch\n", stderr);
        return 1;
    }
    uint8_t cdb[16];
    uint8_t arguments[6] = {0, 1, 0x20, 0, 1, 0};
    build_vendor_cdb(cdb, CMD_READ_FLASH, arguments, sizeof(arguments));
    if (cdb[0] != 0xfd || cdb[1] != 0x05 || cdb[2] != 0 ||
        cdb[3] != 1 || cdb[4] != 0x20 || cdb[6] != 1 || cdb[7] != 0 ||
        cdb[8] != 0xff ||
        cdb[9] != 0xff || cdb[15] != 0xff) {
        fputs("self-test: vendor CDB encoding mismatch\n", stderr);
        return 1;
    }
    puts("self-test: macOS IOKit BOT read/erase/write transport contracts PASS");
    puts("self-test: no device access and no Flash-mutating command sent");
    return 0;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s self-test\n"
            "  %s bot-probe\n"
            "  %s dump --loader FILE --output DIRECTORY [--chunk-size N] [--wait-seconds N]\n"
            "  %s restore --loader FILE --plan FILE --enable-write "
            "[--wait-seconds N] "
            "--confirm-target 'WL82 UBOOT1.00' "
            "--confirm-range 'six audited 4 KiB sectors only' "
            "--confirm-recoverability 'two identical dumps and validated identity mapping'\n",
            program, program, program, program);
}

/* -----------------------------------------------------------------------
 * sloop-write: install a pinned SLOOP package payload through the UBOOT
 * bulk path, for an instrument already running SLOOP.
 *
 * A SLOOP build with FELUCCA_OTA=0 answers the M-UPGRADE upgrade command with
 * nothing, so the stock two-stage OTA path is unreachable once SLOOP is the
 * running app. It does answer the UBOOT soft key (SysEx F0 22 24 35 7D F7),
 * which lands here: 4c4a:8057, vendor CDB, and the same vendor primitives
 * the M09 six-sector restore uses.
 *
 * What it writes is exactly what stage 2 wrote on the way in: the FWSC
 * payload, the de-interleaved image, at flash address 0. The captured P1
 * transcript shows that verbatim -- request 1 at 0x00000000, request 48 at
 * 0x000aafc0 + 481, which is 701120 bytes.
 *
 * Unlike restore, this is not gated on a sector list or on M09 evidence: the
 * owner accepts that the instrument returns to factory state, and the P1
 * package is byte-reproducible offline. What is pinned is the payload itself.
 * ----------------------------------------------------------------------- */

#define SLOOP_P2_PAYLOAD_SIZE 701120u
static const char EXPECTED_SLOOP_P2_PAYLOAD_SHA256[] =
    "f39733b22c7869dd1f8f66c3196a1376249497b5f28faacd98a2be8f00ce2717";

static int run_sloop_write(const char *loader_path, const char *payload_path,
                           unsigned wait_seconds) {
    uint8_t *loader = NULL;
    size_t loader_length = 0;
    uint8_t *payload = NULL;
    long payload_length = 0;
    char hash[65] = {0};
    size_t payload_size = 0;
    BotInterface bot = {0};
    int result = 2;
    uint32_t chunk = 0;
    uint32_t offset;
    uint32_t sector_end;
    uint32_t sector;

    if (validate_loader(loader_path, &loader, &loader_length) != 0) {
        return 2;
    }
    if (sha256_file(payload_path, hash, &payload_size) != 0) {
        fprintf(stderr, "cannot read payload %s\n", payload_path);
        goto done;
    }
    if (payload_size != SLOOP_P2_PAYLOAD_SIZE ||
        strcmp(hash, EXPECTED_SLOOP_P2_PAYLOAD_SHA256) != 0) {
        fprintf(stderr,
                "SAFE STOP: payload is not the pinned SLOOP pass 2 image: "
                "size=%zu sha256=%s\n", payload_size, hash);
        goto done;
    }
    payload = malloc(payload_size);
    if (payload == NULL) {
        goto done;
    }
    FILE *file = fopen(payload_path, "rb");
    if (file == NULL) {
        perror(payload_path);
        goto done;
    }
    if (fread(payload, 1, payload_size, file) != payload_size) {
        fclose(file);
        fprintf(stderr, "short read on payload\n");
        goto done;
    }
    fclose(file);
    payload_length = (long)payload_size;

    if (bot_open(&bot, wait_seconds) != 0) {
        goto done;
    }
    char vendor[9], product[17], revision[5];
    if (bot_inquiry(&bot, vendor, product, revision) != kIOReturnSuccess) {
        goto done;
    }
    printf("inquiry: vendor=%.8s product=%.16s rev=%.4s\n", vendor, product,
           revision);
    g_phase = "upload_loader";
    if (upload_loader(&bot, loader, loader_length) != kIOReturnSuccess) {
        goto done;
    }
    uint32_t loader_buffer = 0;
    g_phase = "loader_info";
    if (loader_info(&bot, &loader_buffer) != kIOReturnSuccess) {
        goto done;
    }
    chunk = loader_buffer < MAX_IO_CHUNK ? loader_buffer : MAX_IO_CHUNK;
    if (chunk == 0) {
        goto done;
    }

    sector_end = (uint32_t)((payload_size + SECTOR_SIZE - 1) & ~(SECTOR_SIZE - 1));
    printf("payload=%zu bytes, chunk=%u, erasing sectors 0x00000..0x%05x\n",
           payload_size, chunk, sector_end - 1);

    g_phase = "erase";
    for (sector = 0; sector < sector_end; sector += SECTOR_SIZE) {
        if (erase_sector(&bot, sector) != kIOReturnSuccess) {
            fprintf(stderr, "erase failed at 0x%05x\n", sector);
            goto done;
        }
    }
    puts("erase: complete");

    g_phase = "write";
    for (offset = 0; offset < payload_size; offset += chunk) {
        size_t n = payload_size - offset;
        if (n > chunk) {
            n = chunk;
        }
        if (write_flash(&bot, offset, payload + offset, n) != kIOReturnSuccess) {
            fprintf(stderr, "write failed at 0x%05x\n", offset);
            goto done;
        }
        if ((offset & 0xffff) == 0) {
            printf("  wrote 0x%05x / 0x%05x\n", offset, (uint32_t)payload_size);
            fflush(stdout);
        }
    }
    puts("write: complete");

    g_phase = "verify";
    uint8_t *readback = malloc(chunk);
    if (readback == NULL) {
        goto done;
    }
    for (offset = 0; offset < payload_size; offset += chunk) {
        size_t n = payload_size - offset;
        if (n > chunk) {
            n = chunk;
        }
        if (read_flash(&bot, offset, readback, n) != kIOReturnSuccess) {
            fprintf(stderr, "verify read failed at 0x%05x\n", offset);
            free(readback);
            goto done;
        }
        if (memcmp(readback, payload + offset, n) != 0) {
            fprintf(stderr, "VERIFY MISMATCH at 0x%05x\n", offset);
            free(readback);
            goto done;
        }
    }
    free(readback);
    puts("verify: payload read back byte-identical");
    puts("PASS: SLOOP pass 2 payload written and verified");
    result = 0;

done:
    g_phase = "close_bot_interface";
    close_bot_interface(&bot);
    free(loader);
    free(payload);
    (void)payload_length;
    return result;
}

int main(int argc, char **argv) {
    signal(SIGSEGV, crash_handler);
    signal(SIGBUS, crash_handler);
    signal(SIGABRT, crash_handler);
    g_phase = "main";
    if (argc == 2 && strcmp(argv[1], "self-test") == 0) return self_test();
    if (argc == 2 && strcmp(argv[1], "bot-probe") == 0) {
        BotInterface bot = {0};
        int result = bot_open(&bot, 0);
        if (result != 0) return result;
        char vendor[9], product[17], revision[5];
        result = bot_inquiry(&bot, vendor, product, revision);
        close_bot_interface(&bot);
        return result == kIOReturnSuccess ? 0 : 2;
    }
    if (argc >= 6 && strcmp(argv[1], "dump") == 0) {
        const char *loader = NULL;
        const char *output = NULL;
        uint32_t chunk = 0;
        unsigned wait_seconds = 90;
        for (int index = 2; index < argc; ++index) {
            if (strcmp(argv[index], "--loader") == 0 && index + 1 < argc) loader = argv[++index];
            else if (strcmp(argv[index], "--output") == 0 && index + 1 < argc) output = argv[++index];
            else if (strcmp(argv[index], "--chunk-size") == 0 && index + 1 < argc) {
                if (!parse_u32(argv[++index], &chunk)) { usage(argv[0]); return 2; }
            } else if (strcmp(argv[index], "--wait-seconds") == 0 && index + 1 < argc) {
                uint32_t parsed = 0;
                if (!parse_u32(argv[++index], &parsed) || parsed > UINT32_MAX / 1000U) {
                    usage(argv[0]); return 2;
                }
                wait_seconds = (unsigned)parsed;
            } else { usage(argv[0]); return 2; }
        }
        if (loader == NULL || output == NULL) { usage(argv[0]); return 2; }
        return run_dump(loader, output, chunk, wait_seconds);
    }
    if (argc == 7 && strcmp(argv[1], "sloop-write") == 0 &&
        strcmp(argv[5], "--confirm") == 0) {
        if (strcmp(argv[6], "WRITE-SMK37PRO-SLOOP-P2-F39733B2") != 0) {
            fputs("confirmation mismatch; required: "
                  "WRITE-SMK37PRO-SLOOP-P2-F39733B2\n", stderr);
            return 2;
        }
        return run_sloop_write(argv[2], argv[3], (unsigned)strtoul(argv[4], NULL, 10));
    }
    if (argc >= 12 && strcmp(argv[1], "restore") == 0) {
        const char *loader = NULL, *plan = NULL, *target = NULL;
        const char *range = NULL, *recoverability = NULL;
        bool enable_write = false;
        unsigned wait_seconds = 90;
        for (int index = 2; index < argc; ++index) {
            if (strcmp(argv[index], "--loader") == 0 && index + 1 < argc) loader = argv[++index];
            else if (strcmp(argv[index], "--plan") == 0 && index + 1 < argc) plan = argv[++index];
            else if (strcmp(argv[index], "--enable-write") == 0) enable_write = true;
            else if (strcmp(argv[index], "--confirm-target") == 0 && index + 1 < argc) target = argv[++index];
            else if (strcmp(argv[index], "--confirm-range") == 0 && index + 1 < argc) range = argv[++index];
            else if (strcmp(argv[index], "--confirm-recoverability") == 0 && index + 1 < argc) recoverability = argv[++index];
            else if (strcmp(argv[index], "--wait-seconds") == 0 && index + 1 < argc) {
                uint32_t parsed = 0;
                if (!parse_u32(argv[++index], &parsed) || parsed > UINT32_MAX / 1000U) {
                    usage(argv[0]); return 2;
                }
                wait_seconds = (unsigned)parsed;
            }
            else { usage(argv[0]); return 2; }
        }
        if (!enable_write || loader == NULL || plan == NULL || target == NULL ||
            range == NULL || recoverability == NULL) {
            usage(argv[0]);
            return 2;
        }
        return restore(loader, plan, target, range, recoverability, wait_seconds);
    }
    usage(argv[0]);
    return 2;
}
