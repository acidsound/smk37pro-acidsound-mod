#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/usb/IOUSBLib.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
};

typedef struct {
    IOUSBInterfaceInterface183 **interface;
    UInt8 bulk_in_pipe;
    UInt8 bulk_out_pipe;
} BotInterface;

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

static bool expected_identity(const uint8_t inquiry[STANDARD_INQUIRY_LENGTH]) {
    char vendor[9];
    char product[17];
    trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
    trim_ascii(product, sizeof(product), inquiry + 16, 16);
    return strcmp(vendor, "WL82") == 0 && strcmp(product, "UBOOT1.00") == 0;
}

static int find_interface(io_service_t *service_out) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOUSBHostInterface");
    if (matching == NULL) {
        return kIOReturnError;
    }
    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn result = IOServiceGetMatchingServices(
        kIOMainPortDefault, matching, &iterator);
    if (result != kIOReturnSuccess) {
        return result;
    }

    io_service_t service;
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
            *service_out = service;
            IOObjectRelease(iterator);
            return kIOReturnSuccess;
        }
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);
    return kIOReturnNotFound;
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

    result = (*interface)->USBInterfaceOpenSeize(interface);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "USBInterfaceOpenSeize failed: 0x%08x\n", result);
        (*interface)->Release(interface);
        return result;
    }

    UInt8 endpoint_count = 0;
    result = (*interface)->GetNumEndpoints(interface, &endpoint_count);
    if (result != kIOReturnSuccess || endpoint_count < 2) {
        fprintf(stderr, "GetNumEndpoints failed: 0x%08x count=%u\n",
                result, endpoint_count);
        (*interface)->USBInterfaceClose(interface);
        (*interface)->Release(interface);
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

static int write_pipe(BotInterface *bot, void *buffer, UInt32 length) {
    IOReturn result = (*bot->interface)->WritePipeTO(
        bot->interface, bot->bulk_out_pipe, buffer, length, 5000, 5000);
    if (result != kIOReturnSuccess) {
        fprintf(stderr, "WritePipeTO failed: 0x%08x\n", result);
        return result;
    }
    return kIOReturnSuccess;
}

static int bot_inquiry(BotInterface *bot) {
    uint8_t cdb[16] = {0};
    uint8_t cbw[31] = {0};
    uint8_t inquiry[36] = {0};
    uint8_t csw[13] = {0};
    static uint32_t tag = 1;
    uint32_t current_tag = tag++;

    cdb[0] = 0x12;
    cdb[4] = STANDARD_INQUIRY_LENGTH;
    write_le32(cbw + 0, BOT_CBW_SIGNATURE);
    write_le32(cbw + 4, current_tag);
    write_le32(cbw + 8, STANDARD_INQUIRY_LENGTH);
    cbw[12] = 0x80;
    cbw[14] = 6;
    memcpy(cbw + 15, cdb, sizeof(cdb));

    int result = write_pipe(bot, cbw, sizeof(cbw));
    if (result != kIOReturnSuccess) {
        return result;
    }
    result = read_pipe(bot, inquiry, sizeof(inquiry));
    if (result != kIOReturnSuccess) {
        return result;
    }
    result = read_pipe(bot, csw, sizeof(csw));
    if (result != kIOReturnSuccess) {
        return result;
    }
    if (read_le32(csw + 0) != BOT_CSW_SIGNATURE ||
        read_le32(csw + 4) != current_tag || csw[12] != 0) {
        fprintf(stderr, "invalid BOT CSW: signature=0x%08x tag=0x%08x status=%u\n",
                read_le32(csw + 0), read_le32(csw + 4), csw[12]);
        return kIOReturnError;
    }

    char vendor[9];
    char product[17];
    char revision[5];
    trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
    trim_ascii(product, sizeof(product), inquiry + 16, 16);
    trim_ascii(revision, sizeof(revision), inquiry + 32, 4);
    printf("vendor=%s product=%s revision=%s%s\n", vendor, product, revision,
           expected_identity(inquiry) ? " MATCH=WL82-UBOOT" : "");
    return expected_identity(inquiry) ? 0 : 2;
}

static int self_test(void) {
    uint8_t cbw[BOT_CBW_LENGTH] = {0};
    uint8_t cdb[16] = {0};
    write_le32(cbw, BOT_CBW_SIGNATURE);
    cbw[12] = 0x80;
    cbw[14] = 6;
    cdb[0] = 0x12;
    cdb[4] = STANDARD_INQUIRY_LENGTH;
    memcpy(cbw + 15, cdb, sizeof(cdb));
    if (read_le32(cbw) != BOT_CBW_SIGNATURE || cbw[12] != 0x80 ||
        cbw[14] != 6 || cbw[15] != 0x12 || cbw[19] != STANDARD_INQUIRY_LENGTH) {
        fputs("self-test: IOKit BOT INQUIRY CBW mismatch\n", stderr);
        return 1;
    }
    puts("self-test: macOS IOKit BOT INQUIRY transport PASS");
    return 0;
}

static int bot_probe(void) {
    io_service_t service = IO_OBJECT_NULL;
    IOReturn result = find_interface(&service);
    if (result != kIOReturnSuccess) {
        puts("WL80 UBOOT USB interface not found");
        return 2;
    }
    BotInterface bot = {0};
    result = open_bot_interface(service, &bot);
    IOObjectRelease(service);
    if (result != kIOReturnSuccess) {
        return 1;
    }
    int exit_code = bot_inquiry(&bot);
    close_bot_interface(&bot);
    return exit_code;
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
