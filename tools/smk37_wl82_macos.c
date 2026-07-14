#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOCFPlugIn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/scsi/SCSITaskLib.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    INQUIRY_LENGTH = 36,
    INQUIRY_CDB_LENGTH = 6,
    TASK_TIMEOUT_MS = 5000,
};

static void build_inquiry_cdb(uint8_t cdb[INQUIRY_CDB_LENGTH]) {
    memset(cdb, 0, INQUIRY_CDB_LENGTH);
    cdb[0] = 0x12;
    cdb[4] = INQUIRY_LENGTH;
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

static bool is_expected_jieli_inquiry(const uint8_t inquiry[INQUIRY_LENGTH]) {
    char vendor[9];
    char product[17];
    trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
    trim_ascii(product, sizeof(product), inquiry + 16, 16);
    return strcmp(vendor, "WL82") == 0 && strncmp(product, "UBOOT", 5) == 0;
}

static int self_test(void) {
    uint8_t cdb[INQUIRY_CDB_LENGTH];
    build_inquiry_cdb(cdb);
    const uint8_t expected[INQUIRY_CDB_LENGTH] = {0x12, 0, 0, 0, 36, 0};
    if (memcmp(cdb, expected, sizeof(expected)) != 0) {
        fputs("self-test: INQUIRY CDB mismatch\n", stderr);
        return 1;
    }

    uint8_t inquiry[INQUIRY_LENGTH] = {0};
    memcpy(inquiry + 8, "WL82    ", 8);
    memcpy(inquiry + 16, "UBOOT1.00       ", 16);
    if (!is_expected_jieli_inquiry(inquiry)) {
        fputs("self-test: WL82 identity matcher rejected valid data\n", stderr);
        return 1;
    }
    memcpy(inquiry + 8, "OTHER   ", 8);
    if (is_expected_jieli_inquiry(inquiry)) {
        fputs("self-test: WL82 identity matcher accepted another vendor\n", stderr);
        return 1;
    }
    puts("self-test: macOS WL82 read-only probe PASS");
    return 0;
}

static SCSITaskDeviceInterface **create_device_interface(io_service_t service) {
    IOCFPlugInInterface **plugin = NULL;
    SCSITaskDeviceInterface **device = NULL;
    SInt32 score = 0;
    IOReturn kr = IOCreatePlugInInterfaceForService(
        service,
        kIOSCSITaskDeviceUserClientTypeID,
        kIOCFPlugInInterfaceID,
        &plugin,
        &score);
    if (kr != kIOReturnSuccess || plugin == NULL) {
        return NULL;
    }

    HRESULT result = (*plugin)->QueryInterface(
        plugin,
        CFUUIDGetUUIDBytes(kIOSCSITaskDeviceInterfaceID),
        (LPVOID *)&device);
    IODestroyPlugInInterface(plugin);
    if (result != S_OK) {
        return NULL;
    }
    return device;
}

static IOReturn execute_inquiry(SCSITaskDeviceInterface **device,
                                uint8_t inquiry[INQUIRY_LENGTH],
                                SCSITaskStatus *status,
                                UInt64 *transferred,
                                SCSI_Sense_Data *sense) {
    SCSITaskInterface **task = (*device)->CreateSCSITask(device);
    if (task == NULL) {
        return kIOReturnNoResources;
    }

    uint8_t cdb[INQUIRY_CDB_LENGTH];
    build_inquiry_cdb(cdb);
    SCSITaskSGElement element = {
        .address = (mach_vm_address_t)(uintptr_t)inquiry,
        .length = INQUIRY_LENGTH,
    };

    IOReturn kr = (*task)->SetCommandDescriptorBlock(task, cdb, sizeof(cdb));
    if (kr == kIOReturnSuccess) {
        kr = (*task)->SetScatterGatherEntries(
            task, &element, 1, INQUIRY_LENGTH,
            kSCSIDataTransfer_FromTargetToInitiator);
    }
    if (kr == kIOReturnSuccess) {
        kr = (*task)->SetTimeoutDuration(task, TASK_TIMEOUT_MS);
    }
    if (kr == kIOReturnSuccess) {
        kr = (*task)->ExecuteTaskSync(task, sense, status, transferred);
    }
    (*task)->Release(task);
    return kr;
}

static int probe(void) {
    CFMutableDictionaryRef matching = IOServiceMatching("IOSCSIPeripheralDeviceNub");
    if (matching == NULL) {
        fputs("probe: could not create IOKit matching dictionary\n", stderr);
        return 1;
    }

    io_iterator_t iterator = IO_OBJECT_NULL;
    IOReturn kr = IOServiceGetMatchingServices(kIOMainPortDefault, matching, &iterator);
    if (kr != kIOReturnSuccess) {
        fprintf(stderr, "probe: IOServiceGetMatchingServices failed: 0x%08x\n", kr);
        return 1;
    }

    unsigned discovered = 0;
    unsigned opened = 0;
    unsigned expected = 0;
    io_service_t service;
    while ((service = IOIteratorNext(iterator)) != IO_OBJECT_NULL) {
        ++discovered;
        uint64_t registry_id = 0;
        (void)IORegistryEntryGetRegistryEntryID(service, &registry_id);
        SCSITaskDeviceInterface **device = create_device_interface(service);
        if (device == NULL) {
            fprintf(stderr, "probe: service 0x%" PRIx64 " has no SCSITask interface\n",
                    registry_id);
            IOObjectRelease(service);
            continue;
        }

        kr = (*device)->ObtainExclusiveAccess(device);
        if (kr != kIOReturnSuccess) {
            fprintf(stderr,
                    "probe: service 0x%" PRIx64
                    " exclusive access failed: 0x%08x (unmount media or run with privileges)\n",
                    registry_id, kr);
            (*device)->Release(device);
            IOObjectRelease(service);
            continue;
        }
        ++opened;

        uint8_t inquiry[INQUIRY_LENGTH] = {0};
        SCSITaskStatus status = kSCSITaskStatus_No_Status;
        UInt64 transferred = 0;
        SCSI_Sense_Data sense = {0};
        kr = execute_inquiry(device, inquiry, &status, &transferred, &sense);
        if (kr == kIOReturnSuccess && status == kSCSITaskStatus_GOOD &&
            transferred >= INQUIRY_LENGTH) {
            char vendor[9];
            char product[17];
            char revision[5];
            trim_ascii(vendor, sizeof(vendor), inquiry + 8, 8);
            trim_ascii(product, sizeof(product), inquiry + 16, 16);
            trim_ascii(revision, sizeof(revision), inquiry + 32, 4);
            bool match = is_expected_jieli_inquiry(inquiry);
            printf("service=0x%" PRIx64 " vendor=%s product=%s revision=%s%s\n",
                   registry_id, vendor, product, revision,
                   match ? " MATCH=WL82-UBOOT" : "");
            if (match) {
                ++expected;
            }
        } else {
            fprintf(stderr,
                    "probe: service 0x%" PRIx64
                    " INQUIRY failed: io=0x%08x status=0x%02x transferred=%" PRIu64 "\n",
                    registry_id, kr, status, transferred);
        }

        (void)(*device)->ReleaseExclusiveAccess(device);
        (*device)->Release(device);
        IOObjectRelease(service);
    }
    IOObjectRelease(iterator);

    if (expected > 0) {
        return 0;
    }
    printf("WL82 UBOOT not found (services=%u opened=%u)\n", discovered, opened);
    return 2;
}

static void usage(const char *program) {
    fprintf(stderr, "usage: %s self-test|probe\n", program);
    fputs("probe sends only the standard read-only SCSI INQUIRY command.\n", stderr);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        usage(argv[0]);
        return 2;
    }
    if (strcmp(argv[1], "self-test") == 0) {
        return self_test();
    }
    if (strcmp(argv[1], "probe") == 0) {
        return probe();
    }
    usage(argv[0]);
    return 2;
}
