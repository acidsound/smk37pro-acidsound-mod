#include <libusb.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

enum {
    SMK37_V15_VID = 0x4353,
    SMK37_V15_PID = 0xcf4d,
    SMK37_MIDI_INTERFACE = 4,
    SMK37_MIDI_ENDPOINT_OUT = 0x04,
};

static const char CONFIRM_TOKEN[] = "SEND-SMK37-V15-R03-STRESS-4E4F5445";

struct midi_event {
    const char *label;
    uint8_t status;
    uint8_t data1;
    uint8_t data2;
    unsigned delay_ms;
};

static const struct midi_event EVENTS[] = {
    {"phase 1: Ch1 chord C4 on", 0x90, 60, 88, 100},
    {"phase 1: Ch1 chord E4 on", 0x90, 64, 88, 100},
    {"phase 1: Ch1 chord G4 on", 0x90, 67, 88, 500},
    {"phase 1: Ch10 notes on 36", 0x99, 36, 102, 100},
    {"phase 1: Ch10 notes on 40", 0x99, 40, 102, 100},
    {"phase 1: Ch10 notes on 43", 0x99, 43, 102, 800},
    {"phase 1: Ch10 reverse off 43", 0x89, 43, 64, 100},
    {"phase 1: Ch10 reverse off 40", 0x89, 40, 64, 100},
    {"phase 1: Ch10 reverse off 36", 0x89, 36, 64, 500},
    {"phase 1: Ch1 reverse off G4", 0x80, 67, 64, 100},
    {"phase 1: Ch1 reverse off E4", 0x80, 64, 64, 100},
    {"phase 1: Ch1 reverse off C4", 0x80, 60, 64, 1500},

    {"phase 2: Ch10 repeated hit 1 on", 0x99, 36, 80, 120},
    {"phase 2: Ch10 repeated hit 1 off", 0x89, 36, 64, 80},
    {"phase 2: Ch10 repeated hit 2 on", 0x99, 36, 96, 120},
    {"phase 2: Ch10 repeated hit 2 off", 0x89, 36, 64, 80},
    {"phase 2: Ch10 repeated hit 3 on", 0x99, 36, 112, 120},
    {"phase 2: Ch10 repeated hit 3 off", 0x89, 36, 64, 1500},

    {"phase 3: Ch10 sustain on", 0xb9, 64, 127, 100},
    {"phase 3: Ch10 sustained note on", 0x99, 40, 100, 500},
    {"phase 3: Ch10 sustained note off", 0x89, 40, 64, 800},
    {"phase 3: Ch10 sustain off", 0xb9, 64, 0, 1500},

    {"phase 4: Ch1 note on before panic", 0x90, 60, 88, 100},
    {"phase 4: Ch10 note on before panic", 0x99, 43, 100, 500},
    {"phase 4: Ch10 all sound off CC120", 0xb9, 120, 0, 300},
    {"phase 4: Ch10 all notes off CC123", 0xb9, 123, 0, 300},
    {"phase 4: Ch1 all sound off CC120", 0xb0, 120, 0, 300},
    {"phase 4: Ch1 all notes off CC123", 0xb0, 123, 0, 500},
};

static void sleep_ms(unsigned milliseconds) {
    struct timespec duration = {
        .tv_sec = (time_t)(milliseconds / 1000),
        .tv_nsec = (long)(milliseconds % 1000) * 1000000L,
    };
    while (nanosleep(&duration, &duration) != 0) {
    }
}

static uint8_t cin_for_status(uint8_t status) {
    switch (status & 0xf0) {
    case 0x80:
        return 0x08;
    case 0x90:
        return 0x09;
    case 0xb0:
        return 0x0b;
    default:
        return 0;
    }
}

static void encode_event(const struct midi_event *event, uint8_t packet[4]) {
    packet[0] = cin_for_status(event->status); /* cable 0 */
    packet[1] = event->status;
    packet[2] = event->data1;
    packet[3] = event->data2;
}

static int validate_events(void) {
    size_t index;
    int ch1_active = 0;
    int ch10_active = 0;

    for (index = 0; index < sizeof(EVENTS) / sizeof(EVENTS[0]); ++index) {
        const struct midi_event *event = &EVENTS[index];
        uint8_t type = event->status & 0xf0;
        uint8_t channel = event->status & 0x0f;

        if (cin_for_status(event->status) == 0 || event->data1 > 127 ||
            event->data2 > 127) {
            fprintf(stderr, "invalid event at index %zu\n", index);
            return 1;
        }
        if (type == 0x90 && event->data2 != 0) {
            if (channel == 0) {
                ++ch1_active;
            } else if (channel == 9) {
                ++ch10_active;
            }
        } else if (type == 0x80 || (type == 0x90 && event->data2 == 0)) {
            if (channel == 0 && ch1_active > 0) {
                --ch1_active;
            } else if (channel == 9 && ch10_active > 0) {
                --ch10_active;
            }
        } else if (type == 0xb0 &&
                   (event->data1 == 120 || event->data1 == 123)) {
            if (channel == 0) {
                ch1_active = 0;
            } else if (channel == 9) {
                ch10_active = 0;
            }
        }
    }
    if (ch1_active != 0 || ch10_active != 0) {
        fprintf(stderr, "event sequence leaves active notes: Ch1=%d Ch10=%d\n",
                ch1_active, ch10_active);
        return 1;
    }
    return 0;
}

static int run_sequence(int send) {
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    size_t index;
    int status = 1;

    if (validate_events() != 0) {
        return 1;
    }
    if (send) {
        int result = libusb_init(&context);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
            return 1;
        }
        handle = libusb_open_device_with_vid_pid(context, SMK37_V15_VID,
                                                  SMK37_V15_PID);
        if (handle == NULL) {
            fputs("exact v15 device 4353:cf4d could not be opened\n", stderr);
            status = 2;
            goto cleanup;
        }
        result = libusb_claim_interface(handle, SMK37_MIDI_INTERFACE);
        if (result != LIBUSB_SUCCESS) {
            fprintf(stderr, "claim interface %d: %s\n", SMK37_MIDI_INTERFACE,
                    libusb_error_name(result));
            status = 3;
            goto cleanup;
        }
    }

    printf("R03 MIDI stress sequence: %zu events\n",
           sizeof(EVENTS) / sizeof(EVENTS[0]));
    for (index = 0; index < sizeof(EVENTS) / sizeof(EVENTS[0]); ++index) {
        const struct midi_event *event = &EVENTS[index];
        uint8_t packet[4];
        encode_event(event, packet);
        printf("%02zu %-42s USB %02x %02x %02x %02x delay=%ums\n", index + 1,
               event->label, packet[0], packet[1], packet[2], packet[3],
               event->delay_ms);
        fflush(stdout);
        if (send) {
            int transferred = 0;
            int result = libusb_bulk_transfer(handle, SMK37_MIDI_ENDPOINT_OUT,
                                              packet, sizeof(packet),
                                              &transferred, 2000);
            if (result != LIBUSB_SUCCESS || transferred != (int)sizeof(packet)) {
                fprintf(stderr, "bulk OUT 0x04 at event %zu: %s, %d/4\n",
                        index + 1, libusb_error_name(result), transferred);
                status = 4;
                goto release;
            }
            sleep_ms(event->delay_ms);
        }
    }
    status = 0;
    puts(send ? "R03 MIDI stress sequence sent" :
                "R03 MIDI stress dry-run PASS");

release:
    if (send && handle != NULL) {
        libusb_release_interface(handle, SMK37_MIDI_INTERFACE);
    }
cleanup:
    if (handle != NULL) {
        libusb_close(handle);
    }
    if (context != NULL) {
        libusb_exit(context);
    }
    return status;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s dry-run\n"
            "  %s send --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "dry-run") == 0) {
        return run_sequence(0);
    }
    if (argc == 4 && strcmp(argv[1], "send") == 0 &&
        strcmp(argv[2], "--confirm") == 0 &&
        strcmp(argv[3], CONFIRM_TOKEN) == 0) {
        return run_sequence(1);
    }
    usage(argv[0]);
    return 2;
}
