#include <libusb.h>

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * Official-v15-only, endpoint-only USB MIDI runtime observer.
 *
 * Safety invariants:
 * - Opens only VID:PID 4353:cf4d.
 * - Claims only interface 4.
 * - Sends only fixed USB-MIDI event packets to bulk OUT endpoint 0x04.
 * - Reads only bulk IN endpoint 0x84.
 * - Has no arbitrary-hex mode, control-command mode, OTA code, flash code,
 *   reset call, configuration change, or kernel-driver detach call.
 * - Rejects the known upgrade SysEx prefix F0 22 24 even if a future fixed
 *   case accidentally contains it.
 * - Refuses non-4-byte-aligned writes and caps all execution at 80 events.
 */

enum {
    V15_VID = 0x4353,
    V15_PID = 0xcf4d,
    MIDI_INTERFACE = 4,
    MIDI_EP_OUT = 0x04,
    MIDI_EP_IN = 0x84,
    MAX_OUT_EVENTS = 80,
    DEFAULT_SETTLE_MS = 260,
};

typedef struct {
    libusb_context *context;
    libusb_device_handle *handle;
    FILE *log;
    unsigned out_events;
    bool claimed;
    bool device_lost;
} observer;

typedef struct {
    const char *name;
    const char *group;
    const char *purpose;
    const uint8_t *bytes;
    size_t length;
    unsigned settle_ms;
} probe_case;

static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0;
    }
    return (uint64_t)now.tv_sec * 1000u + (uint64_t)now.tv_nsec / 1000000u;
}

static void sleep_ms(unsigned milliseconds) {
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000u),
        .tv_nsec = (long)(milliseconds % 1000u) * 1000000L,
    };
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {
    }
}

static void utc_now(char output[32]) {
    time_t now = time(NULL);
    struct tm value;
    gmtime_r(&now, &value);
    strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &value);
}

static void log_event(observer *state, const char *event, const char *format, ...) {
    char timestamp[32];
    va_list arguments;

    utc_now(timestamp);
    fprintf(state->log, "%s\t%llu\t%s", timestamp,
            (unsigned long long)monotonic_ms(), event);
    if (format != NULL && *format != '\0') {
        fputc('\t', state->log);
        va_start(arguments, format);
        vfprintf(state->log, format, arguments);
        va_end(arguments);
    }
    fputc('\n', state->log);
    fflush(state->log);
}

static void print_hex(FILE *stream, const uint8_t *bytes, size_t length) {
    for (size_t index = 0; index < length; ++index) {
        fprintf(stream, "%s%02x", index == 0 ? "" : " ", bytes[index]);
    }
}

static int get_ascii_string(libusb_device_handle *handle, uint8_t index,
                            char *output, size_t output_size) {
    int result;
    if (index == 0 || output_size == 0) {
        if (output_size != 0) {
            output[0] = '\0';
        }
        return 0;
    }
    result = libusb_get_string_descriptor_ascii(
        handle, index, (unsigned char *)output, (int)(output_size - 1));
    if (result < 0) {
        output[0] = '\0';
        return result;
    }
    output[result] = '\0';
    return result;
}

static bool exact_endpoint_layout(libusb_device *device, FILE *diagnostic) {
    struct libusb_config_descriptor *config = NULL;
    bool found_out = false;
    bool found_in = false;
    bool interface_found = false;
    int result = libusb_get_active_config_descriptor(device, &config);

    if (result != LIBUSB_SUCCESS) {
        fprintf(diagnostic, "active descriptor: %s\n", libusb_error_name(result));
        return false;
    }
    for (int interface_index = 0; interface_index < config->bNumInterfaces;
         ++interface_index) {
        const struct libusb_interface *interface = &config->interface[interface_index];
        for (int alt_index = 0; alt_index < interface->num_altsetting; ++alt_index) {
            const struct libusb_interface_descriptor *alt = &interface->altsetting[alt_index];
            if (alt->bInterfaceNumber != MIDI_INTERFACE ||
                alt->bAlternateSetting != 0 || alt->bInterfaceClass != 0x01 ||
                alt->bInterfaceSubClass != 0x03) {
                continue;
            }
            interface_found = true;
            for (int endpoint_index = 0; endpoint_index < alt->bNumEndpoints;
                 ++endpoint_index) {
                const struct libusb_endpoint_descriptor *endpoint =
                    &alt->endpoint[endpoint_index];
                bool bulk = (endpoint->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) ==
                            LIBUSB_TRANSFER_TYPE_BULK;
                if (endpoint->bEndpointAddress == MIDI_EP_OUT && bulk &&
                    endpoint->wMaxPacketSize == 64) {
                    found_out = true;
                }
                if (endpoint->bEndpointAddress == MIDI_EP_IN && bulk &&
                    endpoint->wMaxPacketSize == 64) {
                    found_in = true;
                }
            }
        }
    }
    libusb_free_config_descriptor(config);
    if (!interface_found || !found_out || !found_in) {
        fprintf(diagnostic,
                "refusing unexpected layout: interface4-midi=%d ep04=%d ep84=%d\n",
                interface_found, found_out, found_in);
        return false;
    }
    return true;
}

static int open_exact_v15(observer *state, const char *expected_serial) {
    libusb_device **devices = NULL;
    libusb_device *match = NULL;
    struct libusb_device_descriptor descriptor;
    ssize_t count;
    unsigned matches = 0;
    int result = libusb_init(&state->context);

    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }
    count = libusb_get_device_list(state->context, &devices);
    if (count < 0) {
        fprintf(stderr, "libusb_get_device_list: %s\n", libusb_error_name((int)count));
        return 1;
    }
    for (ssize_t index = 0; index < count; ++index) {
        struct libusb_device_descriptor candidate;
        if (libusb_get_device_descriptor(devices[index], &candidate) == LIBUSB_SUCCESS &&
            candidate.idVendor == V15_VID && candidate.idProduct == V15_PID) {
            match = devices[index];
            matches++;
        }
    }
    if (matches != 1 || match == NULL) {
        fprintf(stderr, "refusing: expected exactly one official-v15 %04x:%04x, found %u\n",
                V15_VID, V15_PID, matches);
        libusb_free_device_list(devices, 1);
        return 3;
    }
    result = libusb_get_device_descriptor(match, &descriptor);
    if (result != LIBUSB_SUCCESS || !exact_endpoint_layout(match, stderr)) {
        libusb_free_device_list(devices, 1);
        return 4;
    }
    result = libusb_open(match, &state->handle);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_open: %s\n", libusb_error_name(result));
        libusb_free_device_list(devices, 1);
        return 4;
    }
    {
        char manufacturer[256] = "";
        char product[256] = "";
        char serial[256] = "";
        get_ascii_string(state->handle, descriptor.iManufacturer,
                         manufacturer, sizeof(manufacturer));
        get_ascii_string(state->handle, descriptor.iProduct, product, sizeof(product));
        get_ascii_string(state->handle, descriptor.iSerialNumber, serial, sizeof(serial));
        if (expected_serial != NULL && strcmp(serial, expected_serial) != 0) {
            fprintf(stderr, "refusing serial mismatch: expected '%s', found '%s'\n",
                    expected_serial, serial);
            libusb_free_device_list(devices, 1);
            return 4;
        }
        log_event(state, "DEVICE",
                  "vid=%04x pid=%04x bus=%u address=%u manufacturer=%s product=%s serial=%s",
                  descriptor.idVendor, descriptor.idProduct,
                  libusb_get_bus_number(match), libusb_get_device_address(match),
                  manufacturer, product, serial);
    }
    libusb_free_device_list(devices, 1);
    return 0;
}

static bool has_upgrade_prefix(const uint8_t *bytes, size_t length) {
    uint8_t stream[256];
    size_t stream_length = 0;

    for (size_t offset = 0; offset + 3 < length; offset += 4) {
        unsigned cin = bytes[offset] & 0x0f;
        static const uint8_t payload_length[16] = {
            0, 0, 2, 3, 3, 1, 2, 3, 3, 3, 3, 3, 2, 2, 3, 1,
        };
        for (unsigned index = 0; index < payload_length[cin]; ++index) {
            if (stream_length < sizeof(stream)) {
                stream[stream_length++] = bytes[offset + 1 + index];
            }
        }
    }
    for (size_t index = 0; index + 2 < stream_length; ++index) {
        if (stream[index] == 0xf0 && stream[index + 1] == 0x22 &&
            stream[index + 2] == 0x24) {
            return true;
        }
    }
    return false;
}

static int read_for(observer *state, unsigned milliseconds, const char *phase) {
    uint64_t deadline = monotonic_ms() + milliseconds;
    while (monotonic_ms() < deadline) {
        uint8_t buffer[64];
        int transferred = 0;
        unsigned remaining = (unsigned)(deadline - monotonic_ms());
        unsigned timeout = remaining < 25 ? remaining : 25;
        int result;
        if (timeout == 0) {
            break;
        }
        result = libusb_bulk_transfer(state->handle, MIDI_EP_IN, buffer,
                                      sizeof(buffer), &transferred, timeout);
        if (result == LIBUSB_ERROR_TIMEOUT) {
            continue;
        }
        if (result == LIBUSB_ERROR_NO_DEVICE) {
            state->device_lost = true;
            log_event(state, "DISCONNECT", "phase=%s error=%s", phase,
                      libusb_error_name(result));
            return 5;
        }
        if (result != LIBUSB_SUCCESS) {
            log_event(state, "IN_ERROR", "phase=%s error=%s", phase,
                      libusb_error_name(result));
            return 5;
        }
        {
            char timestamp[32];
            utc_now(timestamp);
            fprintf(state->log, "%s\t%llu\tIN\tphase=%s length=%d bytes=",
                    timestamp, (unsigned long long)monotonic_ms(), phase, transferred);
            print_hex(state->log, buffer, (size_t)transferred);
            fputc('\n', state->log);
            fflush(state->log);
        }
    }
    return 0;
}

static int send_fixed(observer *state, const probe_case *test) {
    int transferred = 0;
    int result;
    size_t events;

    if (test->length == 0 || test->length > 64 || test->length % 4 != 0) {
        log_event(state, "SAFETY_REFUSAL", "case=%s reason=unaligned_length length=%zu",
                  test->name, test->length);
        return 6;
    }
    events = test->length / 4;
    if (state->out_events + events > MAX_OUT_EVENTS) {
        log_event(state, "SAFETY_REFUSAL", "case=%s reason=event_cap current=%u add=%zu",
                  test->name, state->out_events, events);
        return 6;
    }
    if (has_upgrade_prefix(test->bytes, test->length)) {
        log_event(state, "SAFETY_REFUSAL", "case=%s reason=upgrade_prefix_f0_22_24",
                  test->name);
        return 6;
    }

    {
        char timestamp[32];
        utc_now(timestamp);
        fprintf(state->log,
                "%s\t%llu\tOUT_ATTEMPT\tcase=%s group=%s purpose=%s length=%zu bytes=",
                timestamp, (unsigned long long)monotonic_ms(), test->name,
                test->group, test->purpose, test->length);
        print_hex(state->log, test->bytes, test->length);
        fputc('\n', state->log);
        fflush(state->log);
    }
    result = libusb_bulk_transfer(state->handle, MIDI_EP_OUT,
                                  (unsigned char *)test->bytes, (int)test->length,
                                  &transferred, 1000);
    if (result == LIBUSB_ERROR_NO_DEVICE) {
        state->device_lost = true;
    }
    log_event(state, "OUT_RESULT", "case=%s result=%s transferred=%d/%zu",
              test->name, libusb_error_name(result), transferred, test->length);
    if (result != LIBUSB_SUCCESS || transferred != (int)test->length) {
        return 5;
    }
    state->out_events += (unsigned)events;
    return read_for(state,
                    test->settle_ms == 0 ? DEFAULT_SETTLE_MS : test->settle_ms,
                    test->name);
}

#define PACKET(name, a, b, c, d) static const uint8_t name[] = {a, b, c, d}

PACKET(cable0_on,  0x09, 0x90, 0x3c, 0x18);
PACKET(cable0_off, 0x08, 0x80, 0x3c, 0x40);
PACKET(cable1_on,  0x19, 0x90, 0x3c, 0x18);
PACKET(cable1_off, 0x18, 0x80, 0x3c, 0x40);
PACKET(cable2_on,  0x29, 0x90, 0x3c, 0x18);
PACKET(cable2_off, 0x28, 0x80, 0x3c, 0x40);
PACKET(cable3_on,  0x39, 0x90, 0x3c, 0x18);
PACKET(cable3_off, 0x38, 0x80, 0x3c, 0x40);
PACKET(ch1_on,    0x09, 0x90, 0x3c, 0x18);
PACKET(ch1_off,   0x08, 0x80, 0x3c, 0x40);
PACKET(ch10_on,   0x09, 0x99, 0x24, 0x18);
PACKET(ch10_off,  0x08, 0x89, 0x24, 0x40);
PACKET(ch16_on,   0x09, 0x9f, 0x43, 0x18);
PACKET(ch16_off,  0x08, 0x8f, 0x43, 0x40);
PACKET(cin2,      0x02, 0xf3, 0x00, 0x00);
PACKET(cin3,      0x03, 0xf2, 0x00, 0x00);
PACKET(cin8,      0x08, 0x80, 0x3c, 0x40);
PACKET(cin9,      0x09, 0x90, 0x3c, 0x00);
PACKET(cina,      0x0a, 0xa0, 0x3c, 0x00);
PACKET(cinb,      0x0b, 0xb0, 0x01, 0x00);
PACKET(cinc,      0x0c, 0xc0, 0x00, 0x00);
PACKET(cind,      0x0d, 0xd0, 0x00, 0x00);
PACKET(cine,      0x0e, 0xe0, 0x00, 0x40);
PACKET(cinf,      0x0f, 0xf8, 0x00, 0x00);
PACKET(pc0_ch1,   0x0c, 0xc0, 0x00, 0x00);
PACKET(pc1_ch1,   0x0c, 0xc0, 0x01, 0x00);
PACKET(pc0_ch10,  0x0c, 0xc9, 0x00, 0x00);
PACKET(cc1_zero,  0x0b, 0xb0, 0x01, 0x00);
PACKET(cc1_mid,   0x0b, 0xb0, 0x01, 0x40);
PACKET(cc64_off,  0x0b, 0xb0, 0x40, 0x00);
PACKET(cc123,     0x0b, 0xb0, 0x7b, 0x00);
PACKET(bend_min,  0x0e, 0xe0, 0x00, 0x00);
PACKET(bend_ctr,  0x0e, 0xe0, 0x00, 0x40);
PACKET(bend_max,  0x0e, 0xe0, 0x7f, 0x7f);
PACKET(sysex2,    0x06, 0xf0, 0xf7, 0x00);
PACKET(sysex3,    0x07, 0xf0, 0x7f, 0xf7);
static const uint8_t sysex4[] = {0x04, 0xf0, 0x7d, 0x00,
                                 0x05, 0xf7, 0x00, 0x00};
static const uint8_t identity_request[] = {0x04, 0xf0, 0x7e, 0x7f,
                                           0x07, 0x06, 0x01, 0xf7};
PACKET(bad_cin0,      0x00, 0x00, 0x00, 0x00);
PACKET(bad_cin1,      0x01, 0x00, 0x00, 0x00);
PACKET(bad_9_status8, 0x09, 0x80, 0x3c, 0x00);
PACKET(bad_8_status9, 0x08, 0x90, 0x3c, 0x00);
PACKET(bad_pc_pad,    0x0c, 0xc0, 0x00, 0x7f);
PACKET(bad_end_only,  0x05, 0xf7, 0x00, 0x00);
PACKET(bad_data,      0x09, 0x00, 0x00, 0x00);

static const probe_case cases[] = {
    {"cable0-note-on", "cables", "short low-velocity note", cable0_on, sizeof(cable0_on), 180},
    {"cable0-note-off", "cables", "paired cleanup", cable0_off, sizeof(cable0_off), 220},
    {"cable1-note-on", "cables", "short low-velocity note", cable1_on, sizeof(cable1_on), 180},
    {"cable1-note-off", "cables", "paired cleanup", cable1_off, sizeof(cable1_off), 220},
    {"cable2-note-on", "cables", "short low-velocity note", cable2_on, sizeof(cable2_on), 180},
    {"cable2-note-off", "cables", "paired cleanup", cable2_off, sizeof(cable2_off), 220},
    {"cable3-note-on", "cables", "one-above-described-jack-count boundary", cable3_on, sizeof(cable3_on), 180},
    {"cable3-note-off", "cables", "paired cleanup", cable3_off, sizeof(cable3_off), 220},

    {"channel1-note-on", "channels", "channel 1 dispatch", ch1_on, sizeof(ch1_on), 180},
    {"channel1-note-off", "channels", "paired cleanup", ch1_off, sizeof(ch1_off), 220},
    {"channel10-note-on", "channels", "channel 10 dispatch", ch10_on, sizeof(ch10_on), 180},
    {"channel10-note-off", "channels", "paired cleanup", ch10_off, sizeof(ch10_off), 220},
    {"channel16-note-on", "channels", "channel 16 boundary", ch16_on, sizeof(ch16_on), 180},
    {"channel16-note-off", "channels", "paired cleanup", ch16_off, sizeof(ch16_off), 220},

    {"cin2-song-select", "cin", "defined two-byte system-common CIN", cin2, sizeof(cin2), 220},
    {"cin3-song-position", "cin", "defined three-byte system-common CIN", cin3, sizeof(cin3), 220},
    {"cin8-note-off", "cin", "channel voice CIN 8", cin8, sizeof(cin8), 220},
    {"cin9-note-on-zero", "cin", "channel voice CIN 9 with note-off semantics", cin9, sizeof(cin9), 220},
    {"cina-poly-pressure-zero", "cin", "channel voice CIN A", cina, sizeof(cina), 220},
    {"cinb-cc-zero", "cin", "channel voice CIN B", cinb, sizeof(cinb), 220},
    {"cinc-program-zero", "cin", "channel voice CIN C", cinc, sizeof(cinc), 220},
    {"cind-pressure-zero", "cin", "channel voice CIN D", cind, sizeof(cind), 220},
    {"cine-bend-center", "cin", "channel voice CIN E", cine, sizeof(cine), 220},
    {"cinf-clock", "cin", "single-byte realtime CIN F", cinf, sizeof(cinf), 220},

    {"program-ch1-0", "program", "Program Change lower boundary", pc0_ch1, sizeof(pc0_ch1), 300},
    {"program-ch1-1", "program", "Program Change adjacent value", pc1_ch1, sizeof(pc1_ch1), 300},
    {"program-ch1-restore0", "program", "best-effort restore to program 0", pc0_ch1, sizeof(pc0_ch1), 300},
    {"program-ch10-0", "program", "Program Change channel routing", pc0_ch10, sizeof(pc0_ch10), 300},

    {"cc1-zero", "cc", "modulation lower boundary", cc1_zero, sizeof(cc1_zero), 220},
    {"cc1-mid", "cc", "modulation nonzero value", cc1_mid, sizeof(cc1_mid), 220},
    {"cc1-restore", "cc", "restore modulation to zero", cc1_zero, sizeof(cc1_zero), 220},
    {"cc64-off", "cc", "sustain explicitly off", cc64_off, sizeof(cc64_off), 220},
    {"cc123-all-notes-off", "cc", "bounded cleanup/control dispatch", cc123, sizeof(cc123), 220},

    {"bend-min", "pitch", "pitch-bend lower boundary", bend_min, sizeof(bend_min), 220},
    {"bend-center-a", "pitch", "pitch-bend center", bend_ctr, sizeof(bend_ctr), 220},
    {"bend-max", "pitch", "pitch-bend upper boundary", bend_max, sizeof(bend_max), 220},
    {"bend-center-b", "pitch", "restore pitch-bend center", bend_ctr, sizeof(bend_ctr), 220},

    {"sysex-cin6-two-byte", "sysex", "complete empty SysEx boundary", sysex2, sizeof(sysex2), 350},
    {"sysex-cin7-three-byte", "sysex", "complete three-byte SysEx boundary", sysex3, sizeof(sysex3), 350},
    {"sysex-cin4-cin5-four-byte", "sysex", "two-event SysEx ending with CIN 5", sysex4, sizeof(sysex4), 400},
    {"universal-identity-request", "sysex", "standard non-realtime identity request", identity_request, sizeof(identity_request), 800},

    {"malformed-reserved-cin0", "malformed", "reserved CIN with zero payload", bad_cin0, sizeof(bad_cin0), 300},
    {"malformed-reserved-cin1", "malformed", "reserved CIN with zero payload", bad_cin1, sizeof(bad_cin1), 300},
    {"malformed-cin9-status8", "malformed", "CIN/status mismatch with note-off status", bad_9_status8, sizeof(bad_9_status8), 300},
    {"malformed-cin8-status9-zero", "malformed", "CIN/status mismatch with note-on velocity zero", bad_8_status9, sizeof(bad_8_status9), 300},
    {"malformed-program-padding", "malformed", "nonzero ignored padding byte", bad_pc_pad, sizeof(bad_pc_pad), 300},
    {"malformed-sysex-end-only", "malformed", "SysEx terminator without start", bad_end_only, sizeof(bad_end_only), 350},
    {"malformed-data-status", "malformed", "channel CIN with data byte in status slot", bad_data, sizeof(bad_data), 300},
};

static bool group_selected(const char *selection, const char *group) {
    return strcmp(selection, "all") == 0 || strcmp(selection, group) == 0;
}

static void print_matrix(FILE *stream, const char *selection) {
    unsigned events = 0;
    fprintf(stream, "fixed official-v15 USB MIDI matrix (selection=%s)\n", selection);
    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const probe_case *test = &cases[index];
        if (!group_selected(selection, test->group)) {
            continue;
        }
        fprintf(stream, "%-34s group=%-9s bytes=", test->name, test->group);
        print_hex(stream, test->bytes, test->length);
        fprintf(stream, "  # %s\n", test->purpose);
        events += (unsigned)(test->length / 4);
    }
    fprintf(stream, "outbound events=%u cap=%u\n", events, MAX_OUT_EVENTS);
}

static bool valid_selection(const char *selection) {
    static const char *groups[] = {
        "all", "cables", "channels", "cin", "program", "cc", "pitch",
        "sysex", "malformed",
    };
    for (size_t index = 0; index < sizeof(groups) / sizeof(groups[0]); ++index) {
        if (strcmp(selection, groups[index]) == 0) {
            return true;
        }
    }
    return false;
}

static void cleanup_notes(observer *state) {
    static const uint8_t cleanup[][4] = {
        {0x08, 0x80, 0x3c, 0x40}, {0x18, 0x80, 0x3c, 0x40},
        {0x28, 0x80, 0x3c, 0x40}, {0x38, 0x80, 0x3c, 0x40},
        {0x08, 0x89, 0x24, 0x40}, {0x08, 0x8f, 0x43, 0x40},
        {0x0b, 0xb0, 0x7b, 0x00}, {0x0b, 0xb9, 0x7b, 0x00},
        {0x0b, 0xbf, 0x7b, 0x00}, {0x0e, 0xe0, 0x00, 0x40},
    };
    if (state->device_lost || state->handle == NULL) {
        return;
    }
    log_event(state, "CLEANUP_BEGIN", "events=%zu",
              sizeof(cleanup) / sizeof(cleanup[0]));
    for (size_t index = 0; index < sizeof(cleanup) / sizeof(cleanup[0]); ++index) {
        int transferred = 0;
        int result;
        if (state->out_events >= MAX_OUT_EVENTS) {
            break;
        }
        result = libusb_bulk_transfer(state->handle, MIDI_EP_OUT,
                                      (unsigned char *)cleanup[index], 4,
                                      &transferred, 500);
        state->out_events++;
        log_event(state, "CLEANUP", "index=%zu result=%s transferred=%d bytes=%02x %02x %02x %02x",
                  index, libusb_error_name(result), transferred,
                  cleanup[index][0], cleanup[index][1], cleanup[index][2], cleanup[index][3]);
        if (result == LIBUSB_ERROR_NO_DEVICE) {
            state->device_lost = true;
            break;
        }
        sleep_ms(40);
    }
    read_for(state, 200, "cleanup");
}

static int execute_matrix(observer *state, const char *selection) {
    int result;
    log_event(state, "SAFETY",
              "v15_only=1 interface=4 out=0x04 in=0x84 no_control_commands=1 no_ota=1 no_flash=1 no_reset=1 max_events=%u",
              MAX_OUT_EVENTS);
    result = libusb_claim_interface(state->handle, MIDI_INTERFACE);
    if (result != LIBUSB_SUCCESS) {
        log_event(state, "CLAIM_ERROR", "interface=%d error=%s", MIDI_INTERFACE,
                  libusb_error_name(result));
        return 4;
    }
    state->claimed = true;
    log_event(state, "CLAIM", "interface=%d result=ok", MIDI_INTERFACE);
    log_event(state, "BASELINE_BEGIN", "read_ms=600");
    result = read_for(state, 600, "baseline");
    log_event(state, "BASELINE_END", "result=%d", result);
    if (result != 0) {
        return result;
    }

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const probe_case *test = &cases[index];
        if (!group_selected(selection, test->group)) {
            continue;
        }
        log_event(state, "OBSERVATION_WINDOW",
                  "case=%s inspect_audio_display_usb_disconnect_and_state_now", test->name);
        result = send_fixed(state, test);
        if (result != 0) {
            log_event(state, "STOP", "case=%s result=%d device_lost=%d",
                      test->name, result, state->device_lost);
            return result;
        }
        sleep_ms(120);
    }
    log_event(state, "RUN_COMPLETE", "selection=%s out_events=%u device_lost=%d",
              selection, state->out_events, state->device_lost);
    return 0;
}

static void close_observer(observer *state, bool send_cleanup) {
    if (send_cleanup && state->claimed) {
        cleanup_notes(state);
    }
    if (state->claimed && state->handle != NULL) {
        int result = libusb_release_interface(state->handle, MIDI_INTERFACE);
        log_event(state, "RELEASE", "interface=%d result=%s", MIDI_INTERFACE,
                  libusb_error_name(result));
    }
    if (state->handle != NULL) {
        libusb_close(state->handle);
    }
    if (state->context != NULL) {
        libusb_exit(state->context);
    }
}

static void usage(FILE *stream, const char *program) {
    fprintf(stream,
            "Usage:\n"
            "  %s --dry-run [group]\n"
            "  %s --enumerate [--expect-serial SERIAL] [--log FILE]\n"
            "  %s --execute [group] [--expect-serial SERIAL] [--log FILE]\n"
            "\n"
            "Groups: all, cables, channels, cin, program, cc, pitch, sysex, malformed\n"
            "Default group: all. --execute is required for any OUT transfer.\n",
            program, program, program);
}

int main(int argc, char **argv) {
    observer state = {0};
    const char *mode;
    const char *selection = "all";
    const char *expected_serial = NULL;
    const char *log_path = NULL;
    bool execute = false;
    bool enumerate_only = false;
    int result;

    if (argc < 2) {
        usage(stderr, argv[0]);
        return 2;
    }
    mode = argv[1];
    if (strcmp(mode, "--dry-run") == 0) {
        if (argc >= 3) {
            selection = argv[2];
        }
        if (!valid_selection(selection)) {
            usage(stderr, argv[0]);
            return 2;
        }
        print_matrix(stdout, selection);
        return 0;
    }
    if (strcmp(mode, "--execute") == 0) {
        execute = true;
    } else if (strcmp(mode, "--enumerate") == 0) {
        enumerate_only = true;
    } else {
        usage(stderr, argv[0]);
        return 2;
    }

    for (int index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--expect-serial") == 0 && index + 1 < argc) {
            expected_serial = argv[++index];
        } else if (strcmp(argv[index], "--log") == 0 && index + 1 < argc) {
            log_path = argv[++index];
        } else if (execute && valid_selection(argv[index])) {
            selection = argv[index];
        } else {
            usage(stderr, argv[0]);
            return 2;
        }
    }
    if (log_path != NULL) {
        state.log = fopen(log_path, "a");
        if (state.log == NULL) {
            fprintf(stderr, "open log '%s': %s\n", log_path, strerror(errno));
            return 2;
        }
    } else {
        state.log = stdout;
    }

    result = open_exact_v15(&state, expected_serial);
    if (result == 0 && enumerate_only) {
        log_event(&state, "ENUMERATE_COMPLETE", "no_interface_claim=1 no_transfer=1");
    } else if (result == 0 && execute) {
        result = execute_matrix(&state, selection);
    }
    close_observer(&state, execute && result != 3 && result != 4);
    if (state.log != stdout) {
        fclose(state.log);
    }
    return result;
}
