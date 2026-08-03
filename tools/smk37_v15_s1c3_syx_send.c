/* Send an editor-compatible 16-pad DX7 SysEx set to S1-C3 firmware.
 *
 * Directory contract: exactly one pad01-*.syx through pad16-*.syx file.
 * Each file must be a 163-byte Yamaha DX7 single-voice dump with a valid
 * Yamaha checksum. Before USB transmission, byte 161 is changed to the SMK
 * runtime flag 0x3f. Files are transmitted in MIDI note order 36..51.
 */
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef S1C3_ENABLE_LIVE_USB
#include <libusb.h>
#endif

#define PAD_COUNT 16u
#define SYSEX_SIZE 163u
#define USB_MIDI_SIZE 220u
#define PATH_SIZE 4096u
#define CHECKSUM_OFFSET 161u
#define SMK_RUNTIME_FLAG 0x3fu
#define INTER_PACKET_DELAY_NS 100000000L

static const uint8_t HEADER[6] = {0xf0, 0x43, 0x00, 0x00, 0x01, 0x1b};
static const unsigned PAD_TO_NOTE[PAD_COUNT] = {40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47};
static const char CONFIRM_TOKEN[] = "SEND-SMK37PRO-V15-S1C3-EDITOR-SYX-SET";

struct patch {
    unsigned pad;
    unsigned note;
    char path[PATH_SIZE];
    char name[11];
    uint8_t editor[SYSEX_SIZE];
    uint8_t runtime[SYSEX_SIZE];
    uint8_t events[USB_MIDI_SIZE];
};

static unsigned note_to_pad(unsigned note) {
    unsigned pad;
    for (pad = 0; pad < PAD_COUNT; ++pad) {
        if (PAD_TO_NOTE[pad] == note) return pad + 1u;
    }
    return 0;
}

static int starts_with_pad(const char *name, unsigned pad) {
    char prefix[16];
    int written = snprintf(prefix, sizeof(prefix), "pad%02u-", pad);
    size_t name_length = strlen(name);
    if (written <= 0 || (size_t)written >= sizeof(prefix)) return 0;
    return strncmp(name, prefix, (size_t)written) == 0 && name_length >= 4u &&
           strcmp(name + name_length - 4u, ".syx") == 0;
}

static int find_pad_file(const char *directory, unsigned pad, char path[PATH_SIZE]) {
    DIR *dir = opendir(directory);
    struct dirent *entry;
    unsigned matches = 0;
    if (dir == NULL) {
        perror(directory);
        return 1;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (starts_with_pad(entry->d_name, pad)) {
            int written = snprintf(path, PATH_SIZE, "%s/%s", directory, entry->d_name);
            if (written < 0 || (size_t)written >= PATH_SIZE) {
                fprintf(stderr, "Pad %u path is too long\n", pad);
                closedir(dir);
                return 1;
            }
            ++matches;
        }
    }
    closedir(dir);
    if (matches != 1u) {
        fprintf(stderr, "%s: expected exactly one pad%02u-*.syx, found %u\n", directory, pad, matches);
        return 1;
    }
    return 0;
}

static int read_exact(const char *path, uint8_t data[SYSEX_SIZE]) {
    FILE *file = fopen(path, "rb");
    int extra;
    if (file == NULL) {
        perror(path);
        return 1;
    }
    if (fread(data, 1, SYSEX_SIZE, file) != SYSEX_SIZE) {
        fprintf(stderr, "%s: expected exactly %u bytes\n", path, (unsigned)SYSEX_SIZE);
        fclose(file);
        return 1;
    }
    extra = fgetc(file);
    fclose(file);
    if (extra != EOF) {
        fprintf(stderr, "%s: trailing bytes after %u-byte SysEx\n", path, (unsigned)SYSEX_SIZE);
        return 1;
    }
    return 0;
}

static uint8_t yamaha_checksum(const uint8_t data[SYSEX_SIZE]) {
    unsigned sum = 0;
    unsigned index;
    for (index = 6; index < CHECKSUM_OFFSET; ++index) sum += data[index];
    return (uint8_t)((0u - sum) & 0x7fu);
}

static int validate_editor_syx(struct patch *patch) {
    unsigned index;
    uint8_t expected;
    if (read_exact(patch->path, patch->editor) != 0) return 1;
    if (patch->editor[0] != HEADER[0] || patch->editor[1] != HEADER[1] ||
        (patch->editor[2] & 0xf0u) != 0 || memcmp(patch->editor + 3, HEADER + 3, 3) != 0 ||
        patch->editor[SYSEX_SIZE - 1] != 0xf7) {
        fprintf(stderr, "%s: not a Yamaha DX7 single-voice SysEx\n", patch->path);
        return 1;
    }
    for (index = 1; index + 1 < SYSEX_SIZE; ++index) {
        if (patch->editor[index] > 0x7f) {
            fprintf(stderr, "%s: non-7-bit SysEx byte at %u\n", patch->path, index);
            return 1;
        }
    }
    expected = yamaha_checksum(patch->editor);
    if (patch->editor[CHECKSUM_OFFSET] != expected) {
        fprintf(stderr, "%s: checksum 0x%02x, expected 0x%02x\n",
                patch->path, patch->editor[CHECKSUM_OFFSET], expected);
        return 1;
    }
    memcpy(patch->runtime, patch->editor, SYSEX_SIZE);
    patch->runtime[CHECKSUM_OFFSET] = SMK_RUNTIME_FLAG;
    memcpy(patch->name, patch->editor + 151, 10);
    patch->name[10] = '\0';
    return 0;
}

static size_t packetize(const uint8_t sysex[SYSEX_SIZE], uint8_t events[USB_MIDI_SIZE]) {
    size_t input = 0;
    size_t output = 0;
    while (input < SYSEX_SIZE) {
        size_t remaining = SYSEX_SIZE - input;
        size_t count = remaining > 3u ? 3u : remaining;
        uint8_t cin = remaining > 3u ? 0x04u : (remaining == 1u ? 0x05u : (remaining == 2u ? 0x06u : 0x07u));
        if (output + 4u > USB_MIDI_SIZE) return 0;
        events[output] = cin;
        events[output + 1] = sysex[input];
        events[output + 2] = count > 1u ? sysex[input + 1] : 0;
        events[output + 3] = count > 2u ? sysex[input + 2] : 0;
        input += count;
        output += 4u;
    }
    return output;
}

static int load_set(const char *directory, struct patch patches[PAD_COUNT]) {
    unsigned pad;
    for (pad = 1; pad <= PAD_COUNT; ++pad) {
        struct patch *patch = &patches[pad - 1u];
        memset(patch, 0, sizeof(*patch));
        patch->pad = pad;
        patch->note = PAD_TO_NOTE[pad - 1u];
        if (find_pad_file(directory, pad, patch->path) != 0) return 1;
        if (validate_editor_syx(patch) != 0) return 1;
        if (packetize(patch->runtime, patch->events) != USB_MIDI_SIZE ||
            patch->events[USB_MIDI_SIZE - 4] != 0x05 || patch->events[USB_MIDI_SIZE - 3] != 0xf7) {
            fprintf(stderr, "%s: USB-MIDI packetization failed\n", patch->path);
            return 1;
        }
    }
    return 0;
}

static void print_order(const struct patch patches[PAD_COUNT]) {
    unsigned note;
    for (note = 36; note <= 51; ++note) {
        unsigned pad = note_to_pad(note);
        const struct patch *patch = &patches[pad - 1u];
        printf("order %u slot %u note %u <- Pad %02u: %-10s %s\n",
               note - 35u, note - 36u, note, pad, patch->name, patch->path);
    }
}

#ifdef S1C3_ENABLE_LIVE_USB
static int send_set(const struct patch patches[PAD_COUNT]) {
    const uint16_t vid = 0x4353;
    const uint16_t pid = 0xcf4d;
    const int interface_number = 4;
    const unsigned char endpoint = 0x04;
    libusb_context *context = NULL;
    libusb_device_handle *handle = NULL;
    int result = libusb_init(&context);
    int status = 1;
    unsigned note;
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "libusb_init: %s\n", libusb_error_name(result));
        return 1;
    }
    handle = libusb_open_device_with_vid_pid(context, vid, pid);
    if (handle == NULL) {
        fputs("exact v15 device 4353:cf4d could not be opened\n", stderr);
        status = 2;
        goto cleanup;
    }
    result = libusb_claim_interface(handle, interface_number);
    if (result != LIBUSB_SUCCESS) {
        fprintf(stderr, "claim interface %d: %s\n", interface_number, libusb_error_name(result));
        status = 3;
        goto cleanup;
    }
    for (note = 36; note <= 51; ++note) {
        unsigned pad = note_to_pad(note);
        const struct patch *patch = &patches[pad - 1u];
        int transferred = 0;
        result = libusb_bulk_transfer(handle, endpoint, (unsigned char *)patch->events,
                                      USB_MIDI_SIZE, &transferred, 2000);
        if (result != LIBUSB_SUCCESS || transferred != (int)USB_MIDI_SIZE) {
            fprintf(stderr, "Pad %u note %u bulk OUT: %s transferred %d/%u\n",
                    pad, note, libusb_error_name(result), transferred, (unsigned)USB_MIDI_SIZE);
            status = 4;
            break;
        }
        printf("sent Pad %02u note %u: %s\n", pad, note, patch->name);
        if (note < 51) {
            const struct timespec delay = {0, INTER_PACKET_DELAY_NS};
            if (nanosleep(&delay, NULL) != 0) {
                perror("nanosleep");
                status = 5;
                break;
            }
        }
    }
    if (status == 1) status = 0;
    libusb_release_interface(handle, interface_number);
cleanup:
    if (handle != NULL) libusb_close(handle);
    libusb_exit(context);
    return status;
}
#else
static int send_set(const struct patch patches[PAD_COUNT]) {
    (void)patches;
    fputs("send BLOCK: compile with S1C3_ENABLE_LIVE_USB and libusb for live transmission\n", stderr);
    return 2;
}
#endif

static void usage(const char *program) {
    fprintf(stderr,
            "usage:\n"
            "  %s dry-run <pad-set-directory>\n"
            "  %s send <pad-set-directory> --confirm %s\n",
            program, program, CONFIRM_TOKEN);
}

int main(int argc, char **argv) {
    struct patch patches[PAD_COUNT];
    if (argc < 3 || (strcmp(argv[1], "dry-run") != 0 && strcmp(argv[1], "send") != 0)) {
        usage(argv[0]);
        return 1;
    }
    if (load_set(argv[2], patches) != 0) return 1;
    print_order(patches);
    if (strcmp(argv[1], "dry-run") == 0) {
        puts("16-pad editor SysEx dry-run: PASS");
        return 0;
    }
    if (argc != 5 || strcmp(argv[3], "--confirm") != 0 || strcmp(argv[4], CONFIRM_TOKEN) != 0) {
        fputs("send BLOCK: exact confirmation token required\n", stderr);
        usage(argv[0]);
        return 2;
    }
    return send_set(patches);
}
