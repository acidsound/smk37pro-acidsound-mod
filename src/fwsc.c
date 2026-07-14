#include "fwsc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    FWSC_BLOCK_SIZE = 48,
    FWSC_DATA_PER_BLOCK = 47,
};

static bool parse_metadata(const uint8_t *data, size_t length,
                           unsigned slots, char *name, size_t name_capacity,
                           unsigned *version) {
    enum { READING_NAME, READING_VERSION, READING_PADDING } state =
        READING_NAME;
    size_t name_length = 0;
    unsigned parsed_version = 0;
    unsigned decimal_weight = 100;
    bool valid = false;

    if (slots == 0 || length < (size_t)slots * FWSC_BLOCK_SIZE ||
        name_capacity == 0) {
        return false;
    }

    for (unsigned index = 0; index < slots; ++index) {
        uint8_t raw = data[(size_t)index * FWSC_BLOCK_SIZE + 47];
        uint8_t decoded = (uint8_t)(0xffu - index + raw);

        switch (state) {
            case READING_NAME:
                valid = false;
                if (decoded == '_') {
                    state = READING_VERSION;
                } else {
                    if (decoded < 0x20 || decoded > 0x7e ||
                        name_length + 1 >= name_capacity) {
                        return false;
                    }
                    name[name_length++] = (char)decoded;
                }
                break;
            case READING_VERSION:
                if (raw == 0x7d) {
                    state = READING_PADDING;
                    valid = true;
                } else {
                    unsigned digit = (unsigned)(uint8_t)(decoded - '0');
                    valid = false;
                    if (digit <= 9 && decimal_weight != 0) {
                        parsed_version += digit * decimal_weight;
                        decimal_weight /= 10;
                    }
                }
                break;
            case READING_PADDING:
                valid = raw == 0x7d;
                if (!valid) {
                    return false;
                }
                break;
        }
    }

    if (!valid || state != READING_PADDING || name_length == 0 ||
        decimal_weight != 0) {
        return false;
    }
    name[name_length] = '\0';
    *version = parsed_version;
    return true;
}

bool smk37_fwsc_parse_memory(const uint8_t *file_data, size_t file_length,
                             struct smk37_fwsc *result) {
    static const unsigned slot_counts[] = {36, 20};

    if (file_data == NULL || result == NULL) {
        return false;
    }
    memset(result, 0, sizeof(*result));

    for (size_t attempt = 0;
         attempt < sizeof(slot_counts) / sizeof(slot_counts[0]); ++attempt) {
        unsigned slots = slot_counts[attempt];
        size_t metadata_length = (size_t)slots * FWSC_BLOCK_SIZE;
        size_t payload_length;
        uint8_t *payload;
        size_t output_offset = 0;
        unsigned version = 0;
        char name[SMK37_FWSC_NAME_CAPACITY];

        if (!parse_metadata(file_data, file_length, slots, name, sizeof(name),
                            &version)) {
            continue;
        }

        payload_length = file_length - slots;
        payload = malloc(payload_length == 0 ? 1 : payload_length);
        if (payload == NULL) {
            return false;
        }
        for (unsigned index = 0; index < slots; ++index) {
            memcpy(payload + output_offset,
                   file_data + (size_t)index * FWSC_BLOCK_SIZE,
                   FWSC_DATA_PER_BLOCK);
            output_offset += FWSC_DATA_PER_BLOCK;
        }
        memcpy(payload + output_offset, file_data + metadata_length,
               file_length - metadata_length);

        memcpy(result->name, name, strlen(name) + 1);
        result->version = version;
        result->metadata_slots = slots;
        result->payload = payload;
        result->payload_length = payload_length;
        smk37_sha256(file_data, file_length, result->file_sha256);
        return true;
    }
    return false;
}

bool smk37_fwsc_load(const char *path, struct smk37_fwsc *result) {
    FILE *file = NULL;
    uint8_t *data = NULL;
    long signed_length;
    size_t length;
    bool success = false;

    file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return false;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (signed_length = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        perror(path);
        goto cleanup;
    }
    length = (size_t)signed_length;
    if ((long)length != signed_length) {
        fprintf(stderr, "%s: file is too large\n", path);
        goto cleanup;
    }
    data = malloc(length == 0 ? 1 : length);
    if (data == NULL) {
        fputs("out of memory while loading firmware\n", stderr);
        goto cleanup;
    }
    if (fread(data, 1, length, file) != length) {
        if (ferror(file)) {
            perror(path);
        } else {
            fprintf(stderr, "%s: short read\n", path);
        }
        goto cleanup;
    }
    success = smk37_fwsc_parse_memory(data, length, result);
    if (!success) {
        fprintf(stderr, "%s: OTA file format validation failed\n", path);
    }

cleanup:
    free(data);
    if (fclose(file) != 0 && success) {
        perror(path);
        smk37_fwsc_free(result);
        success = false;
    }
    return success;
}

void smk37_fwsc_free(struct smk37_fwsc *firmware) {
    if (firmware == NULL) {
        return;
    }
    free(firmware->payload);
    memset(firmware, 0, sizeof(*firmware));
}

int smk37_fwsc_inspect(const char *path, const char *payload_output) {
    struct smk37_fwsc firmware;
    FILE *output = NULL;
    int status = 1;

    if (!smk37_fwsc_load(path, &firmware)) {
        return 1;
    }
    printf("name: %s\n", firmware.name);
    printf("version: %03u\n", firmware.version);
    printf("metadata slots: %u\n", firmware.metadata_slots);
    printf("OTA payload length: %zu\n", firmware.payload_length);
    fputs("package SHA-256: ", stdout);
    for (size_t index = 0; index < sizeof(firmware.file_sha256); ++index) {
        printf("%02x", firmware.file_sha256[index]);
    }
    putchar('\n');

    if (payload_output != NULL) {
        output = fopen(payload_output, "wb");
        if (output == NULL) {
            perror(payload_output);
            goto cleanup;
        }
        if (fwrite(firmware.payload, 1, firmware.payload_length, output) !=
                firmware.payload_length ||
            fclose(output) != 0) {
            output = NULL;
            perror(payload_output);
            goto cleanup;
        }
        output = NULL;
        printf("payload saved: %s\n", payload_output);
    }
    status = 0;

cleanup:
    if (output != NULL) {
        fclose(output);
    }
    smk37_fwsc_free(&firmware);
    return status;
}

int smk37_fwsc_self_test(void) {
    static const char metadata[] = "SMK-37 Pro_012nmlkji";
    uint8_t input[20 * FWSC_BLOCK_SIZE + 4];
    struct smk37_fwsc parsed;

    memset(input, 0xa5, sizeof(input));
    for (unsigned index = 0; index < 20; ++index) {
        input[(size_t)index * FWSC_BLOCK_SIZE + 47] =
            (uint8_t)((uint8_t)metadata[index] - (0xffu - index));
    }
    input[sizeof(input) - 4] = 'J';
    input[sizeof(input) - 3] = 'L';
    input[sizeof(input) - 2] = 'U';
    input[sizeof(input) - 1] = 'F';

    if (!smk37_fwsc_parse_memory(input, sizeof(input), &parsed)) {
        fputs("fwsc parser: synthetic package rejected\n", stderr);
        return 1;
    }
    if (strcmp(parsed.name, "SMK-37 Pro") != 0 || parsed.version != 12 ||
        parsed.metadata_slots != 20 ||
        parsed.payload_length != sizeof(input) - 20 ||
        memcmp(parsed.payload + parsed.payload_length - 4, "JLUF", 4) != 0) {
        fputs("fwsc parser: synthetic package mismatch\n", stderr);
        smk37_fwsc_free(&parsed);
        return 1;
    }
    smk37_fwsc_free(&parsed);
    return 0;
}
