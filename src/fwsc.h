#ifndef SMK37_FWSC_H
#define SMK37_FWSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sha256.h"

enum {
    SMK37_FWSC_NAME_CAPACITY = 128,
};

struct smk37_fwsc {
    char name[SMK37_FWSC_NAME_CAPACITY];
    unsigned version;
    unsigned metadata_slots;
    uint8_t *payload;
    size_t payload_length;
    uint8_t file_sha256[SMK37_SHA256_LENGTH];
};

bool smk37_fwsc_parse_memory(const uint8_t *file_data, size_t file_length,
                             struct smk37_fwsc *result);
bool smk37_fwsc_load(const char *path, struct smk37_fwsc *result);
void smk37_fwsc_free(struct smk37_fwsc *firmware);
int smk37_fwsc_inspect(const char *path, const char *payload_output);
int smk37_fwsc_self_test(void);

#endif
