#ifndef SMK37_SHA256_H
#define SMK37_SHA256_H

#include <stddef.h>
#include <stdint.h>

enum { SMK37_SHA256_LENGTH = 32 };

void smk37_sha256(const uint8_t *data, size_t length,
                  uint8_t output[SMK37_SHA256_LENGTH]);
int smk37_sha256_self_test(void);

#endif
