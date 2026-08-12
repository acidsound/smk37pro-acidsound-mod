#include "sha256.h"

#include <stdio.h>
#include <string.h>

static uint32_t rotate_right(uint32_t value, unsigned count) {
    return (value >> count) | (value << (32 - count));
}

static void process_block(uint32_t state[8], const uint8_t block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    uint32_t words[64];
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    for (unsigned index = 0; index < 16; ++index) {
        size_t offset = (size_t)index * 4;
        words[index] = ((uint32_t)block[offset] << 24) |
                       ((uint32_t)block[offset + 1] << 16) |
                       ((uint32_t)block[offset + 2] << 8) |
                       (uint32_t)block[offset + 3];
    }
    for (unsigned index = 16; index < 64; ++index) {
        uint32_t s0 = rotate_right(words[index - 15], 7) ^
                      rotate_right(words[index - 15], 18) ^
                      (words[index - 15] >> 3);
        uint32_t s1 = rotate_right(words[index - 2], 17) ^
                      rotate_right(words[index - 2], 19) ^
                      (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    for (unsigned index = 0; index < 64; ++index) {
        uint32_t choice = (e & f) ^ (~e & g);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t upper_e = rotate_right(e, 6) ^ rotate_right(e, 11) ^
                           rotate_right(e, 25);
        uint32_t upper_a = rotate_right(a, 2) ^ rotate_right(a, 13) ^
                           rotate_right(a, 22);
        uint32_t temporary1 =
            h + upper_e + choice + constants[index] + words[index];
        uint32_t temporary2 = upper_a + majority;
        h = g;
        g = f;
        f = e;
        e = d + temporary1;
        d = c;
        c = b;
        b = a;
        a = temporary1 + temporary2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void smk37_sha256(const uint8_t *data, size_t length,
                  uint8_t output[SMK37_SHA256_LENGTH]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    uint8_t final_blocks[128];
    size_t full_length = length & ~(size_t)63;
    size_t remaining = length - full_length;
    size_t final_length = remaining < 56 ? 64 : 128;
    uint64_t bit_length = (uint64_t)length * 8;

    for (size_t offset = 0; offset < full_length; offset += 64) {
        process_block(state, data + offset);
    }
    memset(final_blocks, 0, sizeof(final_blocks));
    if (remaining != 0) {
        memcpy(final_blocks, data + full_length, remaining);
    }
    final_blocks[remaining] = 0x80;
    for (unsigned index = 0; index < 8; ++index) {
        final_blocks[final_length - 1 - index] = (uint8_t)(bit_length >>
                                                           (index * 8));
    }
    process_block(state, final_blocks);
    if (final_length == 128) {
        process_block(state, final_blocks + 64);
    }
    for (unsigned index = 0; index < 8; ++index) {
        output[index * 4] = (uint8_t)(state[index] >> 24);
        output[index * 4 + 1] = (uint8_t)(state[index] >> 16);
        output[index * 4 + 2] = (uint8_t)(state[index] >> 8);
        output[index * 4 + 3] = (uint8_t)state[index];
    }
}

int smk37_sha256_self_test(void) {
    static const uint8_t expected[SMK37_SHA256_LENGTH] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
    };
    uint8_t actual[SMK37_SHA256_LENGTH];

    smk37_sha256((const uint8_t *)"abc", 3, actual);
    if (memcmp(actual, expected, sizeof(expected)) != 0) {
        fputs("SHA-256 self-test failed\n", stderr);
        return 1;
    }
    return 0;
}
