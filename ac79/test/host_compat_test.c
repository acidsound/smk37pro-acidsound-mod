/*
 * Byte-compatibility test for the device-side OTA transport.
 *
 * It links the device translation unit (ac79/app/smk_ota_transport.c) together
 * with the project's host-side reference (src/protocol.c) and requires them to
 * agree byte for byte on:
 *
 *   1. every shared transport function, over exhaustive lengths and randomized
 *      payloads;
 *   1b. output-capacity refusals: for every function that takes an output
 *      capacity, the exact fit must succeed, every smaller capacity must be
 *      refused, and no byte may be written past the declared capacity. These
 *      guards are what protect device memory, so weakening one must not be
 *      invisible to the suite;
 *   2. both cross-implementation round trips:
 *        device smk_ota_build_request   -> reference smk37_parse_ota_request
 *        reference smk37_make_flash_update_packet -> device smk_ota_parse_response
 *   3. the complete device->host wire path (build -> frame -> packetize ->
 *      reference unpacketize -> reference unframe -> reference parse);
 *   4. the request triples of a captured install transcript, when a transcript
 *      path is given; those lines are what the reference's own parser produced
 *      from a real running device, so reproducing them is the closest offline
 *      equivalent of the hardware round trip.
 *
 * Usage: host_compat_test [transcript.log]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"          /* host-side reference (this repo's src/) */
#include "smk_ota_transport.h" /* device-side mirror (ac79/app/) */

static unsigned long rng_state = 0x13579bdfUL;

static unsigned next_random(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (unsigned)(rng_state & 0xffffffffUL);
}

static void fill_random(uint8_t *buffer, size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        buffer[index] = (uint8_t)(next_random() & 0xffu);
    }
}

static unsigned failures;
static unsigned long comparisons;

static void fail(const char *what, size_t length, unsigned long index) {
    ++failures;
    if (failures <= 20) {
        fprintf(stderr, "FAIL %s (length %zu, case %lu)\n", what, length, index);
    }
}

/* Canary bytes live directly behind a deliberately too-small output capacity:
 * a write that escaped the declared capacity (what a weakened guard allows)
 * changes them, so the guard is checked by behaviour, not by reading the
 * guard's source line. */
#define GUARD_SLACK 16u
#define GUARD_FILL 0xa5u

static int canary_intact(const uint8_t *buffer, size_t capacity) {
    size_t index;

    for (index = capacity; index < capacity + GUARD_SLACK; ++index) {
        if (buffer[index] != GUARD_FILL) {
            return 0;
        }
    }
    return 1;
}

/* Reference-side receive path, mirroring src/ota.c ota_receive_binary(). */
static int reference_unframe(const uint8_t *stream, size_t stream_length,
                             uint8_t *binary, size_t capacity,
                             size_t *binary_length) {
    size_t index;
    int started = 0;
    size_t framed_length = 0;
    static uint8_t framed[512];

    for (index = 0; index < stream_length; ++index) {
        uint8_t value = stream[index];
        if (!started) {
            if (value != 0xf0) {
                continue;
            }
            started = 1;
            framed_length = 0;
        }
        if (framed_length >= sizeof(framed)) {
            return 1;
        }
        framed[framed_length++] = value;
        if (value == 0xf7) {
            *binary_length =
                smk37_unpack_7_to_8(framed + 1, framed_length - 2, binary,
                                    capacity);
            return *binary_length == 0 ? 1 : 0;
        }
    }
    return 1;
}

int main(int argc, char **argv) {
    uint8_t input[128];
    uint8_t mine[256];
    uint8_t theirs[256];
    uint8_t refout[1024];
    uint8_t framed[512];
    uint8_t packets[1024];
    uint8_t stream[512];
    uint8_t binary[512];
    size_t length;
    unsigned long case_index;
    unsigned long transcript_requests = 0;
    unsigned long transcript_failures = 0;
    FILE *transcript = NULL;

    if (argc > 1) {
        transcript = fopen(argv[1], "r");
        if (transcript == NULL) {
            fprintf(stderr, "cannot open transcript %s\n", argv[1]);
            return 2;
        }
    }

    if (smk_ota_transport_self_test() != 0) {
        fputs("FAIL device self-test\n", stderr);
        return 1;
    }

    /* 1. exhaustive lengths, randomized payloads, every shared function. */
    for (length = 0; length <= 96; ++length) {
        size_t mine_length;
        size_t theirs_length;

        for (case_index = 0; case_index < 24; ++case_index) {
            fill_random(input, length);

            mine_length = smk_ota_pack_8_to_7(input, length, mine, sizeof(mine));
            theirs_length =
                smk37_pack_8_to_7(input, length, theirs, sizeof(theirs));
            ++comparisons;
            if (mine_length != theirs_length ||
                memcmp(mine, theirs, theirs_length) != 0) {
                fail("pack_8_to_7", length, case_index);
            }

            /* 7-bit payloads only for the unpack direction. */
            for (size_t index = 0; index < length; ++index) {
                input[index] &= 0x7fu;
            }
            mine_length = smk_ota_unpack_7_to_8(input, length, mine, sizeof(mine));
            theirs_length =
                smk37_unpack_7_to_8(input, length, theirs, sizeof(theirs));
            ++comparisons;
            if (mine_length != theirs_length ||
                memcmp(mine, theirs, theirs_length) != 0) {
                fail("unpack_7_to_8", length, case_index);
            }

            mine_length =
                smk_ota_frame_binary(input, length, mine, sizeof(mine));
            theirs_length =
                smk37_frame_binary(input, length, theirs, sizeof(theirs));
            ++comparisons;
            if (mine_length != theirs_length || mine_length == 0 ||
                memcmp(mine, theirs, theirs_length) != 0) {
                fail("frame_binary", length, case_index);
            }

            if (theirs_length != 0) {
                /* NB: the reference implementation must not be given the same
                 * buffer as input and output, so it writes into refout. */
                mine_length = smk_ota_usb_packetize(theirs, theirs_length, mine,
                                                    sizeof(mine));
                theirs_length = smk37_usb_packetize(theirs, theirs_length,
                                                    refout, sizeof(refout));
                ++comparisons;
                if (mine_length != theirs_length || mine_length == 0 ||
                    memcmp(mine, refout, theirs_length) != 0) {
                    fail("usb_packetize", length, case_index);
                }
            }

            fill_random(input, length);
            mine_length = smk_ota_complement_checksum(input, length);
            theirs_length = smk37_complement_checksum(input, length);
            ++comparisons;
            if (mine_length != theirs_length) {
                fail("complement_checksum", length, case_index);
            }
        }
    }

    /* 1b. capacity refusals. Section 1 always hands each function a comfortable
     * buffer, so its guards were never exercised and a weakened guard ("<" for
     * ">=", or a dropped minimum-size refusal) was undetectable. Each case
     * below demands all three properties at once: the exact fit succeeds, every
     * smaller capacity is refused, and the canary behind the declared capacity
     * is untouched. */
    {
        uint8_t payload[128];
        uint8_t unlimited[256];
        uint8_t guarded[256 + GUARD_SLACK];
        size_t lengths_index;
        size_t needed;
        size_t capacity;
        size_t theirs;

        /* pack_8_to_7: needed = ceil(8 * L / 7) */
        {
            static const size_t lengths[] = {1, 2, 3, 7, 8, 15, 16, 96};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];

                fill_random(payload, want);
                needed = smk_ota_pack_8_to_7(payload, want, unlimited,
                                             sizeof(unlimited));
                if (needed == 0 || needed > 240u) {
                    fail("pack baseline", want, needed);
                    continue;
                }

                /* the exact fit must also agree with the reference byte for
                 * byte, not merely in length */
                memset(guarded, GUARD_FILL, sizeof(guarded));
                theirs = smk37_pack_8_to_7(payload, want, unlimited,
                                           sizeof(unlimited));
                ++comparisons;
                if (smk_ota_pack_8_to_7(payload, want, guarded, needed) != needed ||
                    needed != theirs ||
                    memcmp(guarded, unlimited, needed) != 0 ||
                    !canary_intact(guarded, needed)) {
                    fail("pack exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_pack_8_to_7(payload, want, guarded,
                                            capacity) != 0) {
                        fail("pack accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("pack wrote past capacity", want, capacity);
                        break;
                    }
                }
            }
        }

        /* unpack_7_to_8: needed = floor(7 * L / 8); payload must stay 7-bit */
        {
            static const size_t lengths[] = {8, 9, 15, 16, 23, 96};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];
                size_t index;

                fill_random(payload, want);
                for (index = 0; index < want; ++index) {
                    payload[index] &= 0x7fu;
                }
                needed = smk_ota_unpack_7_to_8(payload, want, unlimited,
                                               sizeof(unlimited));
                if (needed == 0) {
                    fail("unpack baseline", want, needed);
                    continue;
                }

                memset(guarded, GUARD_FILL, sizeof(guarded));
                theirs = smk37_unpack_7_to_8(payload, want, unlimited,
                                             sizeof(unlimited));
                ++comparisons;
                if (smk_ota_unpack_7_to_8(payload, want, guarded,
                                          needed) != needed ||
                    needed != theirs ||
                    memcmp(guarded, unlimited, needed) != 0 ||
                    !canary_intact(guarded, needed)) {
                    fail("unpack exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_unpack_7_to_8(payload, want, guarded,
                                              capacity) != 0) {
                        fail("unpack accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("unpack wrote past capacity", want, capacity);
                        break;
                    }
                }
            }
        }

        /* usb_packetize: needed = 4 * ceil(L / 3) over a framed stream */
        {
            static const size_t lengths[] = {2, 3, 4, 5, 6, 7, 15, 18};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];

                fill_random(payload, want);
                payload[0] = SMK_OTA_STREAM_START;
                payload[want - 1] = SMK_OTA_STREAM_END;
                needed = smk_ota_usb_packetize(payload, want, unlimited,
                                               sizeof(unlimited));
                if (needed == 0 || needed > 240u) {
                    fail("packetize baseline", want, needed);
                    continue;
                }

                memset(guarded, GUARD_FILL, sizeof(guarded));
                theirs = smk37_usb_packetize(payload, want, refout,
                                             sizeof(refout));
                ++comparisons;
                if (smk_ota_usb_packetize(payload, want, guarded,
                                          needed) != needed ||
                    needed != theirs ||
                    memcmp(guarded, refout, needed) != 0 ||
                    !canary_intact(guarded, needed)) {
                    fail("packetize exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_usb_packetize(payload, want, guarded,
                                              capacity) != 0) {
                        fail("packetize accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("packetize wrote past capacity", want, capacity);
                        break;
                    }
                }
            }
        }

        /* usb_unpacketize: needed = the binary length the packets carry */
        {
            static const size_t lengths[] = {1, 2, 3, 4, 7, 15, 96};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];
                size_t framed_length;
                size_t packet_length;

                fill_random(payload, want);
                framed_length = smk37_frame_binary(payload, want, framed,
                                                   sizeof(framed));
                packet_length = smk37_usb_packetize(framed, framed_length,
                                                    packets,
                                                    sizeof(packets));
                /* unpacketize returns the framed stream it carried, not the
                 * 7-bit-decoded binary: section 1 compares it with `framed`. */
                needed = smk_ota_usb_unpacketize(packets, packet_length,
                                                 unlimited,
                                                 sizeof(unlimited));
                if (needed != framed_length) {
                    fail("unpacketize baseline", want, needed);
                    continue;
                }

                memset(guarded, GUARD_FILL, sizeof(guarded));
                ++comparisons;
                if (smk_ota_usb_unpacketize(packets, packet_length, guarded,
                                            needed) != needed ||
                    memcmp(guarded, framed, needed) != 0 ||
                    !canary_intact(guarded, needed)) {
                    fail("unpacketize exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_usb_unpacketize(packets, packet_length,
                                                guarded, capacity) != 0) {
                        fail("unpacketize accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("unpacketize wrote past capacity", want,
                             capacity);
                        break;
                    }
                }
            }
        }

        /* build_request: the 15-byte packet, capacity 15 vs 14 */
        {
            for (lengths_index = 0; lengths_index < 8u; ++lengths_index) {
                uint8_t flash_type = (uint8_t)(next_random() & 1u);
                uint32_t address = next_random() & 0x0fffffffu;
                uint32_t want = next_random() % 0x10000u;

                memset(guarded, GUARD_FILL, sizeof(guarded));
                ++comparisons;
                if (smk_ota_build_request(flash_type, address, want, guarded,
                                          SMK_OTA_REQUEST_PACKET_SIZE) !=
                        SMK_OTA_REQUEST_PACKET_SIZE ||
                    !canary_intact(guarded, SMK_OTA_REQUEST_PACKET_SIZE)) {
                    fail("build_request exact-fit capacity", 0, lengths_index);
                }

                for (capacity = 0; capacity < SMK_OTA_REQUEST_PACKET_SIZE;
                     ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_build_request(flash_type, address, want,
                                              guarded, capacity) != 0) {
                        fail("build_request accepted too-small capacity", 0,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("build_request wrote past capacity", 0, capacity);
                        break;
                    }
                }

                /* a length that cannot be encoded is still refused outright */
                memset(guarded, GUARD_FILL, sizeof(guarded));
                ++comparisons;
                if (smk_ota_build_request(flash_type, address, 0x1000000u,
                                          guarded, sizeof(guarded)) != 0) {
                    fail("build_request accepted a 25-bit length", 0,
                         lengths_index);
                }
            }
        }

        /* frame_binary: 0xf0 / packed payload / 0xf7, capacity >= 2 */
        {
            static const size_t lengths[] = {0, 1, 2, 3, 7, 15, 96};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];

                fill_random(payload, want);
                needed = smk_ota_frame_binary(payload, want, unlimited,
                                              sizeof(unlimited));
                if (needed < 2u || needed > 240u) {
                    fail("frame baseline", want, needed);
                    continue;
                }

                memset(guarded, GUARD_FILL, sizeof(guarded));
                theirs = smk37_frame_binary(payload, want, refout,
                                            sizeof(refout));
                ++comparisons;
                if (smk_ota_frame_binary(payload, want, guarded, needed) !=
                        needed ||
                    needed != theirs ||
                    memcmp(guarded, refout, needed) != 0 ||
                    guarded[0] != SMK_OTA_STREAM_START ||
                    guarded[needed - 1] != SMK_OTA_STREAM_END ||
                    !canary_intact(guarded, needed)) {
                    fail("frame exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_frame_binary(payload, want, guarded,
                                             capacity) != 0) {
                        fail("frame accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("frame wrote past capacity", want, capacity);
                        break;
                    }
                }
            }
        }

        /* unframe_binary passes the capacity through to unpack_7_to_8 */
        {
            static const size_t lengths[] = {1, 2, 3, 4, 7, 15, 96};

            for (lengths_index = 0;
                 lengths_index < sizeof(lengths) / sizeof(lengths[0]);
                 ++lengths_index) {
                size_t want = lengths[lengths_index];
                size_t framed_length;

                fill_random(payload, want);
                framed_length = smk37_frame_binary(payload, want, framed,
                                                   sizeof(framed));
                needed = smk_ota_unframe_binary(framed, framed_length,
                                                unlimited,
                                                sizeof(unlimited));
                if (needed != want) {
                    fail("unframe baseline", want, needed);
                    continue;
                }

                memset(guarded, GUARD_FILL, sizeof(guarded));
                ++comparisons;
                if (smk_ota_unframe_binary(framed, framed_length, guarded,
                                           needed) != needed ||
                    memcmp(guarded, payload, needed) != 0 ||
                    !canary_intact(guarded, needed)) {
                    fail("unframe exact-fit capacity", want, needed);
                }

                for (capacity = 0; capacity < needed; ++capacity) {
                    memset(guarded, GUARD_FILL, sizeof(guarded));
                    ++comparisons;
                    if (smk_ota_unframe_binary(framed, framed_length, guarded,
                                               capacity) != 0) {
                        fail("unframe accepted too-small capacity", want,
                             capacity);
                        break;
                    }
                    if (!canary_intact(guarded, capacity)) {
                        fail("unframe wrote past capacity", want, capacity);
                        break;
                    }
                }
            }
        }
    }

    /* 2a. device request -> reference parser. */
    for (case_index = 0; case_index < 4000; ++case_index) {
        struct smk37_ota_request parsed;
        uint8_t flash_type = (uint8_t)(next_random() & 1u);
        uint32_t address = next_random() & 0x0fffffffu;
        uint32_t want = next_random() % 0x10000u;
        size_t built;

        built = smk_ota_build_request(flash_type, address, want, mine,
                                      sizeof(mine));
        ++comparisons;
        if (built != 15) {
            fail("build_request size", 0, case_index);
            continue;
        }
        if (smk37_parse_ota_request(mine, built, &parsed) != 0 ||
            parsed.flash_type != flash_type || parsed.address != address ||
            parsed.length != want) {
            fail("build_request -> reference parse", 0, case_index);
        }
    }

    /* 2b. reference response builder -> device parser. */
    for (case_index = 0; case_index < 4000; ++case_index) {
        struct smk_ota_response parsed;
        uint8_t flash_type = (uint8_t)(next_random() & 1u);
        uint32_t address = next_random() & 0x0fffffffu;
        size_t data_length = next_random() % 96u;
        size_t built;

        fill_random(input, data_length);
        built = smk37_make_flash_update_packet(flash_type, address, input,
                                               (uint32_t)data_length, theirs,
                                               sizeof(theirs));
        ++comparisons;
        if (built == 0) {
            fail("reference update packet build", data_length, case_index);
            continue;
        }
        if (smk_ota_parse_response(theirs, built, &parsed) != 0 ||
            parsed.flash_type != flash_type || parsed.address != address ||
            parsed.length != data_length ||
            memcmp(parsed.data, input, data_length) != 0) {
            fail("reference packet -> device parse", data_length, case_index);
        }
    }

    /* 3. complete device->host wire path, decoded by the reference. */
    for (case_index = 0; case_index < 4000; ++case_index) {
        struct smk37_ota_request parsed;
        uint8_t flash_type = (uint8_t)(next_random() & 1u);
        uint32_t address = next_random() & 0x0fffffffu;
        uint32_t want = next_random() % 0x10000u;
        size_t framed_length;
        size_t packet_length;
        size_t stream_length;
        size_t binary_length = 0;
        size_t built = smk_ota_build_request(flash_type, address, want, mine,
                                             sizeof(mine));

        ++comparisons;
        framed_length = smk_ota_frame_binary(mine, built, framed,
                                             sizeof(framed));
        packet_length = smk_ota_usb_packetize(framed, framed_length, packets,
                                              sizeof(packets));
        stream_length = smk37_usb_unpacketize(packets, packet_length, stream,
                                              sizeof(stream));
        if (framed_length == 0 || packet_length == 0 ||
            stream_length != framed_length ||
            memcmp(stream, framed, framed_length) != 0) {
            fail("wire path transport", 0, case_index);
            continue;
        }
        if (reference_unframe(stream, stream_length, binary, sizeof(binary),
                              &binary_length) != 0 ||
            binary_length != built ||
            memcmp(binary, mine, built) != 0 ||
            smk37_parse_ota_request(binary, binary_length, &parsed) != 0 ||
            parsed.flash_type != flash_type || parsed.address != address ||
            parsed.length != want) {
            fail("wire path -> reference parse", 0, case_index);
        }
    }

    /* 3b. corrupted / malformed inputs must be refused, not misread. */
    for (case_index = 0; case_index < 15; ++case_index) {
        struct smk37_ota_request parsed;
        size_t built = smk_ota_build_request(0, 0x40u, 0x200u, mine,
                                             sizeof(mine));
        ++comparisons;
        if (built != 15) {
            fail("build_request size (negative)", 0, case_index);
            continue;
        }
        mine[case_index] ^= 0xffu;
        /* The reference parser is the authority on what a valid request is. */
        if (smk37_parse_ota_request(mine, built, &parsed) == 0) {
            fail("reference accepted a corrupted request", 0, case_index);
        }
    }
    {
        struct smk37_ota_request parsed;
        uint8_t corrupt[16];
        size_t built = smk_ota_build_request(0, 0x40u, 0x200u, corrupt,
                                             sizeof(corrupt));
        corrupt[built - 1] ^= 0x01u;
        ++comparisons;
        if (smk37_parse_ota_request(corrupt, built, &parsed) == 0) {
            fail("reference accepts corrupt checksum (test is meaningless)", 0, 0);
        }
    }
    {
        uint8_t good[32];
        struct smk_ota_response parsed;
        size_t built = smk37_make_flash_update_packet(0, 0x100u, (const uint8_t *)"ab",
                                                      2u, good, sizeof(good));
        ++comparisons;
        good[built - 1] ^= 0x01u;
        if (smk_ota_parse_response(good, built, &parsed) == 0) {
            fail("device accepts corrupt response checksum", 0, 0);
        }
        if (smk_ota_parse_response(good, built - 1u, &parsed) == 0) {
            fail("device accepts truncated response", 0, 0);
        }
    }

    /* 4. captured transcript triples (the real device's own request lines). */
    if (transcript != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), transcript) != NULL) {
            unsigned sequence;
            unsigned flash_type;
            unsigned long address;
            unsigned long want;
            struct smk37_ota_request parsed;

            if (sscanf(line, "request %u flash=%u address=0x%lx length=%lu",
                       &sequence, &flash_type, &address, &want) != 4) {
                continue;
            }
            ++transcript_requests;
            {
                size_t built = smk_ota_build_request((uint8_t)flash_type,
                                                     (uint32_t)address,
                                                     (uint32_t)want, mine,
                                                     sizeof(mine));
                size_t framed_length;
                size_t packet_length;
                size_t stream_length;
                size_t binary_length = 0;

                if (built != 15 ||
                    smk37_parse_ota_request(mine, built, &parsed) != 0 ||
                    parsed.flash_type != flash_type ||
                    parsed.address != (uint32_t)address ||
                    parsed.length != (uint32_t)want) {
                    ++transcript_failures;
                    if (transcript_failures <= 5) {
                        fprintf(stderr,
                                "FAIL transcript request %u "
                                "(flash=%u address=0x%lx length=%lu)\n",
                                sequence, flash_type, address, want);
                    }
                    continue;
                }

                framed_length = smk_ota_frame_binary(mine, built, framed,
                                                     sizeof(framed));
                packet_length = smk_ota_usb_packetize(framed, framed_length,
                                                      packets,
                                                      sizeof(packets));
                stream_length = smk37_usb_unpacketize(packets, packet_length,
                                                      stream, sizeof(stream));
                if (reference_unframe(stream, stream_length, binary,
                                      sizeof(binary), &binary_length) != 0 ||
                    binary_length != built ||
                    memcmp(binary, mine, built) != 0) {
                    ++transcript_failures;
                }
                ++comparisons;
            }
        }
        fclose(transcript);
        fprintf(stderr, "transcript: %lu request lines replayed, %lu failed\n",
                transcript_requests, transcript_failures);
    }

    printf("comparisons: %lu, failures: %u\n", comparisons, failures);
    if (failures != 0 || transcript_failures != 0) {
        puts("HOST COMPAT: FAIL");
        return 1;
    }
    puts("HOST COMPAT: PASS");
    return 0;
}
