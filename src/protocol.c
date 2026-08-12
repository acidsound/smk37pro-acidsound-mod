#include "protocol.h"

#include <stdio.h>
#include <string.h>

enum {
    SMK37_STREAM_START = 0xf0,
    SMK37_STREAM_END = 0xf7,
};

size_t smk37_pack_8_to_7(const uint8_t *input, size_t input_length,
                         uint8_t *output, size_t output_capacity) {
    uint32_t accumulator = 0;
    unsigned bit_count = 0;
    size_t output_length = 0;

    for (size_t index = 0; index < input_length; ++index) {
        accumulator |= (uint32_t)input[index] << bit_count;
        bit_count += 8;

        while (bit_count >= 7) {
            if (output_length >= output_capacity) {
                return 0;
            }
            output[output_length++] = (uint8_t)(accumulator & 0x7f);
            accumulator >>= 7;
            bit_count -= 7;
        }
    }

    if (bit_count != 0) {
        if (output_length >= output_capacity) {
            return 0;
        }
        output[output_length++] = (uint8_t)(accumulator & 0x7f);
    }

    return output_length;
}

size_t smk37_unpack_7_to_8(const uint8_t *input, size_t input_length,
                           uint8_t *output, size_t output_capacity) {
    uint32_t accumulator = 0;
    unsigned bit_count = 0;
    size_t output_length = 0;

    for (size_t index = 0; index < input_length; ++index) {
        if ((input[index] & 0x80) != 0) {
            return 0;
        }

        accumulator |= (uint32_t)input[index] << bit_count;
        bit_count += 7;

        while (bit_count >= 8) {
            if (output_length >= output_capacity) {
                return 0;
            }
            output[output_length++] = (uint8_t)(accumulator & 0xff);
            accumulator >>= 8;
            bit_count -= 8;
        }
    }

    return output_length;
}

size_t smk37_frame_binary(const uint8_t *input, size_t input_length,
                          uint8_t *output, size_t output_capacity) {
    size_t packed_length;

    if (output_capacity < 2) {
        return 0;
    }

    output[0] = SMK37_STREAM_START;
    packed_length = smk37_pack_8_to_7(input, input_length, output + 1,
                                      output_capacity - 2);
    if (packed_length == 0 && input_length != 0) {
        return 0;
    }
    output[packed_length + 1] = SMK37_STREAM_END;
    return packed_length + 2;
}

size_t smk37_usb_packetize(const uint8_t *stream, size_t stream_length,
                           uint8_t *output, size_t output_capacity) {
    size_t input_offset = 0;
    size_t output_length = 0;

    if (stream_length < 2 || stream[0] != SMK37_STREAM_START ||
        stream[stream_length - 1] != SMK37_STREAM_END) {
        return 0;
    }

    while (input_offset < stream_length) {
        size_t remaining = stream_length - input_offset;
        size_t data_length = remaining >= 3 ? 3 : remaining;
        uint8_t code_index;

        if (remaining > 3) {
            code_index = 0x04;
        } else if (remaining == 3) {
            code_index = 0x07;
        } else if (remaining == 2) {
            code_index = 0x06;
        } else {
            code_index = 0x05;
        }

        if (output_length + 4 > output_capacity) {
            return 0;
        }

        output[output_length] = code_index;
        output[output_length + 1] = 0;
        output[output_length + 2] = 0;
        output[output_length + 3] = 0;
        memcpy(output + output_length + 1, stream + input_offset, data_length);

        input_offset += data_length;
        output_length += 4;
    }

    return output_length;
}

size_t smk37_usb_unpacketize(const uint8_t *packets, size_t packet_length,
                             uint8_t *output, size_t output_capacity) {
    size_t output_length = 0;

    if (packet_length % 4 != 0) {
        return 0;
    }

    for (size_t offset = 0; offset < packet_length; offset += 4) {
        uint8_t code_index = packets[offset] & 0x0f;
        size_t data_length;

        switch (code_index) {
            case 0x04: data_length = 3; break;
            case 0x05: data_length = 1; break;
            case 0x06: data_length = 2; break;
            case 0x07: data_length = 3; break;
            default: continue;
        }

        if (output_length + data_length > output_capacity) {
            return 0;
        }
        memcpy(output + output_length, packets + offset + 1, data_length);
        output_length += data_length;
    }

    return output_length;
}

uint8_t smk37_complement_checksum(const uint8_t *input, size_t input_length) {
    uint8_t sum = 0;

    for (size_t index = 0; index < input_length; ++index) {
        sum = (uint8_t)(sum + input[index]);
    }
    return (uint8_t)~sum;
}

size_t smk37_make_flash_read_request(uint8_t flash_type, uint32_t address,
                                     uint32_t length, uint8_t *output,
                                     size_t output_capacity) {
    if (output_capacity < 15 || length > 0xffffff) {
        return 0;
    }

    output[0] = 0x00;
    output[1] = 0x59;
    output[2] = 0x23;
    output[3] = 0x08;
    output[4] = 0x00;
    output[5] = 0x00;
    output[6] = flash_type;
    output[7] = (uint8_t)address;
    output[8] = (uint8_t)(address >> 8);
    output[9] = (uint8_t)(address >> 16);
    output[10] = (uint8_t)(address >> 24);
    output[11] = (uint8_t)length;
    output[12] = (uint8_t)(length >> 8);
    output[13] = (uint8_t)(length >> 16);
    output[14] = smk37_complement_checksum(output + 6, 8);
    return 15;
}

size_t smk37_make_flash_update_packet(uint8_t flash_type, uint32_t address,
                                      const uint8_t *data, uint32_t length,
                                      uint8_t *output,
                                      size_t output_capacity) {
    size_t packet_length = (size_t)length + 15;

    if (length > 0xffffff || output_capacity < packet_length ||
        (length != 0 && data == NULL)) {
        return 0;
    }
    output[0] = 0x00;
    output[1] = 0x59;
    output[2] = 0x30;
    output[3] = (uint8_t)(length + 8);
    output[4] = (uint8_t)((length + 8) >> 8);
    output[5] = (uint8_t)((length + 8) >> 16);
    output[6] = flash_type;
    output[7] = (uint8_t)address;
    output[8] = (uint8_t)(address >> 8);
    output[9] = (uint8_t)(address >> 16);
    output[10] = (uint8_t)(address >> 24);
    output[11] = (uint8_t)length;
    output[12] = (uint8_t)(length >> 8);
    output[13] = (uint8_t)(length >> 16);
    if (length != 0) {
        memcpy(output + 14, data, length);
    }
    output[packet_length - 1] =
        smk37_complement_checksum(output + 6, (size_t)length + 8);
    return packet_length;
}

int smk37_parse_ota_request(const uint8_t *packet, size_t packet_length,
                            struct smk37_ota_request *request) {
    uint32_t payload_length;

    if (packet == NULL || request == NULL || packet_length != 15 ||
        packet[0] != 0x00 || packet[1] != 0x59 || packet[2] != 0x30) {
        return 1;
    }
    payload_length = (uint32_t)packet[3] |
                     ((uint32_t)packet[4] << 8) |
                     ((uint32_t)packet[5] << 16);
    if (payload_length != 8 ||
        smk37_complement_checksum(packet + 6, 8) != packet[14]) {
        return 1;
    }
    request->flash_type = packet[6];
    request->address = (uint32_t)packet[7] |
                       ((uint32_t)packet[8] << 8) |
                       ((uint32_t)packet[9] << 16) |
                       ((uint32_t)packet[10] << 24);
    request->length = (uint32_t)packet[11] |
                      ((uint32_t)packet[12] << 8) |
                      ((uint32_t)packet[13] << 16);
    return 0;
}

static int expect_equal(const char *name, const uint8_t *actual,
                        size_t actual_length, const uint8_t *expected,
                        size_t expected_length) {
    if (actual_length == expected_length &&
        memcmp(actual, expected, expected_length) == 0) {
        return 0;
    }

    fprintf(stderr, "%s: mismatch (got %zu bytes, expected %zu)\n", name,
            actual_length, expected_length);
    return 1;
}

int smk37_protocol_self_test(void) {
    static const uint8_t query[] = {0x00, 0x59, 0x11, 0x00, 0x00, 0x00, 0xff};
    static const uint8_t expected_read[] = {
        0x00, 0x59, 0x23, 0x08, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0xbf,
    };
    static const uint8_t update_data[] = {0x12, 0x34, 0x56};
    static const uint8_t expected_update[] = {
        0x00, 0x59, 0x30, 0x0b, 0x00, 0x00, 0x00, 0x78, 0x56,
        0x34, 0x12, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x4c,
    };
    static const uint8_t ota_request_packet[] = {
        0x00, 0x59, 0x30, 0x08, 0x00, 0x00, 0x01, 0x78,
        0x56, 0x34, 0x12, 0xf1, 0x03, 0x00, 0xf6,
    };
    uint8_t read_request[15];
    uint8_t update_packet[sizeof(expected_update)];
    struct smk37_ota_request ota_request;
    uint8_t framed[32];
    uint8_t packets[64];
    uint8_t stream[32];
    uint8_t decoded[32];
    size_t framed_length;
    size_t packet_length;
    size_t stream_length;
    size_t decoded_length;

    if (smk37_complement_checksum(query + 6, 0) != 0xff) {
        fputs("checksum: mismatch\n", stderr);
        return 1;
    }

    if (smk37_make_flash_read_request(0, 0, 64, read_request,
                                      sizeof(read_request)) != 15 ||
        expect_equal("flash read request", read_request, sizeof(read_request),
                     expected_read, sizeof(expected_read)) != 0) {
        return 1;
    }

    if (smk37_make_flash_update_packet(0, 0x12345678, update_data,
                                       sizeof(update_data), update_packet,
                                       sizeof(update_packet)) !=
            sizeof(expected_update) ||
        expect_equal("flash update packet", update_packet,
                     sizeof(update_packet), expected_update,
                     sizeof(expected_update)) != 0) {
        return 1;
    }

    if (smk37_parse_ota_request(ota_request_packet,
                                sizeof(ota_request_packet), &ota_request) !=
            0 ||
        ota_request.flash_type != 1 ||
        ota_request.address != 0x12345678 || ota_request.length != 1009) {
        fputs("OTA request parser: mismatch\n", stderr);
        return 1;
    }

    framed_length = smk37_frame_binary(query, sizeof(query), framed,
                                       sizeof(framed));
    packet_length = smk37_usb_packetize(framed, framed_length, packets,
                                        sizeof(packets));
    stream_length = smk37_usb_unpacketize(packets, packet_length, stream,
                                          sizeof(stream));

    if (expect_equal("USB packet round trip", stream, stream_length, framed,
                     framed_length) != 0) {
        return 1;
    }

    if (stream_length < 2 || stream[0] != SMK37_STREAM_START ||
        stream[stream_length - 1] != SMK37_STREAM_END) {
        fputs("stream framing: mismatch\n", stderr);
        return 1;
    }

    decoded_length = smk37_unpack_7_to_8(stream + 1, stream_length - 2,
                                         decoded, sizeof(decoded));
    if (expect_equal("7-bit round trip", decoded, decoded_length, query,
                     sizeof(query)) != 0) {
        return 1;
    }

    return 0;
}
