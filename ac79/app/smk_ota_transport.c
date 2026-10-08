/*
 * Device-side SMK-37 Pro OTA transport + packet layer.
 * See ac79/app/smk_ota_transport.h for why this exists and what it is not.
 */

#include "smk_ota_transport.h"

static void smk_ota_copy(uint8_t *destination, const uint8_t *source,
                         size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        destination[index] = source[index];
    }
}

static int smk_ota_bytes_equal(const uint8_t *left, const uint8_t *right,
                               size_t length) {
    size_t index;
    for (index = 0; index < length; ++index) {
        if (left[index] != right[index]) {
            return 0;
        }
    }
    return 1;
}

size_t smk_ota_pack_8_to_7(const uint8_t *input, size_t input_length,
                           uint8_t *output, size_t output_capacity) {
    uint32_t accumulator = 0;
    unsigned bit_count = 0;
    size_t output_length = 0;
    size_t index;

    for (index = 0; index < input_length; ++index) {
        accumulator |= (uint32_t)input[index] << bit_count;
        bit_count += 8;

        while (bit_count >= 7) {
            if (output_length >= output_capacity) {
                return 0;
            }
            output[output_length] = (uint8_t)(accumulator & 0x7fu);
            ++output_length;
            accumulator >>= 7;
            bit_count -= 7;
        }
    }

    if (bit_count != 0) {
        if (output_length >= output_capacity) {
            return 0;
        }
        output[output_length] = (uint8_t)(accumulator & 0x7fu);
        ++output_length;
    }

    return output_length;
}

size_t smk_ota_unpack_7_to_8(const uint8_t *input, size_t input_length,
                             uint8_t *output, size_t output_capacity) {
    uint32_t accumulator = 0;
    unsigned bit_count = 0;
    size_t output_length = 0;
    size_t index;

    for (index = 0; index < input_length; ++index) {
        if ((input[index] & 0x80u) != 0) {
            return 0;
        }

        accumulator |= (uint32_t)input[index] << bit_count;
        bit_count += 7;

        while (bit_count >= 8) {
            if (output_length >= output_capacity) {
                return 0;
            }
            output[output_length] = (uint8_t)(accumulator & 0xffu);
            ++output_length;
            accumulator >>= 8;
            bit_count -= 8;
        }
    }

    return output_length;
}

size_t smk_ota_frame_binary(const uint8_t *input, size_t input_length,
                            uint8_t *output, size_t output_capacity) {
    size_t packed_length;

    if (output_capacity < 2) {
        return 0;
    }

    output[0] = SMK_OTA_STREAM_START;
    packed_length = smk_ota_pack_8_to_7(input, input_length, output + 1,
                                        output_capacity - 2);
    if (packed_length == 0 && input_length != 0) {
        return 0;
    }
    output[packed_length + 1] = SMK_OTA_STREAM_END;
    return packed_length + 2;
}

size_t smk_ota_usb_packetize(const uint8_t *stream, size_t stream_length,
                             uint8_t *output, size_t output_capacity) {
    size_t input_offset = 0;
    size_t output_length = 0;

    if (stream_length < 2 || stream[0] != SMK_OTA_STREAM_START ||
        stream[stream_length - 1] != SMK_OTA_STREAM_END) {
        return 0;
    }

    while (input_offset < stream_length) {
        size_t remaining = stream_length - input_offset;
        size_t data_length = remaining >= 3 ? 3 : remaining;
        uint8_t code_index;

        if (remaining > 3) {
            code_index = 0x04u;
        } else if (remaining == 3) {
            code_index = 0x07u;
        } else if (remaining == 2) {
            code_index = 0x06u;
        } else {
            code_index = 0x05u;
        }

        if (output_length + 4 > output_capacity) {
            return 0;
        }

        output[output_length] = code_index;
        output[output_length + 1] = 0;
        output[output_length + 2] = 0;
        output[output_length + 3] = 0;
        smk_ota_copy(output + output_length + 1, stream + input_offset,
                     data_length);

        input_offset += data_length;
        output_length += 4;
    }

    return output_length;
}

size_t smk_ota_usb_unpacketize(const uint8_t *packets, size_t packet_length,
                               uint8_t *output, size_t output_capacity) {
    size_t output_length = 0;
    size_t offset;

    if (packet_length % 4 != 0) {
        return 0;
    }

    for (offset = 0; offset < packet_length; offset += 4) {
        uint8_t code_index = packets[offset] & 0x0fu;
        size_t data_length;

        switch (code_index) {
            case 0x04:
                data_length = 3;
                break;
            case 0x05:
                data_length = 1;
                break;
            case 0x06:
                data_length = 2;
                break;
            case 0x07:
                data_length = 3;
                break;
            default:
                continue;
        }

        if (output_length + data_length > output_capacity) {
            return 0;
        }
        smk_ota_copy(output + output_length, packets + offset + 1, data_length);
        output_length += data_length;
    }

    return output_length;
}

uint8_t smk_ota_complement_checksum(const uint8_t *input, size_t input_length) {
    uint8_t sum = 0;
    size_t index;

    for (index = 0; index < input_length; ++index) {
        sum = (uint8_t)(sum + input[index]);
    }
    return (uint8_t)~sum;
}

size_t smk_ota_unframe_binary(const uint8_t *stream, size_t stream_length,
                              uint8_t *binary, size_t binary_capacity) {
    size_t start = 0;
    size_t index;
    int started = 0;
    size_t framed_length = 0;

    for (index = 0; index < stream_length; ++index) {
        uint8_t value = stream[index];

        if (!started) {
            if (value != SMK_OTA_STREAM_START) {
                continue;
            }
            started = 1;
            start = index;
            framed_length = 1;
            continue;
        }

        ++framed_length;
        if (value == SMK_OTA_STREAM_END) {
            if (framed_length < 3) {
                return 0;
            }
            return smk_ota_unpack_7_to_8(stream + start + 1,
                                         framed_length - 2, binary,
                                         binary_capacity);
        }
    }

    return 0;
}

size_t smk_ota_build_request(uint8_t flash_type, uint32_t address,
                             uint32_t length, uint8_t *output,
                             size_t output_capacity) {
    if (output_capacity < SMK_OTA_REQUEST_PACKET_SIZE) {
        return 0;
    }
    if (length > 0xffffffu) {
        return 0;
    }

    output[0] = SMK_OTA_HEADER_0;
    output[1] = SMK_OTA_HEADER_1;
    output[2] = SMK_OTA_OP_REQUEST;
    /* Payload is the 8 header bytes only: this is the header-only request
     * form that src/protocol.c smk37_parse_ota_request() accepts. */
    output[3] = SMK_OTA_HEADER_PAYLOAD_SIZE;
    output[4] = 0;
    output[5] = 0;
    output[6] = flash_type;
    output[7] = (uint8_t)address;
    output[8] = (uint8_t)(address >> 8);
    output[9] = (uint8_t)(address >> 16);
    output[10] = (uint8_t)(address >> 24);
    output[11] = (uint8_t)length;
    output[12] = (uint8_t)(length >> 8);
    output[13] = (uint8_t)(length >> 16);
    output[14] = smk_ota_complement_checksum(output + 6, 8);
    return SMK_OTA_REQUEST_PACKET_SIZE;
}

int smk_ota_parse_response(const uint8_t *packet, size_t packet_length,
                           struct smk_ota_response *response) {
    uint32_t payload_length;
    uint32_t data_length;

    if (packet == 0 || response == 0) {
        return 1;
    }
    if (packet_length < SMK_OTA_REQUEST_PACKET_SIZE ||
        packet[0] != SMK_OTA_HEADER_0 || packet[1] != SMK_OTA_HEADER_1 ||
        packet[2] != SMK_OTA_OP_REQUEST) {
        return 1;
    }

    payload_length = (uint32_t)packet[3] | ((uint32_t)packet[4] << 8) |
                     ((uint32_t)packet[5] << 16);
    data_length = (uint32_t)packet[11] | ((uint32_t)packet[12] << 8) |
                  ((uint32_t)packet[13] << 16);

    if (payload_length != data_length + SMK_OTA_HEADER_PAYLOAD_SIZE) {
        return 1;
    }
    if ((size_t)data_length + SMK_OTA_REQUEST_PACKET_SIZE != packet_length) {
        return 1;
    }
    if (smk_ota_complement_checksum(packet + 6, (size_t)data_length + 8) !=
        packet[packet_length - 1]) {
        return 1;
    }

    response->flash_type = packet[6];
    response->address = (uint32_t)packet[7] | ((uint32_t)packet[8] << 8) |
                        ((uint32_t)packet[9] << 16) |
                        ((uint32_t)packet[10] << 24);
    response->length = data_length;
    response->data = packet + 14;
    return 0;
}

/* ---------------------------------------------------------------------------
 * Self-check. Vectors are the ones already asserted by src/protocol.c's own
 * self-test plus the completion response shape used by src/ota.c, so a passing
 * device-side build is checked against the project's existing expectations.
 * ------------------------------------------------------------------------- */
int smk_ota_transport_self_test(void) {
    static const uint8_t query[] = {0x00, 0x59, 0x11, 0x00, 0x00, 0x00, 0xff};
    static const uint8_t expected_request[] = {
        0x00, 0x59, 0x30, 0x08, 0x00, 0x00, 0x01, 0x78,
        0x56, 0x34, 0x12, 0xf1, 0x03, 0x00, 0xf6,
    };
    static const uint8_t expected_response[] = {
        0x00, 0x59, 0x30, 0x0b, 0x00, 0x00, 0x00, 0x78, 0x56,
        0x34, 0x12, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x4c,
    };
    static const uint8_t success_response[] = {
        0x00, 0x59, 0x30, 0x10, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xf0, 0x08, 0x00, 0x00,
        0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x00, 0x0e,
    };
    uint8_t request[SMK_OTA_REQUEST_PACKET_SIZE];
    uint8_t framed[64];
    uint8_t packets[64];
    uint8_t stream[64];
    uint8_t binary[64];
    struct smk_ota_response response;
    size_t framed_length;
    size_t packet_length;
    size_t stream_length;
    size_t binary_length;

    if (smk_ota_complement_checksum(query + 6, 0) != 0xff) {
        return 1;
    }

    if (smk_ota_build_request(1, 0x12345678u, 1009u, request,
                              sizeof(request)) != sizeof(expected_request) ||
        !smk_ota_bytes_equal(request, expected_request,
                             sizeof(expected_request))) {
        return 1;
    }

    if (smk_ota_parse_response(expected_response, sizeof(expected_response),
                               &response) != 0 ||
        response.flash_type != 0 || response.address != 0x12345678u ||
        response.length != 3u || response.data[0] != 0x12u ||
        response.data[1] != 0x34u || response.data[2] != 0x56u) {
        return 1;
    }

    /* Completion acknowledgement shape from src/ota.c make_and_send_response. */
    if (smk_ota_parse_response(success_response, sizeof(success_response),
                               &response) != 0 ||
        response.address != SMK_OTA_UPGRADE_COMPLETE || response.length != 8u ||
        response.data[0] != 's' || response.data[7] != 0x00u) {
        return 1;
    }

    /* Corrupt checksum must be rejected. */
    {
        uint8_t corrupt[sizeof(expected_response)];
        smk_ota_copy(corrupt, expected_response, sizeof(expected_response));
        corrupt[sizeof(corrupt) - 1] ^= 0x01u;
        if (smk_ota_parse_response(corrupt, sizeof(corrupt), &response) == 0) {
            return 1;
        }
    }

    /* Whole device->host wire path: request -> frame -> packets -> back. */
    framed_length = smk_ota_frame_binary(request, sizeof(request), framed,
                                         sizeof(framed));
    if (framed_length == 0) {
        return 1;
    }
    packet_length = smk_ota_usb_packetize(framed, framed_length, packets,
                                          sizeof(packets));
    if (packet_length == 0) {
        return 1;
    }
    stream_length = smk_ota_usb_unpacketize(packets, packet_length, stream,
                                            sizeof(stream));
    if (stream_length != framed_length ||
        !smk_ota_bytes_equal(stream, framed, framed_length)) {
        return 1;
    }
    binary_length = smk_ota_unframe_binary(stream, stream_length, binary,
                                           sizeof(binary));
    if (binary_length != sizeof(request) ||
        !smk_ota_bytes_equal(binary, request, sizeof(request))) {
        return 1;
    }

    return 0;
}
