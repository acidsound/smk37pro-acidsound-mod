#ifndef SMK37_PROTOCOL_H
#define SMK37_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

struct smk37_ota_request {
    uint8_t flash_type;
    uint32_t address;
    uint32_t length;
};

size_t smk37_pack_8_to_7(const uint8_t *input, size_t input_length,
                         uint8_t *output, size_t output_capacity);
size_t smk37_unpack_7_to_8(const uint8_t *input, size_t input_length,
                           uint8_t *output, size_t output_capacity);
size_t smk37_frame_binary(const uint8_t *input, size_t input_length,
                          uint8_t *output, size_t output_capacity);
size_t smk37_usb_packetize(const uint8_t *stream, size_t stream_length,
                           uint8_t *output, size_t output_capacity);
size_t smk37_usb_unpacketize(const uint8_t *packets, size_t packet_length,
                             uint8_t *output, size_t output_capacity);
uint8_t smk37_complement_checksum(const uint8_t *input, size_t input_length);
size_t smk37_make_flash_read_request(uint8_t flash_type, uint32_t address,
                                     uint32_t length, uint8_t *output,
                                     size_t output_capacity);
size_t smk37_make_flash_update_packet(uint8_t flash_type, uint32_t address,
                                      const uint8_t *data, uint32_t length,
                                      uint8_t *output,
                                      size_t output_capacity);
int smk37_parse_ota_request(const uint8_t *packet, size_t packet_length,
                            struct smk37_ota_request *request);
int smk37_protocol_self_test(void);

#endif
