#ifndef SMK_OTA_TRANSPORT_H
#define SMK_OTA_TRANSPORT_H

/*
 * Device-side SMK-37 Pro OTA transport + packet layer.
 *
 * Why this file exists
 * --------------------
 * docs/self-recovering-sdk-app.md section 4 defines the first increment of the
 * from-scratch platform as the SDK application that re-implements the SMK
 * update path, and section 6 designates the host-side implementation in
 * src/protocol.c as "the reference for the device-side mirror". Section 3.3
 * records that the stage-1 half of the protocol (the 48-request verification,
 * the 0xE0000000 hand-off) is performed by the running application, i.e. it is
 * exactly the part that a replacement application must carry.
 *
 * This translation unit is that mirror. It is the packet/transport half only:
 * it can encode the requests the device sends and decode the responses it
 * receives, and it does no flash access, no USB access and no session policy
 * (those are stage B3 and are deliberately not here).
 *
 * Byte-compatibility is the whole point, so the shared functions implement
 * exactly the semantics of their src/protocol.c counterparts and are
 * differentially tested against them by ac79/test/host_compat_test.c.
 *
 * No libc dependency beyond fixed-width types: suitable for the SDK toolchain
 * (-target pi32v2) where the device side cannot use malloc or stdio.
 */

#include <stddef.h>
#include <stdint.h>

/* Wire constants, all taken from src/protocol.c / docs/self-recovering-sdk-app.md 3.2 */
#define SMK_OTA_STREAM_START 0xf0u
#define SMK_OTA_STREAM_END 0xf7u
#define SMK_OTA_HEADER_0 0x00u
#define SMK_OTA_HEADER_1 0x59u
#define SMK_OTA_OP_QUERY 0x11u
#define SMK_OTA_OP_READ_REQUEST 0x23u
#define SMK_OTA_OP_REQUEST 0x30u
#define SMK_OTA_REQUEST_PACKET_SIZE 15u
#define SMK_OTA_HEADER_PAYLOAD_SIZE 8u

/* Completion sentinels the device raises (src/ota.c serve_ota_stage). */
#define SMK_OTA_VERIFY_COMPLETE 0xe0000000u
#define SMK_OTA_UPGRADE_COMPLETE 0xf0000000u

struct smk_ota_request {
    uint8_t flash_type;
    uint32_t address;
    uint32_t length;
};

struct smk_ota_response {
    uint8_t flash_type;
    uint32_t address;
    uint32_t length;
    const uint8_t *data; /* points into the caller's packet buffer */
};

/* --- shared with src/protocol.c: identical semantics --- */
size_t smk_ota_pack_8_to_7(const uint8_t *input, size_t input_length,
                           uint8_t *output, size_t output_capacity);
size_t smk_ota_unpack_7_to_8(const uint8_t *input, size_t input_length,
                             uint8_t *output, size_t output_capacity);
size_t smk_ota_frame_binary(const uint8_t *input, size_t input_length,
                            uint8_t *output, size_t output_capacity);
size_t smk_ota_usb_packetize(const uint8_t *stream, size_t stream_length,
                             uint8_t *output, size_t output_capacity);
size_t smk_ota_usb_unpacketize(const uint8_t *packets, size_t packet_length,
                               uint8_t *output, size_t output_capacity);
uint8_t smk_ota_complement_checksum(const uint8_t *input, size_t input_length);

/* --- device-side receive path (mirrors the inline logic in src/ota.c) --- */
size_t smk_ota_unframe_binary(const uint8_t *stream, size_t stream_length,
                              uint8_t *binary, size_t binary_capacity);

/* --- device-side request encoder: inverse of src/protocol.c parse_ota_request --- */
size_t smk_ota_build_request(uint8_t flash_type, uint32_t address,
                             uint32_t length, uint8_t *output,
                             size_t output_capacity);

/* --- device-side response decoder: inverse of src/protocol.c make_flash_update_packet --- */
int smk_ota_parse_response(const uint8_t *packet, size_t packet_length,
                           struct smk_ota_response *response);

/* Self-check with the reference's own vectors; returns 0 on success. */
int smk_ota_transport_self_test(void);

#endif
