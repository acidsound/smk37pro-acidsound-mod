/*
 * B1 host check for the device-side USB descriptor evidence set
 * (ac79/app/smk_usb_descriptors.c).
 *
 * Four things are checked, each against its own source:
 *
 *   1. RECOVERED BYTES AND TEXT. The 18-byte updater device descriptor must equal
 *      the dump's bytes at flash 0x0BDDE5, byte for byte, in every whole-flash
 *      1 MiB image given that carries the identity at 0x0BDDED exactly once. An
 *      image without the identity is the pre-restore negative control. The same
 *      image is sliced at flash 0x0B9000..0x0BDE01 (the vendor package's ota.bin
 *      entry, usb_hid_ota.bin) and searched in WIRE FORMAT: the descriptor must be
 *      0x4DE5 into that image, and the image must contain NO configuration chain,
 *      NO plausible interface record, NO endpoint record, NO MS header and NO
 *      CS_ENDPOINT record - which is how the claim that the updater's
 *      configuration is genuinely absent there is checked rather than asserted.
 *      The recovered 40-byte product-name text at image offset 0x2558 must equal
 *      the app's copy byte for byte.
 *
 *   2. RECORDED FACTS. Every field of the MIDIStreaming interface fragment is
 *      pinned by a source: the live enumeration record
 *      (docs/research-notes.md) for the update-mode interface number and the
 *      endpoint addresses, the probe (baselines/v15/device-info/probe.txt) for
 *      the endpoint count, class, subclass, alternate setting, transfer type,
 *      packet size and interval, and the USB MIDI 1.0 definition for the
 *      descriptor shapes. This test RE-DERIVES those values from the two
 *      documents themselves, so the check is against the record, not against a
 *      restatement of it. If a document is missing the check says so.
 *
 *   3. DECLARED SILENCE. No fragment byte may be set without evidence: each byte
 *      must be either inside a fact (checked in 2) or named in the unrecovered
 *      list. The configuration descriptor is withheld on purpose, and this test
 *      fails if the lookup ever serves one.
 *
 * Usage: usb_descriptor_test [whole-flash-1MiB-dump.bin ...]
 *   exit 0 = every check that could run passed (the mode is printed)
 *   exit 1 = a check failed
 *   exit 2 = usage or I/O problem, or a supplied dump is not a whole-flash image
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha256.h"              /* this repo's src/sha256.c */
#include "smk_usb_descriptors.h" /* device side (ac79/app/) */

/* Transcription of the recovered descriptor, kept here independently of the
 * device translation unit so an accidental edit in ac79/app/ is caught. */
static const uint8_t transcribed_device_descriptor[SMK_USB_DEVICE_DESCRIPTOR_SIZE] = {
    0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40,
    0x4a, 0x4d, 0x55, 0x41, 0x00, 0x01, 0x01, 0x02, 0x00, 0x01,
};

static const uint8_t updater_identity[4] = {0x4a, 0x4d, 0x55, 0x41};

/* Transcription of the recovered product-name text (UTF-16LE), kept here
 * independently of the device translation unit. */
static const uint8_t transcribed_product_name[SMK_USB_UPDATER_PRODUCT_NAME_SIZE] = {
    0x55, 0x00, 0x53, 0x00, 0x42, 0x00, 0x20, 0x00,
    0x43, 0x00, 0x6f, 0x00, 0x6d, 0x00, 0x70, 0x00,
    0x6f, 0x00, 0x73, 0x00, 0x69, 0x00, 0x74, 0x00,
    0x65, 0x00, 0x20, 0x00, 0x44, 0x00, 0x65, 0x00,
    0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00,
};

static const char recorded_product_name[] = "USB Composite Device";

/* The bytes that immediately follow the recovered descriptor, and the 0xFF fill
 * that follows them; both measured from the dumps. */
static const uint8_t site_trailer[10] = {
    0x01, 0x04, 0xf0, 0x22, 0x24, 0x07, 0x35, 0x7d, 0xf7, 0x00,
};
static const char site_marker[] = "/*.ufw";
#define WHOLE_FLASH_SIZE 0x100000u

static const char *const recorded_hashes[] = {
    SMK_USB_DUMP_SHA256_M10,
    SMK_USB_DUMP_SHA256_POST_RESTORE,
    "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b", /* v15-clean-baseline-a */
    "ba1b40a0b4b6234b384b1d812e851c659ded292b57ac55bfee4e04d8489cb1fa", /* pre-restore, no identity */
};

static unsigned checks;
static unsigned failures;

static void check(int ok, const char *what) {
    ++checks;
    if (!ok) {
        ++failures;
        printf("FAIL %s\n", what);
        fflush(stdout);
    }
}

static void print_hex(const char *label, const uint8_t *bytes, size_t length) {
    size_t index;

    printf("  %-34s", label);
    for (index = 0; index < length; ++index) {
        printf("%02x", bytes[index]);
        if (index + 1 != length) {
            printf(" ");
        }
    }
    printf("\n");
}

static uint32_t read_le(const uint8_t *bytes, size_t offset, size_t width) {
    uint32_t value = 0;
    size_t index;

    for (index = 0; index < width; ++index) {
        value |= (uint32_t)bytes[offset + index] << (8u * index);
    }
    return value;
}

static size_t count_pattern(const uint8_t *haystack, size_t length,
                            const uint8_t *pattern, size_t pattern_length) {
    size_t count = 0;
    size_t index;

    if (pattern_length == 0 || pattern_length > length) {
        return 0;
    }
    for (index = 0; index + pattern_length <= length; ++index) {
        if (memcmp(haystack + index, pattern, pattern_length) == 0) {
            ++count;
        }
    }
    return count;
}

/* Count MIDIStreaming class-specific headers structurally: any descriptor whose
 * bDescriptorType is CS_INTERFACE and whose bDescriptorSubtype is MS_HEADER.
 * (An earlier revision searched for the four bytes 07 24 06 01, which can never
 * match a real header, because bcdADC is 0x0100 and the bytes are 07 24 06 00 01..) */
static size_t count_ms_headers(const uint8_t *buffer, size_t length) {
    size_t count = 0;
    size_t index;

    for (index = 0; index + 3 <= length; ++index) {
        if (buffer[index] >= 2 && buffer[index + 1] == SMK_USB_CS_INTERFACE &&
            buffer[index + 2] == SMK_USB_CS_MS_HEADER) {
            ++count;
        }
    }
    return count;
}

/* Count endpoint descriptors structurally, optionally for one address. */
static size_t count_endpoints(const uint8_t *buffer, size_t length, int address) {
    size_t count = 0;
    size_t index;

    for (index = 0; index + 3 <= length; ++index) {
        if (buffer[index] >= 2 && buffer[index + 1] == SMK_USB_DT_ENDPOINT) {
            if (address < 0 || buffer[index + 2] == (uint8_t)address) {
                ++count;
            }
        }
    }
    return count;
}

/* A configuration descriptor only counts if the chain following it is well formed
 * and sums exactly to its wTotalLength, with at least one interface. */
static size_t count_config_chains(const uint8_t *buffer, size_t length) {
    size_t start;
    size_t chains = 0;

    for (start = 0; start + 10 < length; ++start) {
        size_t total;
        size_t offset;
        int interfaces = 0;
        int ok = 1;

        if (buffer[start] != 9 || buffer[start + 1] != SMK_USB_DT_CONFIG) {
            continue;
        }
        total = (size_t)buffer[start + 2] | ((size_t)buffer[start + 3] << 8);
        if (total < 9 || total > 512 || start + total > length) {
            continue;
        }
        offset = start;
        while (offset < start + total) {
            uint8_t descriptor_length = buffer[offset];
            uint8_t descriptor_type = buffer[offset + 1];

            if (descriptor_length < 2 || offset + descriptor_length > start + total) {
                ok = 0;
                break;
            }
            if (descriptor_type == SMK_USB_DT_INTERFACE) {
                ++interfaces;
            } else if (descriptor_type != SMK_USB_DT_CONFIG &&
                       descriptor_type != SMK_USB_DT_ENDPOINT &&
                       !(descriptor_type >= 0x20 && descriptor_type <= 0x2f)) {
                ok = 0;
                break;
            }
            offset += descriptor_length;
        }
        if (ok && offset == start + total && interfaces > 0) {
            ++chains;
        }
    }
    return chains;
}

/* ---------------------------------------------------------------------------
 * 1b. the updater image the site is the tail of, searched in wire format
 *
 * The corridor-wide scans the reconciliation used are weaker than searching the
 * one image that actually carries the site. This slices it out of the dump and
 * looks, in wire format, for the configuration/interface/endpoint records the
 * project does not have. The answers are asserted, so "the chain is genuinely
 * absent there" is a checked claim rather than a sentence.
 * ------------------------------------------------------------------------- */
static void check_updater_image(const uint8_t *dump, const uint8_t *served,
                                size_t served_size) {
    const uint8_t *image = dump + SMK_USB_UPDATER_IMAGE_FLASH_OFFSET;
    const size_t image_size = SMK_USB_UPDATER_IMAGE_SIZE;
    static const uint8_t ms_header_ms[3] = {0x07, 0x24, 0x01};
    static const uint8_t ms_header_uac[3] = {0x07, 0x24, 0x06};
    static const uint8_t cs_endpoint[2] = {0x07, 0x25};
    static const char image_name[] = "usb_hid_ota.bin";
    size_t plausible_interfaces = 0;
    size_t endpoint_records = 0;
    size_t index;

    printf("  updater image: flash 0x%05X..0x%05X (%u B), searched in wire format\n",
           (unsigned)SMK_USB_UPDATER_IMAGE_FLASH_OFFSET,
           (unsigned)(SMK_USB_UPDATER_IMAGE_FLASH_OFFSET + image_size),
           (unsigned)image_size);

    check(memcmp(image + SMK_USB_UPDATER_DESCRIPTOR_IN_IMAGE, served, served_size) == 0,
          "the site descriptor sits 0x4DE5 into the updater image");
    check(count_pattern(image, image_size, (const uint8_t *)image_name,
                        sizeof(image_name) - 1) >= 1,
          "the updater image names itself usb_hid_ota.bin");

    /* Interface records with fields in range; raw (9, 4) byte pairs are not
     * interfaces and are not counted here. */
    for (index = 0; index + 9 <= image_size; ++index) {
        if (image[index] == 9u && image[index + 1] == SMK_USB_DT_INTERFACE &&
            image[index + 2] <= 31u && image[index + 3] <= 8u && image[index + 4] <= 8u) {
            ++plausible_interfaces;
        }
    }
    /* Endpoint records with a legal shape: bLength 7, bDescriptorType 5 and
     * bmAttributes one of control/iso/bulk/interrupt. Loose (>=2, 5) pairs are
     * reported by the dump's informational scan, not asserted here. */
    for (index = 0; index + 7 <= image_size; ++index) {
        if (image[index] == 7u && image[index + 1] == SMK_USB_DT_ENDPOINT &&
            image[index + 3] <= 3u) {
            ++endpoint_records;
        }
    }
    check(count_config_chains(image, image_size) == 0,
          "no config descriptor chain exists inside the updater image");
    check(plausible_interfaces == 0,
          "no plausible interface descriptor exists inside the updater image");
    check(endpoint_records == 0,
          "no endpoint descriptor exists inside the updater image");
    check(count_pattern(image, image_size, ms_header_ms, sizeof(ms_header_ms)) == 0 &&
              count_pattern(image, image_size, ms_header_uac, sizeof(ms_header_uac)) == 0,
          "no MIDIStreaming MS header exists inside the updater image");
    check(count_pattern(image, image_size, cs_endpoint, sizeof(cs_endpoint)) == 0,
          "no CS_ENDPOINT record exists inside the updater image");

    /* The recovered product-name text, byte for byte, and the 2 bytes that
     * precede it in the image. */
    check(memcmp(image + SMK_USB_UPDATER_PRODUCT_NAME_IMAGE_OFFSET,
                 transcribed_product_name, SMK_USB_UPDATER_PRODUCT_NAME_SIZE) == 0,
          "the product-name text == the updater image at image offset 0x2558");
    check(memcmp(image + SMK_USB_UPDATER_PRODUCT_NAME_IMAGE_OFFSET,
                 smk_usb_updater_product_name(), SMK_USB_UPDATER_PRODUCT_NAME_SIZE) == 0,
          "the app's recovered product-name text == the updater image bytes");
    check(image[SMK_USB_UPDATER_PRODUCT_NAME_IMAGE_OFFSET - 2] == 0x2au &&
              image[SMK_USB_UPDATER_PRODUCT_NAME_IMAGE_OFFSET - 1] == 0x03u,
          "the 2 bytes before the product-name text are 2a 03 (observed, not interpreted)");
}

/* ---------------------------------------------------------------------------
 * 2. the fact ledger, evaluated against the fragment
 * ------------------------------------------------------------------------- */
static void check_fact_ledger(const uint8_t *fragment, size_t fragment_size) {
    size_t fact_count = 0;
    size_t unrecovered_count = 0;
    const struct smk_usb_fact *facts = smk_usb_facts(&fact_count);
    const struct smk_usb_unrecovered *unrecovered = smk_usb_unrecovered(&unrecovered_count);
    char message[256];
    uint8_t covered[64];
    size_t index;

    printf("\n=== evidence ledger for the %zu-byte MIDIStreaming fragment ===\n",
           fragment_size);
    check(facts != 0 && fact_count > 0, "a fact table is exported");
    check(unrecovered != 0 && unrecovered_count > 0, "an unrecovered list is exported");
    if (facts == 0 || unrecovered == 0) {
        return;
    }

    printf("  %-30s %-6s %-6s %-8s %s\n", "field", "offset", "width", "value", "source");
    for (index = 0; index < fact_count; ++index) {
        uint32_t observed;
        int in_range = (size_t)facts[index].offset + facts[index].width <= fragment_size &&
                       facts[index].width >= 1u && facts[index].width <= 4u;

        printf("  %-30s %-6u %-6u ", facts[index].field, (unsigned)facts[index].offset,
               (unsigned)facts[index].width);
        if (facts[index].width == 1u) {
            printf("0x%02X     ", facts[index].value);
        } else {
            printf("0x%04X   ", facts[index].value);
        }
        printf("%s\n", smk_usb_source_name(facts[index].source));

        snprintf(message, sizeof(message), "fact %s lies inside the fragment",
                 facts[index].field);
        check(in_range, message);
        if (!in_range) {
            continue;
        }
        observed = read_le(fragment, facts[index].offset, facts[index].width);
        snprintf(message, sizeof(message),
                 "fact %s holds 0x%X (fragment has 0x%X, from %s)", facts[index].field,
                 facts[index].value, observed, smk_usb_source_name(facts[index].source));
        check(observed == facts[index].value, message);
    }

    /* No fragment byte may be silent: each is pinned by a fact or declared. */
    if (fragment_size <= sizeof(covered)) {
        memset(covered, 0, sizeof(covered));
        for (index = 0; index < fact_count; ++index) {
            size_t byte_index;
            for (byte_index = 0; byte_index < facts[index].width; ++byte_index) {
                size_t at = (size_t)facts[index].offset + byte_index;
                if (at < fragment_size) {
                    covered[at] = 1;
                }
            }
        }
        for (index = 0; index < unrecovered_count; ++index) {
            if (unrecovered[index].offset >= 0) {
                covered[(unsigned)unrecovered[index].offset] = 1;
            }
        }
        for (index = 0; index < fragment_size; ++index) {
            snprintf(message, sizeof(message),
                     "fragment byte %u is evidence-pinned or explicitly declared unrecovered",
                     (unsigned)index);
            check(covered[index] == 1u, message);
        }
    }

    printf("  declared unrecovered (never silently filled in):\n");
    for (index = 0; index < unrecovered_count; ++index) {
        if (unrecovered[index].offset >= 0) {
            printf("    [fragment byte %d] %s\n", (int)unrecovered[index].offset,
                   unrecovered[index].item);
        } else {
            printf("    %s\n", unrecovered[index].item);
        }
    }
}

/* ---------------------------------------------------------------------------
 * 3. re-derive the pinned facts from the two evidence documents
 * ------------------------------------------------------------------------- */
static int find_fact(const struct smk_usb_fact *facts, size_t fact_count,
                     const char *field, uint32_t *value) {
    size_t index;

    for (index = 0; index < fact_count; ++index) {
        if (strcmp(facts[index].field, field) == 0) {
            *value = facts[index].value;
            return 0;
        }
    }
    return -1;
}

static void check_evidence_documents(void) {
    const char *root = getenv("SMK_REPO_ROOT");
    char probe_path[512];
    char notes_path[512];
    FILE *file;
    char line[1024];
    size_t fact_count = 0;
    const struct smk_usb_fact *facts = smk_usb_facts(&fact_count);
    char message[256];
    int probe_checked = 0;
    int notes_checked = 0;
    uint32_t value;

    if (root == 0) {
        root = ".";
    }
    snprintf(probe_path, sizeof(probe_path), "%s/baselines/v15/device-info/probe.txt", root);
    snprintf(notes_path, sizeof(notes_path), "%s/docs/research-notes.md", root);

    printf("\n=== re-derived from the record ===\n");

    /* --- probe.txt: the MIDIStreaming interface and its two bulk endpoints --- */
    file = fopen(probe_path, "r");
    if (file == 0) {
        /* Fail closed: without its evidence a PASS would be worthless. An earlier
         * revision reported the missing file and still exited 0. */
        snprintf(message, sizeof(message),
                 "probe.txt is required evidence and is present at %s", probe_path);
        check(0, message);
        printf("  probe.txt not found at %s: document check FAILED (fail-closed)\n",
               probe_path);
    } else {
        unsigned midi_lines = 0;
        unsigned midi_interface_number = 0;
        unsigned midi_alt = 0;
        unsigned midi_class = 0;
        unsigned midi_subclass = 0;
        unsigned midi_endpoints = 0;
        unsigned bulk_lines = 0;
        unsigned bulk_out = 0;
        unsigned bulk_in = 0;

        printf("  %s\n", probe_path);
        while (fgets(line, sizeof(line), file) != 0) {
            unsigned iface = 0;
            unsigned alt = 0;
            unsigned klass = 0;
            unsigned subclass = 0;
            unsigned endpoints = 0;
            unsigned number = 0;
            unsigned max_packet = 0;
            unsigned interval = 0;
            char direction[8] = {0};

            /* e.g. "    interface 4 alt 0: class 0x01 subclass 0x03, 2 endpoints".
             * Only the MIDIStreaming subclass counts; the probe also lists four
             * UAC interface lines with other subclasses. */
            if (sscanf(line, " interface %u alt %u: class 0x%2x subclass 0x%2x, %u endpoints",
                       &iface, &alt, &klass, &subclass, &endpoints) == 5) {
                if (subclass == 0x03u) {
                    ++midi_lines;
                    midi_interface_number = iface;
                    midi_alt = alt;
                    midi_class = klass;
                    midi_subclass = subclass;
                    midi_endpoints = endpoints;
                }
                continue;
            }
            /* e.g. "      endpoint 0x84 IN bulk        max-packet 64 interval 0" */
            if (sscanf(line, " endpoint 0x%2x %7s bulk max-packet %u interval %u",
                       &number, direction, &max_packet, &interval) == 4) {
                const char *address_field = (number == 0x84u) ? "ep_0x84.bEndpointAddress"
                                                             : "ep_0x04.bEndpointAddress";
                const char *packet_field = (number == 0x84u) ? "ep_0x84.wMaxPacketSize"
                                                            : "ep_0x04.wMaxPacketSize";
                const char *interval_field = (number == 0x84u) ? "ep_0x84.bInterval"
                                                              : "ep_0x04.bInterval";
                const char *attr_field = (number == 0x84u) ? "ep_0x84.bmAttributes"
                                                          : "ep_0x04.bmAttributes";

                ++bulk_lines;
                if (number == 0x84u) {
                    ++bulk_in;
                }
                if (number == 0x04u) {
                    ++bulk_out;
                }
                if (find_fact(facts, fact_count, address_field, &value) == 0) {
                    snprintf(message, sizeof(message),
                             "probe lists endpoint 0x%02X (%s) and the ledger address is 0x%02X",
                             number, direction, value);
                    check(value == number, message);
                }
                if (find_fact(facts, fact_count, packet_field, &value) == 0) {
                    snprintf(message, sizeof(message),
                             "probe says endpoint 0x%02X max-packet %u and the ledger says %u",
                             number, max_packet, value);
                    check(value == max_packet, message);
                }
                if (find_fact(facts, fact_count, interval_field, &value) == 0) {
                    snprintf(message, sizeof(message),
                             "probe says endpoint 0x%02X interval %u and the ledger says %u",
                             number, interval, value);
                    check(value == interval, message);
                }
                if (find_fact(facts, fact_count, attr_field, &value) == 0) {
                    snprintf(message, sizeof(message),
                             "probe says endpoint 0x%02X is bulk (0x02) and the ledger says 0x%02X",
                             number, value);
                    check(value == 0x02u, message);
                }
            }
        }
        fclose(file);

        check(midi_lines == 1,
              "the probe lists exactly one MIDIStreaming interface line (so it has one "
              "alternate setting, 0)");
        check(midi_alt == 0, "the probe's MIDIStreaming interface is at alt 0");
        check(bulk_lines == 2 && bulk_in == 1 && bulk_out == 1,
              "the probe lists exactly two bulk endpoints, one IN and one OUT");
        if (find_fact(facts, fact_count, "bAlternateSetting", &value) == 0) {
            snprintf(message, sizeof(message),
                     "probe's MIDIStreaming alternate setting %u matches ledger %u",
                     midi_alt, value);
            check(value == midi_alt, message);
        }
        if (find_fact(facts, fact_count, "bInterfaceClass", &value) == 0) {
            snprintf(message, sizeof(message),
                     "probe class 0x%02X matches ledger 0x%02X", midi_class, value);
            check(value == midi_class && midi_class == 0x01u, message);
        }
        if (find_fact(facts, fact_count, "bInterfaceSubClass", &value) == 0) {
            snprintf(message, sizeof(message),
                     "probe subclass 0x%02X matches ledger 0x%02X", midi_subclass, value);
            check(value == midi_subclass && midi_subclass == 0x03u, message);
        }
        if (find_fact(facts, fact_count, "bNumEndpoints", &value) == 0) {
            snprintf(message, sizeof(message),
                     "probe says the MIDIStreaming interface has %u endpoints; ledger says %u",
                     midi_endpoints, value);
            check(value == midi_endpoints, message);
        }
        printf("    probe: MIDIStreaming at interface %u alt %u, class 0x%02X/0x%02X, %u endpoints\n",
               midi_interface_number, midi_alt, midi_class, midi_subclass, midi_endpoints);
        probe_checked = 1;
    }

    /* --- research-notes.md: the update-mode interface number and endpoints --- */
    file = fopen(notes_path, "r");
    if (file == 0) {
        snprintf(message, sizeof(message),
                 "research-notes.md is required evidence and is present at %s", notes_path);
        check(0, message);
        printf("  research-notes.md not found at %s: document check FAILED (fail-closed)\n",
               notes_path);
    } else {
        int interface_number = -1;
        int composite_seen = 0;
        unsigned out_address = 0;
        unsigned in_address = 0;

        printf("  %s\n", notes_path);
        while (fgets(line, sizeof(line), file) != 0) {
            if (strstr(line, "MIDI Streaming interface") != 0) {
                const char *marker = strstr(line, "interface");
                while (marker != 0 && *marker != 0 &&
                       !(*marker >= '0' && *marker <= '9')) {
                    ++marker;
                }
                if (marker != 0 && *marker >= '0' && *marker <= '9') {
                    interface_number = atoi(marker);
                }
            }
            if (strstr(line, "USB Composite Device") != 0) {
                composite_seen = 1;
                /* The recovered product-name text must decode to exactly the name
                 * the record gives. This ties the bytes found inside the updater
                 * image to the document that names the updater's product. */
                {
                    const uint8_t *text = smk_usb_updater_product_name();
                    size_t text_size = smk_usb_updater_product_name_size();
                    char decoded[128];
                    size_t decoded_length = 0;
                    size_t text_index;
                    int ascii = 1;

                    if (text_size / 2 >= sizeof(decoded)) {
                        ascii = 0;
                    } else {
                        for (text_index = 0; text_index + 1 < text_size; text_index += 2) {
                            if (text[text_index + 1] != 0) {
                                ascii = 0;
                                break;
                            }
                            decoded[decoded_length++] = (char)text[text_index];
                        }
                        decoded[decoded_length] = '\0';
                    }
                    check(ascii && strcmp(decoded, recorded_product_name) == 0,
                          "the recovered product-name text decodes to the name the record gives");
                }
            }
            if (strstr(line, "bulk endpoints remain") != 0) {
                if (sscanf(line, " %*[^0]0x%2x OUT and 0x%2x IN", &out_address, &in_address) != 2) {
                    /* tolerate other wordings: scan for the two hex numbers */
                    const char *scan = strstr(line, "0x");
                    if (scan != 0) {
                        out_address = (unsigned)strtoul(scan + 2, 0, 16);
                        scan = strstr(scan + 2, "0x");
                        if (scan != 0) {
                            in_address = (unsigned)strtoul(scan + 2, 0, 16);
                        }
                    }
                }
            }
        }
        fclose(file);

        if (interface_number >= 0) {
            if (find_fact(facts, fact_count, "bInterfaceNumber", &value) == 0) {
                snprintf(message, sizeof(message),
                         "research-notes says update mode exposes MIDI Streaming interface %d; ledger says %u",
                         interface_number, value);
                check(value == (uint32_t)interface_number, message);
            }
        } else {
            printf("    note: no update-mode interface number found in the record\n");
        }
        if (out_address != 0 && in_address != 0) {
            if (find_fact(facts, fact_count, "ep_0x04.bEndpointAddress", &value) == 0) {
                snprintf(message, sizeof(message),
                         "research-notes says the OUT endpoint remains 0x%02X; ledger says 0x%02X",
                         out_address, value);
                check(value == out_address, message);
            }
            if (find_fact(facts, fact_count, "ep_0x84.bEndpointAddress", &value) == 0) {
                snprintf(message, sizeof(message),
                         "research-notes says the IN endpoint remains 0x%02X; ledger says 0x%02X",
                         in_address, value);
                check(value == in_address, message);
            }
        } else {
            printf("    note: no endpoint addresses found in the record\n");
        }
        if (composite_seen) {
            size_t unrecovered_count = 0;
            const struct smk_usb_unrecovered *unrecovered =
                smk_usb_unrecovered(&unrecovered_count);
            int named = 0;
            size_t index;
            for (index = 0; index < unrecovered_count; ++index) {
                if (strstr(unrecovered[index].item, "composite") != 0) {
                    named = 1;
                }
            }
            check(named,
                  "the record says the updater is a composite device, and the unrecovered "
                  "list names the composite configuration as unrecovered");
        }
        notes_checked = 1;
    }

    if (probe_checked == 0 || notes_checked == 0) {
        printf("  document checks run: probe=%d research-notes=%d (a missing file FAILS "
               "the run, fail-closed)\n", probe_checked, notes_checked);
    }
}

/* ---------------------------------------------------------------------------
 * 1. the recovered bytes, against real dumps
 * ------------------------------------------------------------------------- */
static int check_dump(const char *path, const uint8_t *served, size_t served_size) {
    FILE *file = fopen(path, "rb");
    long file_size = 0;
    uint8_t *dump = NULL;
    uint8_t digest[SMK37_SHA256_LENGTH];
    char sha[SMK37_SHA256_LENGTH * 2 + 1];
    size_t index;
    size_t identity_hits;
    int recorded = 0;

    if (file == NULL) {
        fprintf(stderr, "cannot open %s\n", path);
        return 2;
    }
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    if (file_size <= 0) {
        fclose(file);
        fprintf(stderr, "cannot size %s\n", path);
        return 2;
    }
    dump = (uint8_t *)malloc((size_t)file_size);
    if (dump == NULL || fread(dump, 1, (size_t)file_size, file) != (size_t)file_size) {
        fclose(file);
        free(dump);
        fprintf(stderr, "cannot read %s\n", path);
        return 2;
    }
    fclose(file);

    smk37_sha256(dump, (size_t)file_size, digest);
    for (index = 0; index < SMK37_SHA256_LENGTH; ++index) {
        sprintf(sha + index * 2, "%02x", digest[index]);
    }
    sha[SMK37_SHA256_LENGTH * 2] = '\0';
    for (index = 0; index < sizeof(recorded_hashes) / sizeof(recorded_hashes[0]); ++index) {
        if (strcmp(sha, recorded_hashes[index]) == 0) {
            recorded = 1;
        }
    }

    printf("\n=== dump: %s ===\n", path);
    printf("  size %ld B, sha256 %s\n", file_size, sha);
    printf("  already in this project's record: %s\n", recorded ? "yes" : "no (new dump)");

    /* A dump this test cannot read the site from is a usage error, not a pass:
     * an earlier revision compared against the site without bounds checking and
     * crashed on a short file, and treated a truncated image as a negative
     * control with exit 0. */
    if ((size_t)file_size != WHOLE_FLASH_SIZE) {
        fprintf(stderr,
                "refusing %s: not a whole-flash 1 MiB image (%ld B). The descriptor site is "
                "at flash 0x0BDDE5, so a smaller image cannot be checked; pass the full "
                "1 MiB dump.\n", path, file_size);
        free(dump);
        return 2;
    }

    identity_hits = count_pattern(dump, (size_t)file_size, updater_identity, 4);
    printf("  updater identity 4d4a:4155 in this dump: %zu occurrence(s)\n", identity_hits);

    if (identity_hits == 1) {
        const uint8_t *at_offset = dump + SMK_USB_UPDATER_FLASH_OFFSET;
        const uint8_t *at_identity = dump + SMK_USB_UPDATER_IDENTITY_FLASH_OFFSET;
        size_t marker_at = (size_t)-1;
        size_t fill_start = SMK_USB_UPDATER_FLASH_OFFSET + served_size + sizeof(site_trailer);
        size_t fill_length = SMK_USB_SITE_FILL_END - fill_start;
        size_t ff_run = 0;
        size_t config_chains;
        size_t ms_hits;
        size_t ep04;
        size_t ep84;

        check(memcmp(at_identity, updater_identity, 4) == 0,
              "the single identity occurrence sits at flash 0x0BDDED");
        print_hex("  dump@0x0BDDE5:", at_offset, served_size);
        check(memcmp(at_offset, served, served_size) == 0,
              "GROUND TRUTH: the app's 18-byte device descriptor == the dump at 0x0BDDE5");

        for (index = SMK_USB_UPDATER_FLASH_OFFSET; index > 0; --index) {
            if (memcmp(dump + index - 1, site_marker, sizeof(site_marker) - 1) == 0) {
                marker_at = index - 1;
                break;
            }
        }
        check(marker_at + SMK_USB_SITE_MARKER_TO_DESCRIPTOR ==
                  SMK_USB_UPDATER_FLASH_OFFSET,
              "the descriptor sits 17 bytes into the package record opened by the "
              "2f 2a 2e 75 66 77 marker");
        check(memcmp(dump + SMK_USB_UPDATER_FLASH_OFFSET + served_size,
                     site_trailer, sizeof(site_trailer)) == 0,
              "the 10-byte site trailer follows the descriptor");
        for (index = fill_start; index < SMK_USB_SITE_FILL_END; ++index) {
            if (dump[index] == 0xff) {
                ++ff_run;
            }
        }
        {
            char message[128];
            snprintf(message, sizeof(message),
                     "the site is 0xFF-filled to the 4 KiB sector boundary 0x0BE000 (%zu B run)",
                     fill_length);
            check(ff_run == fill_length, message);
        }

        /* The absence searches. Two layers, because the two failure modes are
         * opposite: the contextual one (a chain that parses from a config
         * descriptor) cannot false-positive, and the specific-field ones catch a
         * fragment injected outside a chain. Loose single-byte-type scans are
         * reported but NOT asserted: in a 1 MiB firmware image a two-byte
         * coincidence has ~16 expected hits, so asserting on them would be
         * asserting on noise. */
        {
            static const uint8_t ms_header_full[5] = {0x07, 0x24, 0x06, 0x00, 0x01};
            static const uint8_t ep040[4] = {0x07, 0x05, 0x04, 0x02};
            static const uint8_t ep084[4] = {0x07, 0x05, 0x84, 0x02};
            size_t ms_full;
            size_t ep04_loose;
            size_t ep84_loose;

            config_chains = count_config_chains(dump, (size_t)file_size);
            ms_full = count_pattern(dump, (size_t)file_size, ms_header_full,
                                    sizeof(ms_header_full));
            ep04 = count_pattern(dump, (size_t)file_size, ep040, sizeof(ep040));
            ep84 = count_pattern(dump, (size_t)file_size, ep084, sizeof(ep084));
            ms_hits = count_ms_headers(dump, (size_t)file_size);
            ep04_loose = count_endpoints(dump, (size_t)file_size, 0x04);
            ep84_loose = count_endpoints(dump, (size_t)file_size, 0x84);

            printf("  absence search (asserted): config chains=%zu, MS header 07 24 06 00 01=%zu,"
                   " ep 07 05 04 02=%zu, ep 07 05 84 02=%zu\n",
                   config_chains, ms_full, ep04, ep84);
            printf("  absence search (informational, chance-level in a firmware image):"
                   " type-byte MS headers=%zu (expected ~%u by chance),"
                   " type-byte ep 0x04=%zu, type-byte ep 0x84=%zu\n",
                   ms_hits, (unsigned)((size_t)file_size / 65536u), ep04_loose, ep84_loose);
            check(config_chains == 0,
                  "no config descriptor chain exists in the dump (the configuration is not recoverable)");
            check(ms_full == 0, "no MIDIStreaming CS_INTERFACE MS_HEADER (07 24 06 00 01) exists in the dump");
            check(ep04 == 0, "no bulk endpoint descriptor 07 05 04 02 exists in the dump");
            check(ep84 == 0, "no bulk endpoint descriptor 07 05 84 02 exists in the dump");
        }
        printf("  the identity sits at flash 0x%05X, inside beyond_package (>= 0x%05X):\n"
               "  an app-delivered payload never covers it; a full .fwsc reflash ships it\n",
               (unsigned)SMK_USB_UPDATER_IDENTITY_FLASH_OFFSET,
               (unsigned)SMK_USB_BEYOND_PACKAGE_BASE);
        check_updater_image(dump, served, served_size);
    } else if (identity_hits == 0) {
        size_t differing = 0;

        for (index = 0; index < served_size; ++index) {
            if (dump[SMK_USB_UPDATER_FLASH_OFFSET + index] != served[index]) {
                ++differing;
            }
        }
        print_hex("  dump@0x0BDDE5:", dump + SMK_USB_UPDATER_FLASH_OFFSET, served_size);
        check(differing == served_size,
              "NEGATIVE CONTROL: no identity in this dump and all 18 bytes at "
              "0x0BDDE5 differ from what the app would serve");
    } else {
        check(0, "the updater identity occurs more than once in this dump");
    }

    free(dump);
    return 0;
}

int main(int argc, char **argv) {
    const uint8_t *served_device = smk_usb_recovered_device_descriptor();
    size_t served_device_size = smk_usb_recovered_device_descriptor_size();
    const uint8_t *fragment = smk_usb_midi_interface_fragment();
    size_t fragment_size = smk_usb_midi_interface_fragment_size();
    struct smk_usb_descriptor_view view;

    printf("=== B1: USB descriptor evidence set ===\n");
    print_hex("recovered device descriptor:", served_device, served_device_size);
    print_hex("MIDIStreaming fragment:", fragment, fragment_size);

    /* The recovered half, against this file's independent transcription. */
    check(served_device_size == SMK_USB_DEVICE_DESCRIPTOR_SIZE,
          "recovered device descriptor is 18 bytes");
    check(memcmp(served_device, transcribed_device_descriptor,
                 SMK_USB_DEVICE_DESCRIPTOR_SIZE) == 0,
          "app's device descriptor equals the transcription of the flash bytes");
    check(fragment_size == SMK_USB_MIDI_FRAGMENT_SIZE,
          "the MIDIStreaming fragment is the expected 30 bytes");
    check(smk_usb_updater_product_name_size() == SMK_USB_UPDATER_PRODUCT_NAME_SIZE,
          "recovered product-name text is 40 bytes");
    check(memcmp(smk_usb_updater_product_name(), transcribed_product_name,
                 SMK_USB_UPDATER_PRODUCT_NAME_SIZE) == 0,
          "app's product-name text equals the transcription of the image bytes");

    /* The lookup serves the recovered descriptor and withholds the rest. */
    check(smk_usb_get_descriptor(SMK_USB_DT_DEVICE, 0, &view) == 0 &&
              view.length == SMK_USB_DEVICE_DESCRIPTOR_SIZE &&
              view.data == served_device,
          "GET_DESCRIPTOR(DEVICE, 0) serves the recovered descriptor");
    check(smk_usb_get_descriptor(SMK_USB_DT_CONFIG, 0, &view) != 0,
          "GET_DESCRIPTOR(CONFIG, 0) is withheld: the composite is unrecovered");
    check(smk_usb_get_descriptor(SMK_USB_DT_STRING, 1, &view) != 0 &&
              smk_usb_get_descriptor(SMK_USB_DT_STRING, 2, &view) != 0,
          "string descriptors report absent, not invented");
    check(smk_usb_serve_class(SMK_USB_DT_DEVICE, 0) == SMK_USB_SERVE_RECOVERED &&
              smk_usb_serve_class(SMK_USB_DT_CONFIG, 0) == SMK_USB_SERVE_WITHHELD,
          "serve classes are recovered / withheld as documented");

    /* The device-side self-test must agree with this file. */
    check(smk_usb_descriptor_self_test() == 0, "device-side descriptor self-test");

    /* The fact ledger, then the record it claims to come from. */
    check_fact_ledger(fragment, fragment_size);
    check_evidence_documents();

    if (argc > 1) {
        int arg;
        for (arg = 1; arg < argc; ++arg) {
            int status = check_dump(argv[arg], served_device, served_device_size);
            if (status != 0) {
                return status;
            }
        }
        printf("\n  GROUND TRUTH VERIFIED against %d whole-flash dump(s).\n", argc - 1);
    } else {
        printf("\n  GROUND TRUTH NOT VERIFIED: no live dump was given, so the 18 bytes\n"
               "  above were only checked against this file's transcription. Re-run as\n"
               "      usb_descriptor_test <path-to-1MiB-live-dump.bin> [more dumps...]\n"
               "  to compare them byte for byte with flash 0x0BDDE5.\n"
               "  The interface fragment IS checked without a dump: every field is\n"
               "  compared with the fact ledger and re-derived from the two documents.\n");
    }

    printf("\nchecks: %u, failures: %u\n", checks, failures);
    if (failures != 0) {
        printf("USB DESCRIPTORS: FAIL\n");
        return 1;
    }
    printf("USB DESCRIPTORS: PASS\n");
    return 0;
}
