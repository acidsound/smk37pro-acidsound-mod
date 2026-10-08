/*
 * B1 descriptor evidence set. See smk_usb_descriptors.h for the three kinds of
 * claim (RECOVERED bytes and text, RECORDED FACTS, and what is declared
 * unrecovered) and for the provenance of each source.
 *
 * The 2026-10-09b audit searched the update-mode firmware image itself (the tail
 * of the vendor package's ota.bin entry, flash 0x0B9000..0x0BDE01) in wire
 * format for configuration/interface/endpoint records: there are none, so the
 * fragment below stays AUTHORED and the configuration stays withheld. The same
 * image does hold the product-name text, recovered below.
 */

#include "smk_usb_descriptors.h"

/* ---------------------------------------------------------------------------
 * RECOVERED: byte for byte from flash 0x0BDDE5 (beyond_package, PRESERVE).
 * The comment fields are interpretation; the bytes are the evidence.
 *
 * __attribute__((used)) is load-bearing, not decoration: with -flto -Oz the
 * optimizer is free to fold this table into immediate compare constants, since
 * today only the self-test observes it, and the 18 bytes then disappear from the
 * built app.bin. The table has to exist as bytes in the image because the USB
 * stack will serve it at runtime - and keeping it also makes the artifact itself
 * checkable (the build recipe requires these 18 bytes to be present verbatim,
 * which no stock image has).
 * ------------------------------------------------------------------------- */
static const uint8_t smk_usb_device_descriptor[SMK_USB_DEVICE_DESCRIPTOR_SIZE]
    __attribute__((used)) = {
    0x12u,             /* bLength = 18 */
    0x01u,             /* bDescriptorType = DEVICE */
    0x00u, 0x02u,      /* bcdUSB = 0x0200 */
    0x00u,             /* bDeviceClass */
    0x00u,             /* bDeviceSubClass */
    0x00u,             /* bDeviceProtocol */
    0x40u,             /* bMaxPacketSize0 = 64 */
    0x4au, 0x4du,      /* idVendor  = 0x4d4a */
    0x55u, 0x41u,      /* idProduct = 0x4155 */
    0x00u, 0x01u,      /* bcdDevice = 0x0100 */
    0x01u,             /* iManufacturer = 1 (that string is NOT recoverable) */
    0x02u,             /* iProduct = 2      (that string is NOT recoverable) */
    0x00u,             /* iSerialNumber = 0 */
    0x01u,             /* bNumConfigurations = 1 */
};

/* ---------------------------------------------------------------------------
 * The updater's MIDIStreaming interface fragment - every field pinned by a named
 * source, listed in smk_usb_facts() below.
 *
 *   09 04 01 00 02 01 03 00 00   interface 1 (record), alt 0, 2 endpoints
 *                                (probe), class 0x01 / subclass 0x03 (probe +
 *                                spec), protocol 0 (spec), iInterface 0
 *   07 24 06 00 01 07 00         CS_HEADER: subtype 6, bcdADC 0x0100, and a
 *                                wTotalLength of 7 = this header alone, because
 *                                the jack descriptors after it are unrecovered
 *   07 05 04 02 40 00 00         endpoint 0x04 OUT, bulk, 64 B, interval 0
 *   07 05 84 02 40 00 00         endpoint 0x84 IN,  bulk, 64 B, interval 0
 *
 * This chain cannot stand alone as a configuration: the device enumerated as a
 * composite, and everything outside this interface is unrecovered. The byte that
 * is set without evidence is iInterface (offset 8); it is declared in
 * smk_usb_unrecovered() and checked as declared by the host test. The
 * 2026-10-09b targeted search of the updater image itself (in wire format)
 * found no configuration/interface/endpoint records that could replace this
 * fragment, so it remains AUTHORED; see ac79/evidence/search_updater_usb_image.py.
 * ------------------------------------------------------------------------- */
static const uint8_t smk_usb_midi_fragment_bytes[SMK_USB_MIDI_FRAGMENT_SIZE]
    __attribute__((used)) = {
    0x09u, 0x04u, 0x01u, 0x00u, 0x02u, 0x01u, 0x03u, 0x00u, 0x00u,
    0x07u, 0x24u, 0x06u, 0x00u, 0x01u, 0x07u, 0x00u,
    0x07u, 0x05u, 0x04u, 0x02u, 0x40u, 0x00u, 0x00u,
    0x07u, 0x05u, 0x84u, 0x02u, 0x40u, 0x00u, 0x00u,
};

/* ---------------------------------------------------------------------------
 * RECOVERED TEXT: the update-mode product name.
 *
 * 40 bytes of UTF-16LE at flash 0x0BB558 (0x2558 into the updater image), byte
 * exact in the same 8 of 9 distinct images as the device descriptor. The audit
 * found it by decoding UTF-16LE string candidates, not by a chain walk: the 2
 * bytes before it are 2a 03, but the surrounding records do not chain, so it is
 * NOT claimed to be a served string descriptor. Exported as evidence for the
 * day the string table is understood; smk_usb_get_descriptor() does not serve it.
 *
 * The text is "USB Composite Device", the product docs/research-notes.md records
 * for update mode; ac79/test/usb_descriptor_test.c checks the bytes against the
 * dump AND re-derives that recorded name from research-notes.md.
 * ------------------------------------------------------------------------- */
static const uint8_t smk_usb_updater_product_name_utf16[SMK_USB_UPDATER_PRODUCT_NAME_SIZE]
    __attribute__((used)) = {
    0x55u, 0x00u, 0x53u, 0x00u, 0x42u, 0x00u, 0x20u, 0x00u,  /* "USB " */
    0x43u, 0x00u, 0x6fu, 0x00u, 0x6du, 0x00u, 0x70u, 0x00u,  /* "Comp" */
    0x6fu, 0x00u, 0x73u, 0x00u, 0x69u, 0x00u, 0x74u, 0x00u,  /* "osit" */
    0x65u, 0x00u, 0x20u, 0x00u, 0x44u, 0x00u, 0x65u, 0x00u,  /* "e De" */
    0x76u, 0x00u, 0x69u, 0x00u, 0x63u, 0x00u, 0x65u, 0x00u,  /* "vice" */
};

/* ---------------------------------------------------------------------------
 * The evidence ledger: every field of the fragment, where it came from, and the
 * value it must hold. The host test evaluates this table against the fragment,
 * so mutating any of these bytes fails the suite, and it re-derives the
 * LIVE_PROBE and UPDATE_MODE_RECORD entries from the two documents themselves.
 * ------------------------------------------------------------------------- */
static const struct smk_usb_fact smk_usb_fact_table[] = {
    {"iface.bLength", 0u, 1u, 9u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"iface.bDescriptorType", 1u, 1u, 0x04u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"bInterfaceNumber", 2u, 1u, 1u, SMK_USB_SRC_UPDATE_MODE_RECORD},
    {"bAlternateSetting", 3u, 1u, 0u, SMK_USB_SRC_LIVE_PROBE},
    {"bNumEndpoints", 4u, 1u, 2u, SMK_USB_SRC_LIVE_PROBE},
    {"bInterfaceClass", 5u, 1u, 0x01u, SMK_USB_SRC_LIVE_PROBE},
    {"bInterfaceSubClass", 6u, 1u, 0x03u, SMK_USB_SRC_LIVE_PROBE},
    {"bInterfaceProtocol", 7u, 1u, 0x00u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"CS_HEADER.bLength", 9u, 1u, 7u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"CS_HEADER.bDescriptorType", 10u, 1u, 0x24u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"CS_HEADER.bDescriptorSubtype", 11u, 1u, 0x06u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"CS_HEADER.bcdADC", 12u, 2u, 0x0100u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"CS_HEADER.wTotalLength", 14u, 2u, 7u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"ep_0x04.bLength", 16u, 1u, 7u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"ep_0x04.bDescriptorType", 17u, 1u, 0x05u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"ep_0x04.bEndpointAddress", 18u, 1u, 0x04u, SMK_USB_SRC_UPDATE_MODE_RECORD},
    {"ep_0x04.bmAttributes", 19u, 1u, 0x02u, SMK_USB_SRC_LIVE_PROBE},
    {"ep_0x04.wMaxPacketSize", 20u, 2u, 64u, SMK_USB_SRC_LIVE_PROBE},
    {"ep_0x04.bInterval", 22u, 1u, 0u, SMK_USB_SRC_LIVE_PROBE},
    {"ep_0x84.bLength", 23u, 1u, 7u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"ep_0x84.bDescriptorType", 24u, 1u, 0x05u, SMK_USB_SRC_USB_MIDI_SPEC},
    {"ep_0x84.bEndpointAddress", 25u, 1u, 0x84u, SMK_USB_SRC_UPDATE_MODE_RECORD},
    {"ep_0x84.bmAttributes", 26u, 1u, 0x02u, SMK_USB_SRC_LIVE_PROBE},
    {"ep_0x84.wMaxPacketSize", 27u, 2u, 64u, SMK_USB_SRC_LIVE_PROBE},
    {"ep_0x84.bInterval", 29u, 1u, 0u, SMK_USB_SRC_LIVE_PROBE},
};

/* What the record does not pin. Negative offsets are outside the fragment. The
 * one positive entry is the fragment byte that had to be chosen: iInterface. */
static const struct smk_usb_unrecovered smk_usb_unrecovered_table[] = {
    {"configuration descriptor entirely (wTotalLength, bNumInterfaces, bmAttributes, bMaxPower, iConfiguration) - searched in wire format inside the updater image itself, absent there", -1},
    {"the other interfaces of the updater's composite configuration (interface 0 and any beyond the MIDI one) - absent from the updater image in wire format", -1},
    {"the string-index mapping and the remaining string contents: the product-name TEXT is recovered (smk_usb_updater_product_name, flash 0x0BB558) but no wire-format string table exists in the updater image, so which index returns it is unproven, and iConfiguration / the manufacturer string contents are still unknown", -1},
    {"MIDI jack descriptors (embedded jack IDs and the cable count) - the image holds one isolated jack-shaped 6-byte sequence at image 0x261E inside a config blob, with no companion record or chain, so it is not a recovered interface", -1},
    {"CS_ENDPOINT descriptors (each must name a jack id the record does not give)", -1},
    {"iInterface of the MIDIStreaming interface: set to 0 (no string), because no artifact records an interface string", 8},
};

const uint8_t *smk_usb_recovered_device_descriptor(void) {
    return smk_usb_device_descriptor;
}

size_t smk_usb_recovered_device_descriptor_size(void) {
    return sizeof(smk_usb_device_descriptor);
}

const uint8_t *smk_usb_midi_interface_fragment(void) {
    return smk_usb_midi_fragment_bytes;
}

size_t smk_usb_midi_interface_fragment_size(void) {
    return sizeof(smk_usb_midi_fragment_bytes);
}

const uint8_t *smk_usb_updater_product_name(void) {
    return smk_usb_updater_product_name_utf16;
}

size_t smk_usb_updater_product_name_size(void) {
    return sizeof(smk_usb_updater_product_name_utf16);
}

const struct smk_usb_fact *smk_usb_facts(size_t *count) {
    if (count != 0) {
        *count = sizeof(smk_usb_fact_table) / sizeof(smk_usb_fact_table[0]);
    }
    return smk_usb_fact_table;
}

const struct smk_usb_unrecovered *smk_usb_unrecovered(size_t *count) {
    if (count != 0) {
        *count = sizeof(smk_usb_unrecovered_table) /
                 sizeof(smk_usb_unrecovered_table[0]);
    }
    return smk_usb_unrecovered_table;
}

const char *smk_usb_source_name(enum smk_usb_source source) {
    switch (source) {
    case SMK_USB_SRC_FLASH_DUMP:
        return "flash dump";
    case SMK_USB_SRC_UPDATE_MODE_RECORD:
        return "docs/research-notes.md";
    case SMK_USB_SRC_LIVE_PROBE:
        return "baselines/v15/device-info/probe.txt";
    case SMK_USB_SRC_USB_MIDI_SPEC:
        return "USB MIDI 1.0";
    default:
        return "unknown";
    }
}

int smk_usb_serve_class(uint8_t type, uint8_t index) {
    if (type == SMK_USB_DT_DEVICE && index == 0u) {
        return SMK_USB_SERVE_RECOVERED;
    }
    /* The configuration cannot be served: only one interface of it is pinned.
     * The MIDIStreaming interface is available as a fragment through
     * smk_usb_midi_interface_fragment() for the assembly step, but a fragment is
     * not a configuration descriptor, so GET_DESCRIPTOR(CONFIG, 0) is withheld
     * rather than answered with an invented composite. */
    if (type == SMK_USB_DT_CONFIG && index == 0u) {
        return SMK_USB_SERVE_WITHHELD;
    }
    return SMK_USB_SERVE_WITHHELD;
}

int smk_usb_get_descriptor(uint8_t type, uint8_t index,
                           struct smk_usb_descriptor_view *view) {
    if (view == 0) {
        return -1;
    }
    if (smk_usb_serve_class(type, index) == SMK_USB_SERVE_RECOVERED) {
        view->data = smk_usb_device_descriptor;
        view->length = (uint16_t)sizeof(smk_usb_device_descriptor);
        return 0;
    }
    return -1;
}

int smk_usb_descriptor_self_test(void) {
    const uint8_t *fragment = smk_usb_midi_fragment_bytes;
    const size_t fragment_size = sizeof(smk_usb_midi_fragment_bytes);
    const uint8_t *device = smk_usb_device_descriptor;
    size_t fact_count = 0;
    size_t unrecovered_count = 0;
    const struct smk_usb_fact *facts = smk_usb_facts(&fact_count);
    const struct smk_usb_unrecovered *unrecovered = smk_usb_unrecovered(&unrecovered_count);
    uint16_t vendor;
    uint16_t product;
    size_t index;
    size_t offset = 0;
    int interfaces = 0;
    int endpoints = 0;
    int ms_headers = 0;
    int out_bulk = 0;
    int in_bulk = 0;

    /* Recovered device descriptor: structural invariants plus the identity it is
     * supposed to carry. (Byte-exact agreement with the dump is the host test's
     * job, not the device's.) */
    if (device[0] != SMK_USB_DEVICE_DESCRIPTOR_SIZE ||
        device[1] != SMK_USB_DT_DEVICE ||
        device[7] != 0x40u ||
        device[17] != 0x01u) {
        return 1;
    }
    vendor = (uint16_t)device[8] | ((uint16_t)device[9] << 8);
    product = (uint16_t)device[10] | ((uint16_t)device[11] << 8);
    if (vendor != SMK_USB_UPDATER_VID || product != SMK_USB_UPDATER_PID) {
        return 2;
    }

    /* The fragment must be a well-formed descriptor chain ... */
    if (fragment[0] != 0x09u || fragment[1] != SMK_USB_DT_INTERFACE) {
        return 3;
    }
    while (offset < fragment_size) {
        uint8_t length = fragment[offset];
        uint8_t type = fragment[offset + 1];

        if (length < 2u || offset + length > fragment_size) {
            return 4;
        }
        if (type == SMK_USB_DT_INTERFACE) {
            if (length != 0x09u || offset != 0u) {
                return 5;
            }
            ++interfaces;
        } else if (type == SMK_USB_DT_ENDPOINT) {
            uint8_t address = fragment[offset + 2];

            if (length != 0x07u) {
                return 6;
            }
            ++endpoints;
            if (address == 0x04u) {
                out_bulk = 1;
            }
            if (address == 0x84u) {
                in_bulk = 1;
            }
        } else if (type == SMK_USB_CS_INTERFACE) {
            if (length != 0x07u || fragment[offset + 2] != SMK_USB_CS_MS_HEADER) {
                return 7;
            }
            ++ms_headers;
        } else {
            return 8;
        }
        offset += length;
    }
    if (interfaces != 1 || endpoints != 2 || ms_headers != 1 ||
        out_bulk == 0 || in_bulk == 0) {
        return 9;
    }

    /* ... and every one of its evidence-pinned fields must hold its pinned value,
     * read through the very table the host test uses. */
    if (facts == 0 || fact_count == 0 || unrecovered == 0 || unrecovered_count == 0) {
        return 10;
    }
    for (index = 0; index < fact_count; ++index) {
        uint32_t observed = 0;
        size_t byte_index;

        if ((size_t)facts[index].offset + facts[index].width > fragment_size ||
            facts[index].width == 0u || facts[index].width > 4u) {
            return 11;
        }
        for (byte_index = 0; byte_index < facts[index].width; ++byte_index) {
            observed |= (uint32_t)fragment[facts[index].offset + byte_index]
                        << (8u * byte_index);
        }
        if (observed != facts[index].value) {
            return 12;
        }
        if (facts[index].source < SMK_USB_SRC_FLASH_DUMP ||
            facts[index].source > SMK_USB_SRC_USB_MIDI_SPEC) {
            return 13;
        }
    }

    /* The lookup must withhold rather than invent. */
    {
        struct smk_usb_descriptor_view view;

        if (smk_usb_get_descriptor(SMK_USB_DT_DEVICE, 0u, &view) != 0 ||
            view.data != smk_usb_device_descriptor ||
            view.length != SMK_USB_DEVICE_DESCRIPTOR_SIZE) {
            return 14;
        }
        if (smk_usb_get_descriptor(SMK_USB_DT_CONFIG, 0u, &view) == 0 ||
            smk_usb_get_descriptor(SMK_USB_DT_CONFIG, 1u, &view) == 0 ||
            smk_usb_get_descriptor(SMK_USB_DT_STRING, 1u, &view) == 0 ||
            smk_usb_get_descriptor(SMK_USB_DT_STRING, 2u, &view) == 0) {
            return 15;
        }
        if (smk_usb_serve_class(SMK_USB_DT_DEVICE, 0u) != SMK_USB_SERVE_RECOVERED ||
            smk_usb_serve_class(SMK_USB_DT_CONFIG, 0u) != SMK_USB_SERVE_WITHHELD) {
            return 16;
        }
    }

    /* Every fragment byte must be either pinned by a fact or declared
     * unrecovered: no byte may be set silently. */
    for (index = 0; index < fragment_size; ++index) {
        int covered = 0;
        size_t other;

        for (other = 0; other < fact_count; ++other) {
            if (index >= facts[other].offset &&
                index < (size_t)facts[other].offset + facts[other].width) {
                covered = 1;
            }
        }
        for (other = 0; other < unrecovered_count; ++other) {
            if (unrecovered[other].offset == (int16_t)index) {
                covered = 1;
            }
        }
        if (covered == 0) {
            return 17; /* a fragment byte is neither evidence-pinned nor declared */
        }
    }

    /* The recovered product-name text must be well-formed UTF-16LE ASCII of the
     * documented size. Byte-exact agreement with the dump and with research-notes
     * is the host test's job (the device has no access to either). */
    if (sizeof(smk_usb_updater_product_name_utf16) != SMK_USB_UPDATER_PRODUCT_NAME_SIZE ||
        smk_usb_updater_product_name_utf16[0] != 0x55u ||
        smk_usb_updater_product_name_utf16[1] != 0x00u) {
        return 18;
    }
    for (index = 1; index < sizeof(smk_usb_updater_product_name_utf16); index += 2) {
        if (smk_usb_updater_product_name_utf16[index] != 0x00u) {
            return 19; /* not ASCII UTF-16LE */
        }
    }

    return 0;
}
