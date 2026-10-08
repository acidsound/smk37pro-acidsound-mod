#ifndef SMK_USB_DESCRIPTORS_H
#define SMK_USB_DESCRIPTORS_H

/*
 * B1 of docs/self-recovering-sdk-app.md section 4: the USB personality the app
 * presents when it acts as the updatable SMK-37 Pro.
 *
 * WHAT THIS FILE CLAIMS, AND ON WHAT EVIDENCE
 * ------------------------------------------
 * The whole point of this translation unit is that every byte it exports is
 * traceable to a named source, and that what the record does not pin is listed
 * as unrecovered instead of invented. Three kinds of claim appear below:
 *
 *   RECOVERED (byte exact, flash dump)
 *     The 18-byte device descriptor of the updater identity 4d4a:4155, read at
 *     flash 0x0BDDE5 (identity at 0x0BDDED) from every whole-flash 1 MiB image
 *     that carries it: 8 of the 9 DISTINCT such images in the workspace (16 of the
 *     19 stored paths - the captures were taken in -a/-b pairs and are byte
 *     identical), all at that same offset. The one image without it is the
 *     pre-restore 2026-07-14 image (3 stored paths, including its
 *     `_unpack/decrypted.bin`, which is byte identical to the plaintext dump):
 *     there the 18 bytes are 0xFF and the identity occurs zero times - the
 *     negative control used by ac79/test/usb_descriptor_test.c. The identity is
 *     not a descriptor table: the bytes sit inside a package record opened by an
 *     ASCII marker (2f 2a 2e 75 66 77 = a slash, a star, ".ufw"), 17 bytes
 *     before the descriptor, followed by the 10-byte trailer
 *     01 04 f0 22 24 07 35 7d f7 00 and then 0xFF fill to the 4 KiB sector
 *     boundary 0x0BE000. The probe record those bytes are the tail of is the
 *     update-mode firmware image itself: the vendor package (the .fwsc) carries
 *     it as the `ota.bin` UFW entry (0x4E01 bytes, name usb_hid_ota.bin), which
 *     maps to flash 0x0B9000..0x0BDE01, with the descriptor 0x4DE5 into the
 *     entry. Two consequences must not be conflated: an APP-DELIVERED payload
 *     (the app slot ends at 0x9C000) never covers this region, so a replacement
 *     app cannot inherit the site; a FULL .fwsc reflash does write it, because
 *     the vendor package ships it. The audit of 2026-10-09b found the site bytes
 *     inside every .fwsc for that reason.
 *
 *   RECOVERED (text, from the same updater image)
 *     The updater's product name as recorded by docs/research-notes.md ("USB
 *     Composite Device") exists byte exact as 40 bytes of UTF-16LE at flash
 *     0x0BB558, i.e. 0x2558 into the updater image - present in exactly the same
 *     8 of 9 distinct whole-flash images as the device descriptor, absent in the
 *     pre-restore negative. The 2 bytes immediately before it are 2a 03; whether
 *     that is a served string-descriptor header is NOT established (the surrounding
 *     records do not chain into a table), so the text is exported as recovered
 *     EVIDENCE and the serve class stays WITHHELD, like the rest of the strings.
 *
 *   RECORDED FACTS (values pinned by a named document; no wire-format bytes)
 *     No raw CONFIGURATION descriptor bytes exist anywhere in this project. That
 *     was verified, not assumed, and the verification was corrected on
 *     2026-10-09b after an audit showed the earlier wording overstated it:
 *       - every text artifact in the workspace was searched for the descriptor
 *         byte strings in every spacing/escape spelling and none quotes them;
 *       - EVERY *.bin, *.fwsc and *.elf in the scan set (schema /4: 765 files,
 *         179.6 MB = 704 .bin - 19 whole-flash images, 47 app-slot payloads, 24
 *         SDK tool images and build inputs, 614 other captures - plus 56 .fwsc
 *         packages and 5 .elf tools) was walked with a tolerant config-descriptor
 *         parser that accepts any class-specific type. The scan set excludes this
 *         project's own regenerated build outputs under the linux-build
 *         ac79-build-* prefix (listed with size and sha256 in scope.excluded;
 *         scope.manifest_sha256 pins exactly what was counted), so the counts do
 *         not drift with our own builds and no project artifact can be mistaken
 *         for recovered evidence. The chains the walk finds are stated per file:
 *         1 in the vendor SDK's AC790N MP-test tool ELF and 1 in its AC791N
 *         MP-test tool ELF, none in a recovered corpus (an earlier revision of
 *         this scan, before the exclusion rule, also counted the authored
 *         39-byte set in the superseded B1 build's own app.bin and its sdk.elf -
 *         project artifacts, not recoveries);
 *       - the audit's finding is that raw descriptor bytes DO exist for the
 *         STRING channel (see above) - what does not exist is a wire-format
 *         string-descriptor TABLE: walking from the LANGID anchor (04 03 09 04)
 *         inside the updater image fails at the second record, so a lone
 *         `LL 03 <utf16>` sequence there is config-blob text, not a served
 *         descriptor. ac79/evidence/search_updater_usb_image.py searches the one
 *         image that carries the site in wire format and reports exactly that:
 *         0 config chains, 0 plausible interface records, 0 endpoint records,
 *         0 MS headers, 0 CS_ENDPOINT records inside it.
 *     The facts below are therefore records of a live enumeration:
 *       - docs/research-notes.md lines 930-935 (update mode 4D4A:4155):
 *         product "USB Composite Device" (so the configuration is composite),
 *         "MIDI Streaming interface 1 rather than normal-mode interface 4", and
 *         the bulk endpoints "remain 0x04 OUT and 0x84 IN";
 *       - baselines/v15/device-info/probe.txt (normal mode 4353:cf4d, interface
 *         4 of 5): class 0x01 / subclass 0x03 with 2 endpoints, endpoint 0x84 IN
 *         bulk max-packet 64 interval 0, endpoint 0x04 OUT bulk max-packet 64
 *         interval 0. The same file records that the MIDIStreaming interface has
 *         no alternate setting at all.
 *     The plan document's "v15 descriptor capture complete"
 *     (docs/from-scratch-platform-plan.md line 31, citing public-research
 *     section 5) resolves to exactly that probe - and its citation is off by a
 *     section, since the USB material is section 4.1 - while public-research
 *     section 4.4 itself says descriptor extraction "remains necessary to
 *     enumerate embedded jack IDs, cable count, and class-specific endpoint
 *     descriptors". So the plan overstates what exists; the record pins fields,
 *     not bytes.
 *
 *   AUTHORED, but only where a named source pins the field (see smk_usb_facts())
 *     The one piece of the updater's configuration the record does pin is its
 *     MIDIStreaming interface and its two bulk endpoints. Those 30 bytes are
 *     exported as a FRAGMENT (smk_usb_midi_interface_fragment) - a descriptor
 *     chain that cannot legally stand alone - and every field in it is listed in
 *     smk_usb_facts() with its offset, value and source. The device is a
 *     composite, so the configuration descriptor, the other interfaces, the
 *     MIDI jack descriptors, the CS_ENDPOINT descriptors and the cable count are
 *     NOT recovered; they are named in smk_usb_unrecovered() and deliberately not
 *     served. The 2026-10-09b audit searched the update-mode firmware image
 *     itself, in wire format, for those records; they are genuinely absent there,
 *     so nothing could be promoted from authored to recovered.
 *
 * Consequence: smk_usb_get_descriptor() serves the recovered device descriptor
 * and WITHHOLDS the configuration and strings, because serving a fabricated
 * composite descriptor would be the invention earlier revisions of this file
 * shipped. The recovered product-name text (see above) is exported as evidence
 * but not served, because the string-index mapping is unproven. The fragment
 * exists so the next stage can assemble and register a real configuration once
 * the composite is known.
 *
 * This translation unit is data plus a table lookup: no USB access, no
 * descriptor transfer, no hardware interaction. It states what the app would
 * present; ac79/test/usb_descriptor_test.c checks it against the dump and the
 * two documents on the host.
 */

#include <stddef.h>
#include <stdint.h>

/* Descriptor types used here. */
#define SMK_USB_DT_DEVICE 0x01u
#define SMK_USB_DT_CONFIG 0x02u
#define SMK_USB_DT_STRING 0x03u
#define SMK_USB_DT_INTERFACE 0x04u
#define SMK_USB_DT_ENDPOINT 0x05u
#define SMK_USB_CS_INTERFACE 0x24u
#define SMK_USB_CS_MS_HEADER 0x06u

/* Recovered identity and where it was read from. */
#define SMK_USB_DEVICE_DESCRIPTOR_SIZE 18u
#define SMK_USB_UPDATER_VID 0x4d4au
#define SMK_USB_UPDATER_PID 0x4155u
#define SMK_USB_UPDATER_FLASH_OFFSET 0x0bdde5u
#define SMK_USB_UPDATER_IDENTITY_FLASH_OFFSET 0x0bddedu
#define SMK_USB_BEYOND_PACKAGE_BASE 0x9c000u
#define SMK_USB_SITE_SECTOR_BASE 0x0bd000u
#define SMK_USB_SITE_FILL_END 0x0be000u
#define SMK_USB_SITE_MARKER_TO_DESCRIPTOR 17u
#define SMK_USB_DUMP_SHA256_M10 \
    "0cd4b8253ae979d428e9821eb451bcae10b4188891cad291bd6c831ae967b62f"
#define SMK_USB_DUMP_SHA256_POST_RESTORE \
    "288a2e70a515d39f98e4616461f152ae2a61c01e8a0cbd5e1d592b83cb750ecd"

/* The update-mode firmware image the site is the tail of: the vendor package's
 * `ota.bin` UFW entry (usb_hid_ota.bin), mapped to flash 0x0B9000..0x0BDE01.
 * The descriptor sits SMK_USB_UPDATER_DESCRIPTOR_IN_IMAGE bytes into it. */
#define SMK_USB_UPDATER_IMAGE_FLASH_OFFSET 0x0b9000u
#define SMK_USB_UPDATER_IMAGE_SIZE 0x4e01u
#define SMK_USB_UPDATER_DESCRIPTOR_IN_IMAGE 0x04de5u
#define SMK_USB_UPDATER_IMAGE_NAME "usb_hid_ota.bin"

/* Recovered product-name text: 40 bytes of UTF-16LE at flash 0x0BB558 (image
 * offset 0x2558), the name docs/research-notes.md records for update mode. The
 * 2 bytes before it in the image are 2a 03; whether that is a string-descriptor
 * header is not established, so this is evidence, not a served string. */
#define SMK_USB_UPDATER_PRODUCT_NAME_SIZE 40u
#define SMK_USB_UPDATER_PRODUCT_NAME_FLASH_OFFSET 0x0bb558u
#define SMK_USB_UPDATER_PRODUCT_NAME_IMAGE_OFFSET 0x02558u

/* The updater's MIDIStreaming interface fragment: interface + CS_HEADER + the
 * two bulk endpoints. 30 bytes, every field pinned by smk_usb_facts(). */
#define SMK_USB_MIDI_FRAGMENT_SIZE 30u

/* Where a pinned value comes from. */
enum smk_usb_source {
    SMK_USB_SRC_FLASH_DUMP = 1,     /* byte exact, recovered from the live dump */
    SMK_USB_SRC_UPDATE_MODE_RECORD, /* docs/research-notes.md, update-mode enumeration */
    SMK_USB_SRC_LIVE_PROBE,         /* baselines/v15/device-info/probe.txt */
    SMK_USB_SRC_USB_MIDI_SPEC       /* USB Device Class Definition for MIDI Devices 1.0 */
};

/* One evidence-pinned field of the fragment: bytes [offset, offset+width) must
 * equal `value` (little endian, width <= 4). */
struct smk_usb_fact {
    const char *field;
    uint16_t offset;
    uint8_t width;
    uint32_t value;
    enum smk_usb_source source;
};

/* One thing the record does not pin. `offset` >= 0 names the fragment byte that
 * had to be set without evidence (and is therefore declared, never silent);
 * offset < 0 means the item is not part of the fragment at all. */
struct smk_usb_unrecovered {
    const char *item;
    int16_t offset;
};

/* How the app may serve a descriptor request. */
#define SMK_USB_SERVE_RECOVERED 2 /* served, and byte identical to the flash dump */
#define SMK_USB_SERVE_FRAGMENT 1  /* served only as the evidence-pinned fragment */
#define SMK_USB_SERVE_WITHHELD 0  /* the record is silent: not served at all */

struct smk_usb_descriptor_view {
    const uint8_t *data;
    uint16_t length;
};

/* Standard GET_DESCRIPTOR lookup: type = bDescriptorType, index = the low byte
 * of wValue. Returns 0 when served, -1 when this set has nothing for it. Only
 * (DEVICE, 0) is served; see smk_usb_serve_class(). */
int smk_usb_get_descriptor(uint8_t type, uint8_t index,
                           struct smk_usb_descriptor_view *view);

/* 2 = recovered bytes, 1 = evidence fragment, 0 = withheld. */
int smk_usb_serve_class(uint8_t type, uint8_t index);

const uint8_t *smk_usb_recovered_device_descriptor(void);
size_t smk_usb_recovered_device_descriptor_size(void);
const uint8_t *smk_usb_midi_interface_fragment(void);
size_t smk_usb_midi_interface_fragment_size(void);

/* Recovered UTF-16LE product-name text of the update-mode firmware image. Not
 * served: smk_usb_get_descriptor(STRING, ...) still reports absent. */
const uint8_t *smk_usb_updater_product_name(void);
size_t smk_usb_updater_product_name_size(void);

/* The evidence ledger. Never NULL; count is always set. */
const struct smk_usb_fact *smk_usb_facts(size_t *count);
const struct smk_usb_unrecovered *smk_usb_unrecovered(size_t *count);
const char *smk_usb_source_name(enum smk_usb_source source);

/* Structural self-check of what this file exports; 0 on success. The evidence
 * itself is asserted by ac79/test/usb_descriptor_test.c against the dump and the
 * two documents, not here: the device has no access to them. */
int smk_usb_descriptor_self_test(void);

#endif
