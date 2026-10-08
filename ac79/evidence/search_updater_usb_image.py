#!/usr/bin/env python3
"""
Targeted search of the update-mode firmware image (usb_hid_ota.bin).

WHY THIS EXISTS
The corridor-wide searches (ac79/evidence/recon_updater_usb_identity.py) walk
every *.bin in the workspace. After the 2026-10-09 audit that was shown to be
the weaker instrument: the block of flash that actually holds the updater's
descriptor site is the tail of the vendor package's `ota.bin` entry, a 19,969-byte
image (`usb_hid_ota.bin`) mapped at flash 0x0B9000..0x0BDE01. Corpus-wide scans
see it as bytes like any other file; this tool searches the ONE image that is
known to carry the site, in wire format, so the negative can be stated about the
right artifact.

WHERE THE IMAGE BOUNDS COME FROM (derivation, not assumption)
The official v12 package build/SMK-37_Pro_012.fwsc is a UFW container with eight
entries. Parsing it with tools/smk37_app_patch.py gives, among others:

    entry 4  type=100  name='ota.bin'  offset=0x0A63A0  size=0x4E01

and the recovered 18-byte device descriptor sits at payload offset 0x0AB185,
i.e. 0x04DE5 into that entry. On the device the same descriptor is at flash
0x0BDDE5, so the entry maps to flash base 0x0BDDE5 - 0x04DE5 = 0x0B9000 and ends
at 0x0BDE01 (the 10-byte site trailer's end). Both numbers are re-verified
against every dump here rather than trusted: the descriptor must sit at image
offset 0x04DE5 with the 10-byte trailer right after it.

WHAT IS SEARCHED (wire format only)
  * configuration chains: a config descriptor whose chain parses and sums to its
    wTotalLength (the same search the corridor tool uses, so results compare);
  * interface records (bLength 9 / bDescriptorType 4);
  * endpoint records (bLength 7 / bDescriptorType 5);
  * MIDIStreaming headers (07 24 01 <bcdADC> <wTotalLength>) and the
    class-specific records around them (07 25), plus other CS_INTERFACE forms;
  * string descriptors only when they form a walkable table from a LANGID
    anchor (04 03 09 04) - a lone `LL 03 <utf16>` inside a config blob is
    reported as text, not as a served descriptor, because the audit showed the
    surrounding records do not chain;
  * the UTF-16 product-name text at its measured offset.

Exit status: 0 when every dump yielded a search, 2 on usage/IO/fail-closed
problems (a dump that is not a whole-flash image, or a site that does not sit
where this tool's derivation says it must).

Usage:
    python3 ac79/evidence/search_updater_usb_image.py [--json OUT] dump.bin [...]
"""

import argparse
import hashlib
import json
import os
import sys

WHOLE_FLASH_SIZE = 0x100000
FLASH_SITE_DESCRIPTOR = 0x0BDDE5
FLASH_SITE_IDENTITY = 0x0BDDED
SECTOR_FILL_END = 0x0BE000
IMAGE_FLASH_BASE = 0x0B9000          # derived above
IMAGE_SIZE = 0x4E01
DESCRIPTOR_OFFSET_IN_IMAGE = 0x04DE5

IDENTITY = bytes.fromhex("4a4d5541")
DEVICE_DESCRIPTOR = bytes.fromhex("12010002000000404a4d5541000101020001")
SITE_TRAILER = bytes.fromhex("0104f0222407357df700")
PRODUCT_NAME_UTF16 = "USB Composite Device".encode("utf-16-le")
UPDATER_IMAGE_NAME = b"usb_hid_ota.bin"
LANGID_DESCRIPTOR = bytes.fromhex("04030904")
MS_HEADER_MS = bytes.fromhex("072401")   # MIDIStreaming 1.0 MS_HEADER
MS_HEADER_UAC = bytes.fromhex("072406")  # the shape the B1 fragment used
CS_ENDPOINT = bytes.fromhex("0725")
ENDPOINT_OUT_04 = bytes.fromhex("07050402")
ENDPOINT_IN_84 = bytes.fromhex("07058402")
JACK_IN = bytes.fromhex("062402")
JACK_OUT = bytes.fromhex("062403")


def count(buffer, pattern):
    found = 0
    start = 0
    while True:
        index = buffer.find(pattern, start)
        if index < 0:
            return found, []
        found += 1
        start = index + 1


def find_all(buffer, pattern):
    offsets = []
    start = 0
    while True:
        index = buffer.find(pattern, start)
        if index < 0:
            return offsets
        offsets.append(index)
        start = index + 1


def config_chains(buffer):
    """Same shape as the corridor tool: a chain that parses and sums exactly."""
    chains = []
    for start in range(max(0, len(buffer) - 10)):
        if buffer[start] != 9 or buffer[start + 1] != 0x02:
            continue
        total = buffer[start + 2] | (buffer[start + 3] << 8)
        if total < 9 or total > 512 or start + total > len(buffer):
            continue
        offset = start
        interfaces = 0
        ok = True
        while offset < start + total:
            length = buffer[offset]
            dtype = buffer[offset + 1]
            if length < 2 or offset + length > start + total:
                ok = False
                break
            if dtype == 0x04:
                interfaces += 1
            elif dtype not in (0x02, 0x05) and not (0x20 <= dtype <= 0x2F):
                ok = False
                break
            offset += length
        if ok and offset == start + total and interfaces:
            chains.append({"offset": "0x%05X" % start, "wTotalLength": total})
    return chains


def interface_records(buffer):
    """A record only counts as an interface when the fields a real interface
    must carry are in range; raw (9, 4) byte pairs are reported separately."""
    out = []
    for i in range(len(buffer) - 9):
        if buffer[i] != 9 or buffer[i + 1] != 0x04:
            continue
        record = {"offset": "0x%05X" % i,
                  "bInterfaceNumber": buffer[i + 2],
                  "bAlternateSetting": buffer[i + 3],
                  "bNumEndpoints": buffer[i + 4],
                  "bInterfaceClass": "0x%02X" % buffer[i + 5],
                  "bInterfaceSubClass": "0x%02X" % buffer[i + 6]}
        record["plausible"] = (buffer[i + 2] <= 31 and buffer[i + 3] <= 8
                               and buffer[i + 4] <= 8)
        out.append(record)
    return out


def endpoint_records(buffer):
    """bmAttributes must be one of control/iso/bulk/interrupt (0..3)."""
    out = []
    for i in range(len(buffer) - 7):
        if buffer[i] != 7 or buffer[i + 1] != 0x05:
            continue
        out.append({"offset": "0x%05X" % i,
                    "bEndpointAddress": "0x%02X" % buffer[i + 2],
                    "bmAttributes": "0x%02X" % buffer[i + 3],
                    "wMaxPacketSize": buffer[i + 4] | (buffer[i + 5] << 8),
                    "plausible": buffer[i + 3] <= 3})
    return out


def jack_records(buffer, kind):
    """MIDI jack records: 06 24 02/03 <bJackType 1|2> <bJackID> <iJack>."""
    out = []
    pattern = JACK_IN if kind == "in" else JACK_OUT
    for offset in find_all(buffer, pattern):
        if offset + 6 <= len(buffer) and buffer[offset + 3] in (1, 2):
            out.append({"offset": "0x%05X" % offset,
                        "bJackType": buffer[offset + 3],
                        "bJackID": buffer[offset + 4],
                        "iJack": buffer[offset + 5]})
    return out


def string_table(buffer):
    """Walkable string-descriptor table from a LANGID anchor, or nothing."""
    tables = []
    for anchor in find_all(buffer, LANGID_DESCRIPTOR):
        records = []
        offset = anchor
        while offset + 2 <= len(buffer):
            length = buffer[offset]
            dtype = buffer[offset + 1]
            if dtype != 0x03 or length < 4 or (length - 2) % 2 or offset + length > len(buffer):
                break
            try:
                text = buffer[offset + 2:offset + length].decode("utf-16-le")
            except Exception:
                break
            if sum(1 for c in text if 0x20 <= ord(c) < 0x7F) < len(text) * 0.9:
                break
            records.append({"offset": "0x%05X" % offset, "length": length, "text": text})
            offset += length
        if records:
            tables.append({"anchor": "0x%05X" % anchor, "records": records})
    return tables


def search_image(image):
    interfaces = interface_records(image)
    endpoints = endpoint_records(image)
    report = {
        "size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "first_16_bytes": image[:16].hex(),
        "updater_image_name_present": image.find(UPDATER_IMAGE_NAME) >= 0,
        "config_chains": config_chains(image),
        "interface_records": interfaces,
        "interface_records_plausible": sum(1 for r in interfaces if r["plausible"]),
        "endpoint_records": endpoints,
        "endpoint_records_plausible": sum(1 for r in endpoints if r["plausible"]),
        "ms_header_ms_072401": len(find_all(image, MS_HEADER_MS)),
        "ms_header_uac_072406": len(find_all(image, MS_HEADER_UAC)),
        "cs_endpoint_0725": len(find_all(image, CS_ENDPOINT)),
        "jack_in_records": jack_records(image, "in"),
        "jack_out_records": jack_records(image, "out"),
        "endpoint_out_0x04_bulk": len(find_all(image, ENDPOINT_OUT_04)),
        "endpoint_in_0x84_bulk": len(find_all(image, ENDPOINT_IN_84)),
        "langid_descriptors": ["0x%05X" % o for o in find_all(image, LANGID_DESCRIPTOR)],
        "walkable_string_tables": string_table(image),
        "product_name_utf16_offsets": [
            "0x%05X" % o for o in find_all(image, PRODUCT_NAME_UTF16)],
    }
    if report["product_name_utf16_offsets"]:
        at = int(report["product_name_utf16_offsets"][0], 16)
        report["product_name_prefix_2_bytes"] = image[at - 2:at].hex()
        report["product_name_length_utf16"] = len(PRODUCT_NAME_UTF16)
    return report


def inspect_dump(path):
    with open(path, "rb") as handle:
        dump = handle.read()
    result = {"path": os.path.abspath(path), "size": len(dump),
              "sha256": hashlib.sha256(dump).hexdigest()}
    if len(dump) != WHOLE_FLASH_SIZE:
        raise SystemExit("refusing %s: not a whole-flash 1 MiB image (%d B)"
                         % (path, len(dump)))
    identity_hits = find_all(dump, IDENTITY)
    result["identity_occurrences"] = len(identity_hits)
    if len(identity_hits) != 1:
        result["verdict"] = ("no updater site: identity occurs %d times, so there is "
                             "no single site to search" % len(identity_hits))
        return result
    if dump[0x0BDDE5:0x0BDDE5 + 18] != DEVICE_DESCRIPTOR:
        raise SystemExit("refusing %s: identity present but the site does not carry "
                         "the recovered device descriptor" % path)
    image = dump[IMAGE_FLASH_BASE:IMAGE_FLASH_BASE + IMAGE_SIZE]
    if image[DESCRIPTOR_OFFSET_IN_IMAGE:DESCRIPTOR_OFFSET_IN_IMAGE + 18] != DEVICE_DESCRIPTOR:
        raise SystemExit(
            "refusing %s: the updater image derived for flash 0x%05X..0x%05X does "
            "not carry the descriptor at offset 0x%05X, so this dump's layout is not "
            "the one this tool was written against" % (path, IMAGE_FLASH_BASE,
                                                       IMAGE_FLASH_BASE + IMAGE_SIZE,
                                                       DESCRIPTOR_OFFSET_IN_IMAGE))
    if image[DESCRIPTOR_OFFSET_IN_IMAGE + 18:
             DESCRIPTOR_OFFSET_IN_IMAGE + 18 + 10] != SITE_TRAILER:
        raise SystemExit("refusing %s: the site trailer is not at the derived offset" % path)
    result["verdict"] = "searched"
    result["flash_base"] = "0x%05X" % IMAGE_FLASH_BASE
    result["descriptor_offset_in_image"] = "0x%05X" % DESCRIPTOR_OFFSET_IN_IMAGE
    result["image"] = search_image(image)
    return result


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("dumps", nargs="*", help="whole-flash 1 MiB dumps")
    parser.add_argument("--json", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "updater-usb-image-search.json"))
    args = parser.parse_args()
    if not args.dumps:
        parser.error("give at least one whole-flash dump")

    report = {
        "schema": "smk37-updater-image-search/1",
        "purpose": ("Search the update-mode firmware image usb_hid_ota.bin "
                    "(flash 0x%05X..0x%05X, the tail of the vendor package's "
                    "ota.bin entry) for configuration/interface/endpoint/string "
                    "descriptors in wire format." % (IMAGE_FLASH_BASE,
                                                     IMAGE_FLASH_BASE + IMAGE_SIZE)),
        "derivation": {
            "vendor_package": "build/SMK-37_Pro_012.fwsc, UFW entry 4 "
                              "name='ota.bin' size=0x4E01, parsed with "
                              "tools/smk37_app_patch.py",
            "descriptor_offset_in_entry": "0x04DE5",
            "flash_site": "0x0BDDE5",
            "flash_base": "0x%05X" % IMAGE_FLASH_BASE,
            "flash_end": "0x%05X" % (IMAGE_FLASH_BASE + IMAGE_SIZE),
        },
        "dumps": [],
    }
    for path in args.dumps:
        result = inspect_dump(path)
        report["dumps"].append(result)
        image = result.get("image", {})
        print("%s" % result["path"])
        print("  sha256 %s  identity=%d  %s" % (result["sha256"][:16],
                                                result["identity_occurrences"],
                                                result["verdict"]))
        if result["verdict"] != "searched":
            continue
        print("  image: %d B at flash %s, first 16 %s, carries %s: %s"
              % (image["size"], result["flash_base"], image["first_16_bytes"],
                 UPDATER_IMAGE_NAME.decode(), image["updater_image_name_present"]))
        print("  config chains=%d  interface records=%d (plausible %d)  endpoint records=%d (plausible %d)"
              % (len(image["config_chains"]), len(image["interface_records"]),
                 image["interface_records_plausible"],
                 len(image["endpoint_records"]), image["endpoint_records_plausible"]))
        print("  MS header 072401=%d  072406=%d  CS_ENDPOINT=%d  jack records in/out=%d/%d"
              % (image["ms_header_ms_072401"], image["ms_header_uac_072406"],
                 image["cs_endpoint_0725"], len(image["jack_in_records"]),
                 len(image["jack_out_records"])))
        print("  endpoint 07050402=%d  07058402=%d"
              % (image["endpoint_out_0x04_bulk"], image["endpoint_in_0x84_bulk"]))
        print("  walkable string tables=%d  product-name text at %s (prefix %s)"
              % (len(image["walkable_string_tables"]),
                 image["product_name_utf16_offsets"],
                 image.get("product_name_prefix_2_bytes", "-")))

    with open(args.json, "w") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")
    print("\nwrote %s" % args.json)


if __name__ == "__main__":
    main()
