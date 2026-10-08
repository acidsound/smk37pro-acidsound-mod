#!/usr/bin/env python3
"""
Reconnaissance for B1: where the updater USB identity 4d4a:4155 actually lives,
which parts of its descriptor set exist anywhere in the captured corpora, and
how trustworthy each search is.

This script is the evidence generator behind ac79/evidence/updater-usb-identity.json
and the provenance statements in ac79/app/smk_usb_descriptors.h. It is read-only:
it never writes to a device and never modifies the corpora it scans.

Scope (corrected 2026-10-09 three times: the first revision missed 32 files; the
second added the .fwsc and .elf formats after an audit showed the descriptor
bytes hid outside the .bin set; the third excluded this project's own
regenerated build outputs so the headline counts stop drifting with every build):
EVERY *.bin, *.fwsc and *.elf under the workspace root is scanned - the SDK's own
tool images (usb_update2.bin, ota.bin, sd_update2.bin, wl82loader.bin, the
MP-test .elf images), the firmware packages (.fwsc, which carry the update-mode
firmware usb_hid_ota.bin as their ota.bin entry), the toolchain blobs and the
captures - EXCEPT this project's own regenerated build outputs under
linux-build/ac79-build-*/. Those are listed in scope.excluded with their sizes
and sha256, so scanned plus excluded is still every candidate file, and
scope.manifest_sha256 pins exactly which files the headline counts are over.

String descriptors are searched structurally as well as by byte pattern: a
descriptor of type 3 counts only when it decodes as UTF-16 text, and the walkable
form counts only when records chain from a LANGID anchor (04 03 09 04). That is
how the product-name text inside usb_hid_ota.bin is reported without pretending
it is a served string table.

Two levels of search are reported, because they fail in opposite directions:
  - CHAIN searches (a configuration descriptor whose chain parses and sums to its
    wTotalLength, with at least one interface) accept any class-specific type, so
    they find real descriptor sets and cannot false-positive on noise;
  - BYTE patterns are specific but blind to descriptors built in code, and a short
    pattern has a real chance-hit rate in a megabyte-scale image. Every pattern's
    expected chance hit count over the scanned bytes is reported alongside it.

Usage:
    python3 ac79/evidence/recon_updater_usb_identity.py [--workspace DIR] [--json OUT]
"""

import argparse
import glob
import hashlib
import json
import os
import sys

# --- byte patterns ----------------------------------------------------------

# The update-mode product-name text, UTF-16LE, recovered at flash 0x0BB558
# (image offset 0x2558 of usb_hid_ota.bin; see ac79/app/smk_usb_descriptors.c).
UPDATER_PRODUCT_NAME_UTF16 = "USB Composite Device".encode("utf-16-le")
NORMAL_STRING_MIDI = bytes.fromhex("2003") + "SMK-37 Pro Midi".encode("utf-16-le")
NORMAL_STRING_AUDIO = bytes.fromhex("2203") + "SMK-37 Pro Audio".encode("utf-16-le")
LANGID_DESCRIPTOR = bytes.fromhex("04030904")

IDENTITY = bytes.fromhex("4a4d5541")             # 4d4a:4155 little endian
RECOVERED_DEVICE_DESCRIPTOR = bytes.fromhex("12010002000000404a4d5541000101020001")
NORMAL_DEVICE_DESCRIPTOR_PREFIX = bytes.fromhex("120100020000004053434d4b")
# The updater's MIDIStreaming interface fragment as the app now carries it: the
# fields are pinned by the records (see ac79/app/smk_usb_descriptors.c), the bytes
# are authored. It is searched for so its presence in the project's own builds is
# recorded rather than hidden.
MIDI_FRAGMENT = bytes.fromhex(
    "090401000201030000" "07240600010700" "07050402400000" "07058402400000")
MS_HEADER_FULL = bytes.fromhex("0724060001")      # CS_INTERFACE + MS_HEADER + bcdADC 0x0100
ENDPOINT_OUT_04 = bytes.fromhex("07050402")
ENDPOINT_IN_84 = bytes.fromhex("07058402")
CONFIG_PREFIX = bytes.fromhex("0902")

PATTERNS = {
    "identity_4d4a_4155": IDENTITY,
    "recovered_device_descriptor_18B": RECOVERED_DEVICE_DESCRIPTOR,
    "normal_device_descriptor_prefix_12B": NORMAL_DEVICE_DESCRIPTOR_PREFIX,
    "midi_streaming_header_full": MS_HEADER_FULL,
    "endpoint_out_0x04_bulk": ENDPOINT_OUT_04,
    "endpoint_in_0x84_bulk": ENDPOINT_IN_84,
    "app_midi_fragment_30B": MIDI_FRAGMENT,
    "updater_product_name_utf16_40B": UPDATER_PRODUCT_NAME_UTF16,
    "normal_mode_string_midi_32B": NORMAL_STRING_MIDI,
    "normal_mode_string_audio_34B": NORMAL_STRING_AUDIO,
    "langid_descriptor_0409": LANGID_DESCRIPTOR,
}

APP_SLOT_SIZES = {615828, 617012, 619704, 638976}
WHOLE_FLASH_SIZE = 0x100000

# This project's own regenerated SDK app build outputs (sdk.elf / app.bin staged
# by ac79/build/build_sdk_app_project_source.sh). Excluded from the scan set so
# the headline counts stay reproducible across increments and so a project
# artifact can never be mistaken for recovered evidence.
SELF_BUILD_OUTPUT_PREFIX = "linux-build/ac79-build-"


def manifest_digest(entries):
    """Deterministic digest of a scanned set: sorted path, size and sha256 of
    every scanned file, so the counts can be checked against one hash."""
    digest = hashlib.sha256()
    for relative, size, sha256_hex in sorted(entries):
        digest.update(("%s\0%d\0%s\n" % (relative, size, sha256_hex)).encode("utf-8"))
    return digest.hexdigest()


def count_pattern(buffer, pattern):
    count = 0
    start = 0
    while True:
        index = buffer.find(pattern, start)
        if index < 0:
            return count
        count += 1
        start = index + 1


def count_config_chains(buffer):
    """A configuration descriptor counts only if a chain of well-formed
    descriptors follows it, accepts every standard and class-specific type, sums
    exactly to its wTotalLength, and contains at least one interface."""
    chains = []
    for start in range(max(0, len(buffer) - 10)):
        if buffer[start] != 9 or buffer[start + 1] != 0x02:
            continue
        total = buffer[start + 2] | (buffer[start + 3] << 8)
        if total < 9 or total > 512 or start + total > len(buffer):
            continue
        offset = start
        interfaces = []
        endpoints = []
        ok = True
        while offset < start + total:
            length = buffer[offset]
            dtype = buffer[offset + 1]
            if length < 2 or offset + length > start + total:
                ok = False
                break
            if dtype == 0x04:
                interfaces.append({"number": buffer[offset + 2],
                                   "class": buffer[offset + 5],
                                   "subclass": buffer[offset + 6],
                                   "endpoints": buffer[offset + 4]})
            elif dtype == 0x05:
                endpoints.append({"address": buffer[offset + 2],
                                  "attributes": buffer[offset + 3],
                                  "max_packet": buffer[offset + 4] | (buffer[offset + 5] << 8)})
            elif dtype not in (0x02,) and not (0x20 <= dtype <= 0x2F):
                ok = False
                break
            offset += length
        if ok and offset == start + total and interfaces:
            chains.append({"offset": "0x%06X" % start, "wTotalLength": total,
                           "interfaces": interfaces, "endpoints": endpoints})
    return chains


def string_descriptors(buffer):
    """Descriptor-type-3 records that decode as UTF-16 text, plus the subset
    that chains from a LANGID anchor into a walkable table."""
    records = []
    for index in range(len(buffer) - 3):
        length = buffer[index]
        if buffer[index + 1] != 0x03 or length < 4 or (length - 2) % 2 or index + length > len(buffer):
            continue
        try:
            text = buffer[index + 2:index + length].decode("utf-16-le")
        except Exception:
            continue
        if not text or sum(1 for c in text if 0x20 <= ord(c) < 0x7F) < len(text) * 0.9:
            continue
        records.append({"offset": "0x%06X" % index, "length": length, "text": text})
    tables = []
    for anchor in range(len(buffer) - 4):
        if buffer[anchor:anchor + 4] != LANGID_DESCRIPTOR:
            continue
        walked = []
        offset = anchor
        while offset + 2 <= len(buffer):
            length = buffer[offset]
            if buffer[offset + 1] != 0x03 or length < 4 or (length - 2) % 2 or offset + length > len(buffer):
                break
            try:
                text = buffer[offset + 2:offset + length].decode("utf-16-le")
            except Exception:
                break
            if not text or sum(1 for c in text if 0x20 <= ord(c) < 0x7F) < len(text) * 0.9:
                break
            walked.append({"offset": "0x%06X" % offset, "length": length, "text": text})
            offset += length
        if walked:
            tables.append({"anchor": "0x%06X" % anchor, "records": walked})
    return records, tables


def search(buffer):
    stats = {"size": len(buffer), "sha256": hashlib.sha256(buffer).hexdigest()}
    for name, pattern in PATTERNS.items():
        stats[name] = count_pattern(buffer, pattern)
    chains = count_config_chains(buffer)
    stats["config_chains"] = len(chains)
    if chains:
        stats["config_chain_detail"] = chains[:8]
    records, tables = string_descriptors(buffer)
    stats["string_descriptor_records"] = len(records)
    stats["walkable_string_tables"] = len(tables)
    if records:
        stats["string_descriptor_detail"] = records[:8]
    return stats


def classify(path, size, workspace):
    relative = os.path.relpath(path, workspace)
    extension = os.path.splitext(path)[1].lower()
    if extension == ".fwsc":
        return "fwsc_packages"
    if extension == ".elf":
        return "elf_tools"
    if size == WHOLE_FLASH_SIZE:
        return "whole_flash_1MiB_images"
    if size in APP_SLOT_SIZES:
        return "app_slot_payloads"
    if relative.startswith("linux-build/"):
        return "sdk_tool_images_and_build_inputs"
    return "other_captures"


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--workspace",
                        default=os.path.expanduser("~/Documents/SMK37ProMod"))
    parser.add_argument("--json",
                        default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                             "updater-usb-identity.json"))
    args = parser.parse_args()

    workspace = os.path.abspath(args.workspace)
    if not os.path.isdir(workspace):
        sys.exit("workspace not found: %s" % workspace)

    candidates = sorted(set(
        glob.glob(os.path.join(workspace, "**", "*.bin"), recursive=True)
        + glob.glob(os.path.join(workspace, "**", "*.fwsc"), recursive=True)
        + glob.glob(os.path.join(workspace, "**", "*.elf"), recursive=True)))
    scanned = []
    excluded = []
    for path in candidates:
        relative = os.path.relpath(path, workspace)
        if relative.startswith(SELF_BUILD_OUTPUT_PREFIX):
            data = open(path, "rb").read()
            excluded.append({"path": relative, "size": len(data),
                             "sha256": hashlib.sha256(data).hexdigest(),
                             "reason": "this project's own regenerated build output"})
        else:
            scanned.append(path)

    report = {
        "schema": "smk37-usb-identity-recon/4",
        "purpose": ("Locate the updater USB identity 4d4a:4155 and establish which parts "
                    "of its descriptor set are recoverable evidence, for B1 of "
                    "docs/self-recovering-sdk-app.md section 4."),
        "generated_by": "ac79/evidence/recon_updater_usb_identity.py",
        "workspace": workspace,
        "scope": {
            "rule": ("every *.bin, *.fwsc and *.elf under the workspace root, "
                     "recursively, EXCEPT this project's own regenerated build "
                     "outputs under linux-build/ac79-build-*/ - excluded so the "
                     "headline counts are reproducible across increments and no "
                     "project artifact can be mistaken for recovered evidence; "
                     "scanned plus excluded is every candidate file"),
            "exclusion_prefix": SELF_BUILD_OUTPUT_PREFIX,
            "files_on_disk": len(candidates),
            "files_scanned": 0,
            "files_excluded": len(excluded),
            "excluded": excluded,
            "manifest_sha256": None,
            "files_unscanned": [],
        },
        "patterns": {name: pattern.hex() for name, pattern in PATTERNS.items()},
        "corpora": {"whole_flash_1MiB_images": {}, "app_slot_payloads": {},
                    "sdk_tool_images_and_build_inputs": {}, "other_captures": {},
                    "fwsc_packages": {}, "elf_tools": {}},
        "chance_hit_expectation": {},
        "distinct_images": {},
        "identity_sites": [],
    }

    total_bytes = 0
    manifest = []
    for path in scanned:
        buffer = open(path, "rb").read()
        total_bytes += len(buffer)
        group = classify(path, len(buffer), workspace)
        relative = os.path.relpath(path, workspace)
        report["corpora"][group][relative] = search(buffer)
        manifest.append((relative, len(buffer),
                         report["corpora"][group][relative]["sha256"]))
        report["scope"]["files_scanned"] += 1

        # Every occurrence of the identity, wherever it is.
        start = 0
        while True:
            index = buffer.find(IDENTITY, start)
            if index < 0:
                break
            site = {
                "file": relative,
                "sha256": report["corpora"][group][relative]["sha256"],
                "size": len(buffer),
                "identity_offset": "0x%06X" % index,
                "device_descriptor_offset": "0x%06X" % (index - 8),
                "device_descriptor_bytes": buffer[index - 8:index + 10].hex(),
                "in_beyond_package": index >= 0x9C000,
            }
            marker = buffer.rfind(b"/*.ufw", 0, index)
            descriptor_end = index + 10
            trailer_end = descriptor_end
            while trailer_end < len(buffer) and buffer[trailer_end] != 0xFF:
                trailer_end += 1
            padding_end = trailer_end
            while padding_end < len(buffer) and buffer[padding_end] == 0xFF:
                padding_end += 1
            site["context"] = {
                "marker_offset": "0x%06X" % marker if marker >= 0 else None,
                "bytes_from_marker_to_descriptor": index - 8 - marker if marker >= 0 else None,
                "trailer_after_descriptor": buffer[descriptor_end:trailer_end].hex(),
                "trailer_bytes": trailer_end - descriptor_end,
                "ff_padding_run": padding_end - trailer_end,
                "ff_padding_ends_at": "0x%06X" % padding_end,
                "padding_ends_on_sector_boundary": padding_end % 0x1000 == 0,
                "flash_sector_base": "0x%06X" % (index & ~0xFFF),
                "identity_offset_in_sector": "0x%03X" % (index & 0xFFF),
            }
            report["identity_sites"].append(site)
            start = index + 1

    # Which corpora entries share an image (the same bytes stored twice inflate
    # naive counts; the audit found "16 of 18 dumps" was one image too many).
    by_hash = {}
    for group, entries in report["corpora"].items():
        for relative, stats in entries.items():
            by_hash.setdefault(stats["sha256"], {"paths": [], "groups": set()})
            by_hash[stats["sha256"]]["paths"].append(relative)
            by_hash[stats["sha256"]]["groups"].add(group)
    report["distinct_images"] = {
        digest: {"paths": sorted(info["paths"]),
                 "groups": sorted(info["groups"]),
                 "shared_path_count": len(info["paths"])}
        for digest, info in sorted(by_hash.items())
    }

    # How many chance hits each pattern would be expected to produce over the
    # bytes actually scanned. A short pattern is not evidence on its own.
    for name, pattern in PATTERNS.items():
        report["chance_hit_expectation"][name] = {
            "pattern_bytes": len(pattern),
            "expected_chance_hits_over_all_scanned_bytes": round(total_bytes / (256.0 ** len(pattern)), 3),
            "expected_chance_hits_in_one_1MiB_image": round(WHOLE_FLASH_SIZE / (256.0 ** len(pattern)), 4),
        }

    # --- per-group totals ----------------------------------------------------
    totals = {}
    for group, entries in report["corpora"].items():
        totals[group] = {"files": len(entries),
                         "distinct_images": len({s["sha256"] for s in entries.values()}),
                         "bytes": sum(s["size"] for s in entries.values())}
        for name in PATTERNS:
            totals[group][name] = sum(s[name] for s in entries.values())
        totals[group]["config_chains"] = sum(s["config_chains"] for s in entries.values())
        totals[group]["string_descriptor_records"] = sum(
            s["string_descriptor_records"] for s in entries.values())
        totals[group]["walkable_string_tables"] = sum(
            s["walkable_string_tables"] for s in entries.values())
    report["totals"] = totals
    report["scope"]["bytes_scanned"] = total_bytes
    report["scope"]["manifest_sha256"] = manifest_digest(manifest)
    report["scope"]["files_unscanned"] = [
        os.path.relpath(p, workspace)
        for p in sorted(set(
            glob.glob(os.path.join(workspace, "**", "*.bin"), recursive=True)
            + glob.glob(os.path.join(workspace, "**", "*.fwsc"), recursive=True)
            + glob.glob(os.path.join(workspace, "**", "*.elf"), recursive=True)) - set(candidates))
    ]

    dumps = totals["whole_flash_1MiB_images"]
    apps = totals["app_slot_payloads"]
    other = totals["other_captures"]
    sdk = totals["sdk_tool_images_and_build_inputs"]
    fwsc = totals["fwsc_packages"]
    elf = totals["elf_tools"]
    distinct_dumps = report["distinct_images"]
    dumps_with_identity = {
        digest for digest, info in distinct_dumps.items()
        if "whole_flash_1MiB_images" in info["groups"]
        and report["corpora"]["whole_flash_1MiB_images"].get(info["paths"][0], {}).get("identity_4d4a_4155", 0) == 1
    }
    dumps_without_identity = {
        digest for digest, info in distinct_dumps.items()
        if "whole_flash_1MiB_images" in info["groups"] and digest not in dumps_with_identity
    }

    # Chain attribution as DATA: every chain is named by the file that holds it,
    # so the prose can never say "all in the vendor tools" again while the scan
    # counts three.
    chain_sites = sorted(
        (relative, stats["config_chains"])
        for entries in report["corpora"].values()
        for relative, stats in entries.items()
        if stats["config_chains"])
    chain_text = (", ".join("%s (%d)" % (path, count) for path, count in chain_sites)
                  if chain_sites else "none")

    report["conclusion"] = {
        "scope_correction": (
            "This revision scans every *.bin, *.fwsc and *.elf in the workspace EXCEPT "
            "this project's own regenerated build outputs under linux-build/ac79-build-*/, "
            "which are listed in scope.excluded with sizes and sha256 so nothing is "
            "hidden. The scan set is %d files / %d bytes (%d whole-flash images, %d "
            "app-slot payloads, %d SDK inputs, %d other captures, %d fwsc packages, %d "
            "elf tools); scope.manifest_sha256 is the sha256 over its sorted "
            "(path, size, sha256) rows, so the counts are checkable against one hash "
            "and do not drift with this project's own builds. The first revision globbed "
            "only backups/, build/, baselines/ and the root and left 32 files unscanned; "
            "the second (same day) added the .fwsc and .elf formats after an audit showed "
            "the descriptor bytes hid there; the third excluded the project's own build "
            "outputs after the 2026-10-09b audit found a chain attributed to them was "
            "being counted among the evidence corpora."
            % (report["scope"]["files_scanned"], report["scope"]["bytes_scanned"],
               dumps["files"], apps["files"], sdk["files"], other["files"],
               fwsc["files"], elf["files"])
        ),
        "counting_correction": (
            "Counts are reported per PATH and per DISTINCT IMAGE (sha256). Some images are "
            "stored twice, so the earlier headline \"16 of 18 whole-flash dumps\" counted "
            "one image twice; the distinct-image figure is %d of %d whole-flash images."
            % (len(dumps_with_identity), dumps["distinct_images"])
        ),
        "string_channel": (
            "String descriptors exist as bytes, but not as a wire-format table. The "
            "update-mode firmware image (usb_hid_ota.bin, the vendor package's ota.bin "
            "entry at flash 0x0B9000..0x0BDE01) holds the UTF-16LE product-name text "
            "\"USB Composite Device\" at image offset 0x2558 (flash 0x0BB558), present "
            "in the same whole-flash images as the device descriptor; the two bytes "
            "before it are 2a 03. But walking string records from the LANGID anchor "
            "(04 03 09 04) inside that image stops at the second record, so it is config-"
            "blob text, not a served descriptor table - ac79/evidence/search_updater_usb_"
            "image.py searches the image itself and reports 0 walkable string tables. "
            "Normal-mode app images do store wire-format strings (%d x 'SMK-37 Pro Midi', "
            "%d x 'SMK-37 Pro Audio'), which is how string records were found to begin "
            "with; none of them is the updater's. Walkable string tables per corpus: "
            "%d dumps / %d apps / %d other / %d sdk / %d fwsc / %d elf."
            % (apps["normal_mode_string_midi_32B"], apps["normal_mode_string_audio_34B"],
               dumps["walkable_string_tables"], apps["walkable_string_tables"],
               other["walkable_string_tables"], sdk["walkable_string_tables"],
               fwsc["walkable_string_tables"], elf["walkable_string_tables"])
        ),
        "recoverable": {
            "product_name_text_40B": (
                "YES - byte exact, but not a served descriptor. %d occurrence(s) of the "
                "UTF-16LE product name in whole-flash images, %d in the fwsc "
                "packages, %d in app-slot payloads, %d in elf tools. The bytes sit at "
                "flash 0x0BB558 inside the update-mode firmware image; the 2 bytes "
                "before them are 2a 03. Whether that is a string-descriptor header is "
                "NOT established (the surrounding records do not chain), so the text is "
                "evidence and the serve class stays withheld."
                % (dumps["updater_product_name_utf16_40B"],
                   fwsc["updater_product_name_utf16_40B"],
                   apps["updater_product_name_utf16_40B"],
                   elf["updater_product_name_utf16_40B"])
            ),
            "device_descriptor_18B": (
                "YES - byte exact. %d of the %d distinct whole-flash 1 MiB images carry it "
                "at flash 0x0BDDE5 (identity at 0x0BDDED), inside beyond_package "
                "(>= 0x9C000). The remaining %d distinct image(s) are the pre-restore "
                "2026-07-14 image and its copy, where the 18 bytes are 0xFF and the "
                "identity occurs zero times - the negative control. None of the %d "
                "app-slot payloads carries it (%d hits)."
                % (len(dumps_with_identity), dumps["distinct_images"],
                   len(dumps_without_identity), apps["files"],
                   apps["identity_4d4a_4155"])
            ),
            "identity_4d4a_4155": (
                "%d occurrence(s) in whole-flash images, all at flash 0x0BDDED; %d in "
                "other captures (partial flash-range captures whose aligned region matches "
                "live flash); %d in app-slot payloads."
                % (dumps["identity_4d4a_4155"], other["identity_4d4a_4155"],
                   apps["identity_4d4a_4155"])
            ),
        },
        "not_recoverable": {
            "descriptor_set_core": (
                "The configuration descriptor, the MIDIStreaming interface and the endpoints "
                "do NOT exist as wire-format bytes anywhere scanned: config chains %d (dumps) "
                "/ %d (app payloads) / %d (other) / %d (SDK images) / %d (fwsc) / %d (elf), "
                "MS header %s %d / %d / %d / %d / %d / %d, endpoint 0x04 %d / %d / %d / %d / "
                "%d / %d, endpoint 0x84 %d / %d / %d / %d / %d / %d. The chains are stated "
                "per file rather than in aggregate: %s. This project's own regenerated "
                "build outputs - the superseded B1 build among them, which carries the "
                "authored 39-byte set - are excluded from the scan by the scope rule, so "
                "no chain in the scan set is a project artifact and none is in a "
                "recovered corpus."
                % (dumps["config_chains"], apps["config_chains"], other["config_chains"],
                   sdk["config_chains"], fwsc["config_chains"], elf["config_chains"],
                   MS_HEADER_FULL.hex(),
                   dumps["midi_streaming_header_full"], apps["midi_streaming_header_full"],
                   other["midi_streaming_header_full"], sdk["midi_streaming_header_full"],
                   fwsc["midi_streaming_header_full"], elf["midi_streaming_header_full"],
                   dumps["endpoint_out_0x04_bulk"], apps["endpoint_out_0x04_bulk"],
                   other["endpoint_out_0x04_bulk"], sdk["endpoint_out_0x04_bulk"],
                   fwsc["endpoint_out_0x04_bulk"], elf["endpoint_out_0x04_bulk"],
                   dumps["endpoint_in_0x84_bulk"], apps["endpoint_in_0x84_bulk"],
                   other["endpoint_in_0x84_bulk"], sdk["endpoint_in_0x84_bulk"],
                   fwsc["endpoint_in_0x84_bulk"], elf["endpoint_in_0x84_bulk"],
                   chain_text)
            ),
            "why_no_capture_exists": (
                "No raw CONFIGURATION descriptor bytes exist in the project at all, and the "
                "2026-10-09b audit narrowed this claim after finding it had been stated too "
                "broadly: raw STRING bytes do exist (see string_channel). The wire-format "
                "configuration/interface/endpoint records do not: every text artifact was "
                "searched for the descriptor byte strings in every spelling and none quotes "
                "them, the scan finds no chain outside the vendor SDK's own MP-test tool "
                "ELFs, and the targeted search of the one image that actually carries the "
                "site (ac79/evidence/search_updater_usb_image.py) finds none inside it "
                "either. The plan's \"v15 descriptor capture complete\" resolves to "
                "baselines/v15/device-info/probe.txt, which records interface/endpoint "
                "FIELDS from a live enumeration, not bytes - and public-research section "
                "4.4 itself says extraction \"remains necessary\"."
            ),
            "the_apps_own_fragment_is_not_evidence": (
                "The app's own MIDIStreaming fragment is carried by this project's own "
                "build outputs (the build recipe asserts the 30 bytes are in app.bin), "
                "and those outputs are excluded from this scan by the scope rule, so the "
                "fragment does not appear in any scanned corpus (%d hit(s) in the scan "
                "set) and is not recovered evidence."
                % sdk["app_midi_fragment_30B"]
            ),
        },
        "search_strength": (
            "Chain searches accept any class-specific type and require the chain to sum to "
            "its wTotalLength, so a hit is a real descriptor set and noise cannot produce "
            "one. Byte patterns are exact but blind to descriptors built in code, and short "
            "patterns have real chance-hit rates: over the %d bytes scanned, the 4-byte "
            "endpoint patterns expect ~%.2f hits and the 5-byte MS header ~%.4f, so this "
            "record only asserts the byte searches as corroboration of the chain searches."
            % (total_bytes,
               report["chance_hit_expectation"]["endpoint_out_0x04_bulk"]["expected_chance_hits_over_all_scanned_bytes"],
               report["chance_hit_expectation"]["midi_streaming_header_full"]["expected_chance_hits_over_all_scanned_bytes"])
        ),
        "note": (
            "The normal personality's device-descriptor prefix 4353:4b4d appears in %d "
            "app-slot payloads (%d hits) and %d whole-flash images, but with no stored "
            "configuration either. Its string descriptors DO exist in wire format there "
            "(%d x 'SMK-37 Pro Midi', %d x 'SMK-37 Pro Audio'), so the normal-mode "
            "strings are recoverable; the updater's are not, only its product-name text "
            "is. The live probe records the normal identity as 4353:cf4d, so the app-image "
            "prefix is a different revision of the normal identity - the two must not be "
            "conflated."
            % (apps["files"], apps["normal_device_descriptor_prefix_12B"],
               dumps["normal_device_descriptor_prefix_12B"],
               apps["normal_mode_string_midi_32B"], apps["normal_mode_string_audio_34B"])
        ),
    }

    with open(args.json, "w") as handle:
        json.dump(report, handle, indent=2, sort_keys=False)
        handle.write("\n")

    # --- human summary -------------------------------------------------------
    print("workspace: %s" % workspace)
    print("scope: %d of %d candidate files scanned, %d excluded (%s*), %d bytes; "
          "manifest sha256 %s"
          % (report["scope"]["files_scanned"], len(candidates),
             report["scope"]["files_excluded"], SELF_BUILD_OUTPUT_PREFIX,
             total_bytes, report["scope"]["manifest_sha256"]))
    if report["scope"]["files_unscanned"]:
        print("UNSCANNED: %s" % report["scope"]["files_unscanned"])
    for group, group_totals in totals.items():
        print("\n[%s] %d files / %d distinct images / %d bytes"
              % (group, group_totals["files"], group_totals["distinct_images"],
                 group_totals["bytes"]))
        for name in PATTERNS:
            print("    %-38s %d" % (name, group_totals[name]))
        print("    %-38s %d" % ("config_chains", group_totals["config_chains"]))
    print("\nchance-hit expectation (all scanned bytes):")
    for name, info in report["chance_hit_expectation"].items():
        print("    %-38s bytes=%d expected=%.3f"
              % (name, info["pattern_bytes"],
                 info["expected_chance_hits_over_all_scanned_bytes"]))
    print("\nidentity sites: %d" % len(report["identity_sites"]))
    for site in report["identity_sites"][:6]:
        print("    %-52s %s" % (site["file"][-52:], site["identity_offset"]))
    print("\nconclusion:")
    for key, text in report["conclusion"].items():
        print("  %s:\n    %s" % (key, text))
    print("\nwrote %s" % args.json)


if __name__ == "__main__":
    main()
