#!/usr/bin/env python3
"""Pre-flash link-layout gate for a Jieli AC79 (wl82/SFC) SDK application.

The 2026-08-15 SMK-37 Pro brick happened because the flashed SDK app was linked
with the SDK default 'sdram' layout: .data/.bss and the malloc heap were placed
at 0x04000000, a window the device's boot chain does not establish. Nothing in
the offline package gates looked at the link map, so it was never noticed.
docs/usb-flash-safety-case.md gate P4 cites this tool; this file restores it to
the repository and reads its windows from the target definition in
ac79/target/smk37pro-ac7911b8.json.

This gate refuses to pass unless every allocatable section of the input lands
fully inside a window that is PROVEN present on this unit (or inside an
explicitly allow-listed platform slot). SDRAM is refused with the brick reason,
and RAM0 above the stock v15 high-water mark is refused as unproven.

Usage:
  python3 tools/check_sdk_app_layout.py <sdk.map|sdk.elf> [--app app.bin]
                                       [--json out.json] [--target FILE]
  python3 tools/check_sdk_app_layout.py --check-target
  python3 tools/check_sdk_app_layout.py --self-test

Exit codes: 0 = PASS, 1 = REFUSE (layout unsafe), 2 = usage/parse error.

Offline only. Reads a map or ELF file (and optionally app.bin); writes nothing
unless --json is given. No device, USB, flash or OTA access.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TARGET = REPO_ROOT / "ac79" / "target" / "smk37pro-ac7911b8.json"

# Sources that name a path inside this repository; everything else (URLs, the
# local build workspace) is recorded but not existence-checked.
REPO_SOURCE_PREFIXES = (
    "ac79/", "baselines/", "docs/", "logs/", "patches/", "patch-set-editor/",
    "recovery/", "scripts/", "src/", "tools/", "apps/", "esp32c3-usbkey/",
)

SECTION_RE = re.compile(r"^(\.[A-Za-z0-9_.\-]+)\s+0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s*$")

# Sections that are never loaded into the target image. Section-header tables
# list them with address 0x0; they must not be judged as placements.
NON_ALLOC_PREFIXES = (
    ".debug", ".comment", ".note", ".symtab", ".strtab", ".shstrtab",
    ".gnu", ".llvm", ".rel.", ".mdebug", ".group",
)

SHT_NULL = 0


class TargetError(Exception):
    pass


def _addr(value) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    raise TargetError(f"cannot read address {value!r}")


def load_target(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text())
    except OSError as exc:
        raise TargetError(f"cannot read target file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise TargetError(f"target file {path} is not valid JSON: {exc}") from exc

    fmt = raw.get("format", "")
    if not fmt.startswith("smk37-ac79-target"):
        raise TargetError(f"{path}: unexpected format {fmt!r}")
    windows = raw.get("windows")
    if not isinstance(windows, dict):
        raise TargetError(f"{path}: missing windows object")
    normalized = {"format": fmt}
    for kind in ("allowed", "forbidden", "unproven"):
        entries = windows.get(kind)
        if not isinstance(entries, list) or not entries:
            raise TargetError(f"{path}: windows.{kind} must be a non-empty list")
        normalized[kind] = []
        for entry in entries:
            for key in ("id", "name", "start", "end_exclusive", "reason", "evidence"):
                if key not in entry:
                    raise TargetError(f"{path}: window {entry.get('id', '?')} misses {key}")
            start = _addr(entry["start"])
            end = _addr(entry["end_exclusive"])
            if not 0 <= start < end <= 0xFFFFFFFF:
                raise TargetError(f"{path}: window {entry['id']} has an invalid range")
            normalized[kind].append({
                "id": entry["id"],
                "name": entry["name"],
                "start": start,
                "end": end,
                "reason": entry["reason"],
                "evidence": entry["evidence"],
            })

    slot = raw.get("build", {}).get("app_slot_max_bytes")
    if not isinstance(slot, int) or slot <= 0:
        raise TargetError(f"{path}: build.app_slot_max_bytes must be a positive integer")
    normalized["app_slot_max_bytes"] = slot
    normalized["raw"] = raw
    normalized["path"] = str(path)
    return normalized


def parse_map_text(text: str):
    sections = []
    skipped = []
    for line in text.splitlines():
        match = SECTION_RE.match(line.strip())
        if not match:
            continue
        name, addr, size = match.group(1), int(match.group(2), 16), int(match.group(3), 16)
        if size == 0:
            continue
        if name.startswith(NON_ALLOC_PREFIXES):
            skipped.append(name)
            continue
        sections.append({"name": name, "start": addr, "end": addr + size, "size": size})
    return sections, skipped


def parse_elf32_sections(data: bytes):
    """Section placements of a little-endian ELF32 (pi32v2) image."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ValueError("only little-endian ELF32 is supported")
    e_shoff, = struct.unpack_from("<I", data, 0x20)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x2E)
    if e_shoff == 0 or e_shnum == 0:
        raise ValueError("ELF has no section header table")
    if e_shnum * e_shentsize + e_shoff > len(data):
        raise ValueError("section header table runs past end of file")

    def read_sh(index):
        off = e_shoff + index * e_shentsize
        name_off, sh_type, _flags, addr, _offset, size = struct.unpack_from("<IIIIII", data, off)
        return name_off, sh_type, addr, size

    strtab_name, _strtab_type, _strtab_addr, _strtab_size = read_sh(e_shstrndx)
    strtab_off = struct.unpack_from("<I", data, e_shoff + e_shstrndx * e_shentsize + 0x10)[0]

    def name_at(offset: int) -> str:
        end = data.index(b"\0", strtab_off + offset)
        return data[strtab_off + offset:end].decode("utf-8", "replace")

    sections = []
    skipped = []
    for index in range(e_shnum):
        name_off, sh_type, addr, size = read_sh(index)
        if sh_type == SHT_NULL or size == 0:
            continue
        name = name_at(name_off)
        if name.startswith(NON_ALLOC_PREFIXES) or not name:
            skipped.append(name)
            continue
        sections.append({"name": name, "start": addr, "end": addr + size, "size": size})
    if not sections:
        raise ValueError("no allocatable sections found in ELF")
    return sections, skipped


def classify(section: dict, target: dict):
    for window in target["forbidden"]:
        if section["start"] < window["end"] and section["end"] > window["start"]:
            return False, window["reason"], window["id"]
    for window in target["unproven"]:
        if section["start"] < window["end"] and section["end"] > window["start"]:
            return False, window["reason"], window["id"]
    for window in target["allowed"]:
        if section["start"] >= window["start"] and section["end"] <= window["end"]:
            return True, window["reason"], window["id"]
    return (
        False,
        "not inside any allow-listed window; extend the allow-list only with "
        "positive evidence that the window exists on this unit",
        None,
    )


def check(sections, app_bytes, target: dict):
    results = []
    ok = True
    for section in sections:
        allowed, reason, window = classify(section, target)
        results.append({
            "section": section["name"],
            "start": f"0x{section['start']:08x}",
            "end_exclusive": f"0x{section['end']:08x}",
            "size": section["size"],
            "allowed": allowed,
            "window": window,
            "reason": reason,
        })
        if not allowed:
            ok = False
    if app_bytes is not None:
        ceiling = target["app_slot_max_bytes"]
        if len(app_bytes) > ceiling:
            ok = False
            results.append({
                "section": "<app.bin size>",
                "start": "n/a",
                "end_exclusive": "n/a",
                "size": len(app_bytes),
                "allowed": False,
                "window": None,
                "reason": f"app.bin is {len(app_bytes)} B but the v15 application ceiling is {ceiling} B",
            })
    return ok, results


def _window_payload(windows):
    return [
        {
            "window": w["id"],
            "name": w["name"],
            "start": f"0x{w['start']:08x}",
            "end_exclusive": f"0x{w['end']:08x}",
            "reason": w["reason"],
        }
        for w in windows
    ]


def check_target(target: dict) -> int:
    problems = []
    all_windows = []
    for kind in ("allowed", "forbidden", "unproven"):
        for window in target[kind]:
            all_windows.append((kind, window))

    for index, (kind_a, a) in enumerate(all_windows):
        for kind_b, b in all_windows[index + 1:]:
            if a["start"] < b["end"] and a["end"] > b["start"]:
                problems.append(f"windows overlap: {kind_a}:{a['id']} vs {kind_b}:{b['id']}")

    checked = 0
    missing = 0
    skipped = 0
    sources = []
    for _kind, window in all_windows:
        sources.extend(window["evidence"])
    raw = target["raw"]
    for key in ("flash_layout",):
        for row in raw.get(key, []):
            sources.extend(row.get("evidence", []))
    for row in raw.get("known_builds", []):
        sources.extend(row.get("evidence", []))
    sources.extend(raw.get("target", {}).get("part_evidence", []))
    sources.extend(raw.get("target", {}).get("flash_evidence", []))
    for define in raw.get("build", {}).get("required_defines", []):
        sources.extend(define.get("evidence", []))
    for transfer in raw.get("transfers_from_fm1_project", []):
        sources.extend(transfer.get("evidence", []))
    for question in raw.get("open_questions", []):
        sources.extend(question.get("evidence", []))

    for source in sources:
        candidate = source.split(" ")[0]
        if "://" in candidate or candidate.startswith("~") or candidate.startswith("linux-build/"):
            skipped += 1
            continue
        if not candidate.startswith(REPO_SOURCE_PREFIXES):
            skipped += 1
            continue
        checked += 1
        if not (REPO_ROOT / candidate).exists():
            missing += 1
            problems.append(f"evidence path does not exist in the repo: {candidate}")

    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    print(f"target: {target['path']}")
    print(f"windows: {len(target['allowed'])} allowed, {len(target['forbidden'])} forbidden, "
          f"{len(target['unproven'])} unproven; app ceiling {target['app_slot_max_bytes']} B")
    print(f"evidence paths: {checked} checked in-repo, {missing} missing, {skipped} external/annotated")
    if problems:
        print("TARGET GATE: FAIL")
        return 1
    print("TARGET GATE: PASS")
    return 0


FIXTURE_TARGET = {
    "allowed": [
        {"id": "xip", "name": "xip", "start": 0x02000120, "end": 0x02096B54, "reason": "xip window", "evidence": []},
        {"id": "ram0_proven", "name": "ram0", "start": 0x01C00000, "end": 0x01C4651C, "reason": "ram0 window", "evidence": []},
        {"id": "cache_ram", "name": "cache", "start": 0x01F20000, "end": 0x01F30000, "reason": "cache window", "evidence": []},
        {"id": "boot_info_slot", "name": "boot info", "start": 0x01C7FD50, "end": 0x01C7FD80, "reason": "boot info slot", "evidence": []},
        {"id": "updata_beg", "name": "updata", "start": 0x01C7FD80, "end": 0x01C7FE00, "reason": "updata slot", "evidence": []},
    ],
    "forbidden": [
        {"id": "sdram", "name": "sdram", "start": 0x04000000, "end": 0x04200000, "reason": "SDRAM window. This is the 2026-08-15 brick.", "evidence": []},
    ],
    "unproven": [
        {"id": "ram0_above_stock", "name": "ram0 above", "start": 0x01C4651C, "end": 0x01C7FD50, "reason": "RAM0 above the stock high-water mark is unproven.", "evidence": []},
    ],
    "app_slot_max_bytes": 617012,
}

GOOD_MAP = """
.text           0x0000000002000120    0x15de0
.data           0x0000000001c00000      0x988
.bss            0x0000000001c009a0     0x2bb0
.ram0_data      0x0000000001c080f8     0x1000
.cache_ram_data 0x0000000001f20000      0x400
.boot_info      0x0000000001c7fd50       0x28
.debug_info     0x0000000000000000    0x345fd
"""

BAD_SDRAM_MAP = """
.text           0x0000000002000120    0x15de0
.data           0x0000000004000000      0x988
.bss            0x00000000040009a0     0x2bb0
.ram0_data      0x0000000001c00000     0x80f8
.debug_info     0x0000000000000000    0x345fd
"""

BAD_UNPROVEN_MAP = """
.text           0x0000000002000120    0x15de0
.data           0x0000000001c50000      0x988
.bss            0x0000000001c60000      0x400
"""


def self_test() -> int:
    good_sections, good_skipped = parse_map_text(GOOD_MAP)
    ok_good, _ = check(good_sections, None, FIXTURE_TARGET)
    if not ok_good:
        print("SELF-TEST FAIL: a fully proven layout was rejected", file=sys.stderr)
        return 1
    if ".debug_info" not in good_skipped:
        print("SELF-TEST FAIL: a non-allocatable debug section was judged as a placement", file=sys.stderr)
        return 1

    bad_sections, _ = parse_map_text(BAD_SDRAM_MAP)
    ok_bad, bad_results = check(bad_sections, None, FIXTURE_TARGET)
    if ok_bad:
        print("SELF-TEST FAIL: an SDRAM link map was accepted", file=sys.stderr)
        return 1
    offenders = [r for r in bad_results if not r["allowed"]]
    if not any(r["section"] == ".data" and r["window"] == "sdram" for r in offenders):
        print("SELF-TEST FAIL: .data was not identified as the SDRAM offender", file=sys.stderr)
        return 1

    unproven_sections, _ = parse_map_text(BAD_UNPROVEN_MAP)
    ok_unproven, unproven_results = check(unproven_sections, None, FIXTURE_TARGET)
    if ok_unproven:
        print("SELF-TEST FAIL: a RAM0-above-high-water layout was accepted", file=sys.stderr)
        return 1
    if not all(r["window"] == "ram0_above_stock" for r in unproven_results if not r["allowed"]):
        print("SELF-TEST FAIL: the unproven-RAM0 reason was not applied", file=sys.stderr)
        return 1

    oversized_ok, oversized_results = check(good_sections, b"\0" * (FIXTURE_TARGET["app_slot_max_bytes"] + 1), FIXTURE_TARGET)
    if oversized_ok or not any(r["section"] == "<app.bin size>" for r in oversized_results):
        print("SELF-TEST FAIL: an oversized app.bin was accepted", file=sys.stderr)
        return 1

    if check(*parse_map_text(BAD_SDRAM_MAP)[:1], None, FIXTURE_TARGET)[0]:
        print("SELF-TEST FAIL: result is not deterministic", file=sys.stderr)
        return 1

    print("SELF-TEST PASS: proven layout accepted, SDRAM refused with .data named, "
          "unproven RAM0 refused, oversized app refused, debug sections skipped")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse unsafe AC79 (wl82) SDK app link layouts before flashing.")
    parser.add_argument("input", nargs="?", help="sdk.map or sdk.elf")
    parser.add_argument("--target", default=str(DEFAULT_TARGET), help="target definition JSON")
    parser.add_argument("--app", help="optional app.bin to size-check")
    parser.add_argument("--json", help="optional path to write the full result as JSON")
    parser.add_argument("--check-target", action="store_true", help="validate only the target definition")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if not args.input and not args.check_target:
        parser.print_usage(sys.stderr)
        return 2

    try:
        target = load_target(Path(args.target))
    except TargetError as exc:
        print(f"target error: {exc}", file=sys.stderr)
        return 2

    if args.check_target:
        return check_target(target)

    raw = Path(args.input).read_bytes()
    try:
        if raw[:4] == b"\x7fELF":
            sections, skipped = parse_elf32_sections(raw)
            kind = "elf"
        else:
            sections, skipped = parse_map_text(raw.decode("utf-8", "replace"))
            kind = "map"
    except (ValueError, IndexError, struct.error) as exc:
        print(f"parse error: {exc}", file=sys.stderr)
        return 2
    if not sections:
        print("parse error: no allocatable sections parsed from the input", file=sys.stderr)
        return 2

    app_bytes = None
    app_sha = None
    if args.app:
        try:
            app_bytes = Path(args.app).read_bytes()
        except OSError as exc:
            print(f"cannot read app: {exc}", file=sys.stderr)
            return 2
        app_sha = hashlib.sha256(app_bytes).hexdigest()

    ok, results = check(sections, app_bytes, target)

    payload = {
        "format": "smk37-sdk-app-layout-gate-v1",
        "target": target["path"],
        "input": {"kind": kind, "file": args.input},
        "app": args.app,
        "app_size": len(app_bytes) if app_bytes is not None else None,
        "app_sha256": app_sha,
        "verdict": "PASS" if ok else "REFUSE",
        "allow_list": _window_payload(target["allowed"]),
        "forbidden": _window_payload(target["forbidden"]),
        "unproven": _window_payload(target["unproven"]),
        "sections": results,
        "skipped_non_alloc_sections": skipped,
    }

    for result in results:
        mark = "ok  " if result["allowed"] else "FAIL"
        print(f"{mark} {result['section']:<16} {result['start']}..{result['end_exclusive']} ({result['size']} B)")
        if not result["allowed"]:
            print(f"       -> {result['reason']}")

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")

    if skipped:
        unique = sorted(set(skipped))
        print(f"(ignored {len(skipped)} non-allocatable sections: {', '.join(unique[:6])}"
              f"{' ...' if len(unique) > 6 else ''})")

    if ok:
        print("LAYOUT GATE: PASS")
        return 0
    print("LAYOUT GATE: REFUSE - do not flash this binary", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
