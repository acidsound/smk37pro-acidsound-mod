#!/usr/bin/env python3
"""Build the official-v15/S1-C2-parent-only S1-C3 16-slot boundary diagnostic.

Offline builder only. It changes only the parent S1-C2 live v2 BSS-size and
HEAP_BEGIN immediates to reserve the data-model's 16-slot volatile RAM layout.
It never opens a device transport, flashes, resets, or sends MIDI.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(HERE))

from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_OFFSET,
    APP_DATA_SIZE,
    AppImage,
    Ufw,
    compact_ranges,
    difference_offsets,
    protected_hashes,
    unpack_fwsc,
)

FORMAT = "smk37-v15-s1c3-16slot-boundary-only"
RUNTIME_BASE = 0x02000000
APP_SIZE = APP_DATA_SIZE
SECTOR_SIZE = 0x2000
PROTECTED_PREFIX_END = 0x4000
PACKAGE_NAME = "SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc"

S1C2_DIR = HERE.parent / "S1C2-two-slot-selector-live-v2"
OFFICIAL_FWSC = S1C2_DIR / "inputs" / "SMK-37_Pro_015.fwsc"
S1C2_PARENT_APP = S1C2_DIR / "app.bin"
S1C2_PARENT_FWSC = S1C2_DIR / "SMK37Pro-v15-S1C2-two-slot-selector-live-v2.fwsc"

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c2_parent_app": "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
    "s1c2_parent_fwsc": "63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e",
}

BOOT_BSS_SIZE_ADDR = 0x0200001E
HEAP_BEGIN_ADDR = 0x0205E9F8
PARENT_BSS_BYTES = bytes.fromhex("c2ff8ccc0300")
CHILD_BSS_BYTES = bytes.fromhex("c2ffdcd50300")
PARENT_HEAP_BYTES = bytes.fromhex("c5ff6066c401")
CHILD_HEAP_BYTES = bytes.fromhex("c5ffb06fc401")

BSS_ZERO_START = 0x01C099D4
OFFICIAL_HEAP_BEGIN = 0x01C46520
H2_HEAP_BEGIN = 0x01C465C0
S1C2_PARENT_HEAP_BEGIN = 0x01C46660
PATCH_SET_BASE = 0x01C46520
PATCH_SET_HEAP_BEGIN = 0x01C46FB0
PATCH_SET_SIZE = PATCH_SET_HEAP_BEGIN - PATCH_SET_BASE
PARENT_TO_CHILD_ADDITIONAL = PATCH_SET_HEAP_BEGIN - S1C2_PARENT_HEAP_BEGIN
H2_TO_CHILD_ADDITIONAL = PATCH_SET_HEAP_BEGIN - H2_HEAP_BEGIN
BSS_ZERO_SIZE = PATCH_SET_HEAP_BEGIN - BSS_ZERO_START
BSS_EXTENSION_VS_OFFICIAL = PATCH_SET_HEAP_BEGIN - 0x01C4651C


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def off(address: int) -> int:
    value = address - RUNTIME_BASE
    require(0 <= value < APP_SIZE, f"address outside app: 0x{address:08x}")
    return value


def patch_exact(output: bytearray, before: bytes, address: int, old: bytes, new: bytes, purpose: str) -> dict[str, Any]:
    start = off(address)
    end = start + len(old)
    require(before[start:end] == old, f"old bytes mismatch at 0x{address:08x}: {before[start:end].hex()} != {old.hex()}")
    output[start:end] = new
    return {
        "address": f"0x{address:08x}",
        "file_offset": start,
        "old_hex": old.hex(),
        "new_hex": new.hex(),
        "changed_byte_offsets_in_app": [start + i for i, (a, b) in enumerate(zip(old, new)) if a != b],
        "purpose": purpose,
    }


def extract_app_from_fwsc(path: Path) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    if sha256(raw) == EXPECTED["official_fwsc"]:
        payload, _metadata = unpack_fwsc(raw)
    else:
        payload, _metadata = unpack_nonofficial_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def unpack_nonofficial_fwsc(raw: bytes) -> tuple[bytearray, bytes]:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    require(len(raw) == 701_140, "FWSC size")
    metadata = bytes(raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for index in range(FWSC_SLOTS))
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    require(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "payload size")
    return payload, metadata


def boundary_manifest() -> dict[str, Any]:
    return {
        "data_model_required_reservation_bytes": PATCH_SET_SIZE,
        "data_model_required_reservation_hex": f"0x{PATCH_SET_SIZE:04x}",
        "patch_set_base": f"0x{PATCH_SET_BASE:08x}",
        "patch_set_end_exclusive": f"0x{PATCH_SET_HEAP_BEGIN:08x}",
        "official_heap_begin": f"0x{OFFICIAL_HEAP_BEGIN:08x}",
        "h2_h0_heap_begin": f"0x{H2_HEAP_BEGIN:08x}",
        "s1c2_parent_heap_begin": f"0x{S1C2_PARENT_HEAP_BEGIN:08x}",
        "candidate_heap_begin": f"0x{PATCH_SET_HEAP_BEGIN:08x}",
        "additional_bytes_over_s1c2_parent": PARENT_TO_CHILD_ADDITIONAL,
        "additional_hex_over_s1c2_parent": f"0x{PARENT_TO_CHILD_ADDITIONAL:04x}",
        "additional_bytes_over_h2_h0": H2_TO_CHILD_ADDITIONAL,
        "additional_hex_over_h2_h0": f"0x{H2_TO_CHILD_ADDITIONAL:04x}",
        "boot_bss_zero_start": f"0x{BSS_ZERO_START:08x}",
        "boot_bss_zero_end_exclusive": f"0x{PATCH_SET_HEAP_BEGIN:08x}",
        "boot_bss_zero_size_bytes": BSS_ZERO_SIZE,
        "boot_bss_zero_size_hex": f"0x{BSS_ZERO_SIZE:08x}",
        "boot_bss_extension_vs_official_bytes": BSS_EXTENSION_VS_OFFICIAL,
        "boot_bss_extension_vs_official_hex": f"0x{BSS_EXTENSION_VS_OFFICIAL:04x}",
        "boundary_bytes": {
            "bss_size_instruction_address": f"0x{BOOT_BSS_SIZE_ADDR:08x}",
            "s1c2_parent_bss_size_hex": PARENT_BSS_BYTES.hex(),
            "candidate_bss_size_hex": CHILD_BSS_BYTES.hex(),
            "heap_begin_instruction_address": f"0x{HEAP_BEGIN_ADDR:08x}",
            "s1c2_parent_heap_begin_hex": PARENT_HEAP_BYTES.hex(),
            "candidate_heap_begin_hex": CHILD_HEAP_BYTES.hex(),
        },
        "layout": [
            {"range": "0x01c46520..0x01c46f20", "size_hex": "0x0a00", "purpose": "16 slot records at stride 0xa0"},
            {"range": "0x01c46520..0x01c465bc", "size_hex": "0x009c", "purpose": "slot 0 voice, exact H2 source"},
            {"address": "0x01c465bc", "size": 1, "purpose": "slot 0 valid, exact H2 valid"},
            {"address": "0x01c465bd", "size": 1, "purpose": "global nonblocking producer lock, exact H2 lock"},
            {"range": "0x01c46f20..0x01c46fb0", "size_hex": "0x0090", "purpose": "header plus 128-entry note_to_slot map"},
        ],
    }


def build_app(parent: bytes, official_app: bytes) -> tuple[bytes, dict[str, Any]]:
    require(len(parent) == APP_SIZE and sha256(parent) == EXPECTED["s1c2_parent_app"], "S1-C2 parent app hash")
    require(len(official_app) == APP_SIZE and sha256(official_app) == EXPECTED["official_app"], "official app hash")
    require(PATCH_SET_SIZE == 0x0A90, "patch-set reservation arithmetic")
    require(BSS_ZERO_SIZE == 0x0003D5DC, "BSS zero size arithmetic")
    require(PARENT_TO_CHILD_ADDITIONAL == 0x0950, "parent additional reservation arithmetic")
    require(H2_TO_CHILD_ADDITIONAL == 0x09F0, "H2 additional reservation arithmetic")

    output = bytearray(parent)
    changes = [
        patch_exact(output, parent, BOOT_BSS_SIZE_ADDR, PARENT_BSS_BYTES, CHILD_BSS_BYTES,
                    "parent-only boundary: extend boot BSS zeroing from S1-C2 end 0x01c46660 through 0x01c46fb0"),
        patch_exact(output, parent, HEAP_BEGIN_ADDR, PARENT_HEAP_BYTES, CHILD_HEAP_BYTES,
                    "parent-only boundary: move S1-C2 HEAP_BEGIN forward to full 16-slot layout end 0x01c46fb0"),
    ]
    parent_diffs = difference_offsets(parent, output)
    expected_parent_diffs = sorted(offset for change in changes for offset in change["changed_byte_offsets_in_app"])
    require(parent_diffs == expected_parent_diffs, "unexpected S1-C2-parent-relative app diffs")
    official_diffs = difference_offsets(official_app, output)
    return bytes(output), {
        "format": FORMAT + ".app-manifest-v1",
        "artifact_scope": "offline S1-C2-parent-only boundary diagnostic; no new selector, parser, persistence, packet, or 16-slot consumption behavior",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "app_size": len(output),
        "official_app_sha256": EXPECTED["official_app"],
        "s1c2_parent_app_sha256": EXPECTED["s1c2_parent_app"],
        "output_app_sha256": sha256(output),
        "changes": changes,
        "s1c2_parent_relative_changed_byte_count": len(parent_diffs),
        "s1c2_parent_relative_changed_ranges": compact_ranges(parent_diffs),
        "official_relative_changed_byte_count": len(official_diffs),
        "official_relative_changed_ranges": compact_ranges(official_diffs),
        "boundary": boundary_manifest(),
        "invariants": {
            "s1c2_code_byte_identical_except_boundary_immediates": True,
            "new_executable_bytes": 0,
            "new_packets_or_host_protocol": False,
            "selector_behavior": "unchanged exact S1-C2 live v2 two-slot selector",
            "save_policy": "unchanged exact S1-C2 live v2 inherited H2 no-write block",
            "sixteen_slot_consumption": False,
        },
    }


def repack(input_fwsc: Path, app_path: Path, package_path: Path, manifest_path: Path) -> None:
    subprocess.run([sys.executable, str(HERE / "smk37_v15_app_patch.py"), "repack-app", str(input_fwsc), str(app_path), str(package_path), "--manifest", str(manifest_path)], check=True)


def validate_package_and_rollback(stock_raw: bytes, stock_flash: bytes | bytearray, stock_app: bytes, parent_raw: bytes, parent_flash: bytes | bytearray, parent_app: bytes, candidate_app: bytes, package_path: Path, output_dir: Path) -> dict[str, Any]:
    cand_raw, cand_flash, cand_app = extract_app_from_fwsc(package_path)
    require(cand_app == candidate_app, "package embeds candidate app")
    official_app_diffs = difference_offsets(stock_app, candidate_app)
    official_flash_diffs = difference_offsets(stock_flash, cand_flash)
    official_raw_diffs = difference_offsets(stock_raw, cand_raw)
    parent_app_diffs = difference_offsets(parent_app, candidate_app)
    parent_flash_diffs = difference_offsets(parent_flash, cand_flash)
    parent_raw_diffs = difference_offsets(parent_raw, cand_raw)
    expected_official_flash_offsets = sorted(APP_DATA_OFFSET + item for item in official_app_diffs)
    require(not (set(expected_official_flash_offsets) - set(official_flash_diffs)), "missing app diffs in flash")
    metadata_flash_offsets = sorted(set(official_flash_diffs) - set(expected_official_flash_offsets))
    require(not [item for item in metadata_flash_offsets if not (0x4000 <= item < 0x4100)], "unexpected non-app flash diffs")
    require(not any(item < PROTECTED_PREFIX_END for item in official_flash_diffs), "protected prefix unchanged")
    sectors = sorted({item - (item % SECTOR_SIZE) for item in official_flash_diffs})
    parent_sectors = sorted({item - (item % SECTOR_SIZE) for item in parent_flash_diffs})
    rollback_dir = output_dir / "rollback" / "official-v15-recovery-sectors"
    if rollback_dir.exists():
        shutil.rmtree(rollback_dir)
    rollback_dir.mkdir(parents=True, exist_ok=True)
    sector_entries = []
    for base in sectors:
        data = bytes(stock_flash[base:base + SECTOR_SIZE])
        name = f"official-v15-sector-{base:05x}.bin"
        (rollback_dir / name).write_bytes(data)
        sector_entries.append({"sector_base": f"0x{base:05x}", "size": len(data), "sha256": sha256(data), "file": f"rollback/official-v15-recovery-sectors/{name}"})
    reconstructed = bytearray(cand_flash)
    for base in sectors:
        reconstructed[base:base + SECTOR_SIZE] = stock_flash[base:base + SECTOR_SIZE]
    require(bytes(reconstructed) == bytes(stock_flash), "rollback sectors restore official flash")
    write_json(rollback_dir / "manifest.json", {
        "format": FORMAT + ".official-v15-sector-rollback-v1",
        "scope": "official-v15 exact changed flash sectors only; no device action performed",
        "sector_size": SECTOR_SIZE,
        "changed_sector_count": len(sector_entries),
        "changed_sectors": sector_entries,
        "official_flash_sha256": sha256(stock_flash),
        "candidate_flash_sha256": sha256(cand_flash),
        "reconstructed_flash_sha256": sha256(reconstructed),
        "rollback_restores_official_flash": True,
    })
    return {
        "validation_gate": "PASS",
        "package_sha256": sha256(cand_raw),
        "package_size": len(cand_raw),
        "app_sha256": sha256(candidate_app),
        "official_package_sha256": sha256(stock_raw),
        "official_app_sha256": sha256(stock_app),
        "s1c2_parent_package_sha256": sha256(parent_raw),
        "s1c2_parent_app_sha256": sha256(parent_app),
        "candidate_flash_sha256": sha256(cand_flash),
        "official_flash_sha256": sha256(stock_flash),
        "s1c2_parent_flash_sha256": sha256(parent_flash),
        "changed_app_byte_count_vs_official": len(official_app_diffs),
        "changed_app_ranges_vs_official": compact_ranges(official_app_diffs),
        "changed_app_byte_count_vs_s1c2_parent": len(parent_app_diffs),
        "changed_app_ranges_vs_s1c2_parent": compact_ranges(parent_app_diffs),
        "changed_flash_byte_count_vs_official": len(official_flash_diffs),
        "changed_flash_ranges_vs_official": compact_ranges(official_flash_diffs),
        "changed_flash_byte_count_vs_s1c2_parent": len(parent_flash_diffs),
        "changed_flash_ranges_vs_s1c2_parent": compact_ranges(parent_flash_diffs),
        "changed_package_byte_count_vs_official": len(official_raw_diffs),
        "changed_package_ranges_vs_official": compact_ranges(official_raw_diffs),
        "changed_package_byte_count_vs_s1c2_parent": len(parent_raw_diffs),
        "changed_package_ranges_vs_s1c2_parent": compact_ranges(parent_raw_diffs),
        "expected_app_flash_offsets_match": True,
        "repacker_metadata_flash_offsets": [f"0x{item:05x}" for item in metadata_flash_offsets],
        "changed_flash_sectors_vs_official": [f"0x{item:05x}" for item in sectors],
        "changed_flash_sectors_vs_s1c2_parent": [f"0x{item:05x}" for item in parent_sectors],
        "protected_prefix_0x0000_0x3fff_unchanged": True,
        "protected_hashes_official": protected_hashes(bytearray(stock_flash)),
        "protected_hashes_candidate": protected_hashes(bytearray(cand_flash)),
        "rollback_manifest": "rollback/official-v15-recovery-sectors/manifest.json",
        "rollback_restores_official_flash": True,
    }


def render_report(evidence: dict[str, Any]) -> str:
    app = evidence["app"]; pkg = evidence["package"]; boundary = app["boundary"]
    token = evidence["flash"]["confirmation_token"]; command = evidence["flash"]["upload_command"]
    return f"""# S1-C3 16-slot boundary-only diagnostic PASS

Date: 2026-08-03 UTC  
Status: **PASS, boundary-only candidate built offline**  
Scope: exact official v15 package plus exact live-PASS S1-C2 live v2 parent app. No device access, flash, OTA, reset, or MIDI traffic was performed.

## Decision

This is a narrow S1-C2-parent-only boundary diagnostic. It is **not** a functional 16-slot implementation and does not claim heap headroom or 16-slot consumption. The build is defensible only because it changes exactly two parent instructions, four app bytes total, and preserves all S1-C2 live v2 code and behavior:

- boot BSS zero size at `0x0200001e`: `{boundary['boundary_bytes']['s1c2_parent_bss_size_hex']}` -> `{boundary['boundary_bytes']['candidate_bss_size_hex']}`;
- HEAP_BEGIN immediate at `0x0205e9f8`: `{boundary['boundary_bytes']['s1c2_parent_heap_begin_hex']}` -> `{boundary['boundary_bytes']['candidate_heap_begin_hex']}`.

## Exact reservation and boundaries

- Required full 16-slot data-model reservation: `{boundary['data_model_required_reservation_hex']}` bytes.
- Reserved RAM: `{boundary['patch_set_base']}..{boundary['patch_set_end_exclusive']}`.
- Candidate HEAP_BEGIN: `{boundary['candidate_heap_begin']}`.
- Boot BSS zero: `{boundary['boot_bss_zero_start']}..{boundary['boot_bss_zero_end_exclusive']}`, size `{boundary['boot_bss_zero_size_hex']}`.
- Additional over exact S1-C2 parent: `{boundary['additional_hex_over_s1c2_parent']}` bytes.
- Additional over H2/H0 first owned-source reservation: `{boundary['additional_hex_over_h2_h0']}` bytes.

Layout admitted from the data-model:

| Range/address | Size | Purpose |
|---|---:|---|
| `0x01c46520..0x01c46f20` | `0x0a00` | 16 slot records at stride `0xa0` |
| `0x01c46520..0x01c465bc` | `0x009c` | slot 0 voice, exact H2 source |
| `0x01c465bc` | 1 | slot 0 valid, exact H2 valid |
| `0x01c465bd` | 1 | global nonblocking producer lock, exact H2 lock |
| `0x01c46f20..0x01c46fb0` | `0x0090` | header plus 128-entry note map |

## Artifacts

- App: `app.bin`, SHA-256 `{app['output_app_sha256']}`.
- FWSC: `{PACKAGE_NAME}`, SHA-256 `{pkg['package_sha256']}`.
- Official-v15 rollback: `{pkg['rollback_manifest']}`.
- S1-C2-parent-relative app changed bytes: `{app['s1c2_parent_relative_changed_byte_count']}`.
- Official-v15 changed flash sectors: `{', '.join(pkg['changed_flash_sectors_vs_official'])}`.
- S1-C2-parent-relative changed flash sectors: `{', '.join(pkg['changed_flash_sectors_vs_s1c2_parent'])}`.

## Flash command, if later explicitly authorized

Offline check:

```sh
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc tools/smk37_v15_s1c3_boundary_ota.c src/device_info.c src/fwsc.c src/protocol.c src/sha256.c src/usb_probe.c -o build/smk37-v15-s1c3-boundary-ota $(pkg-config --cflags --libs libusb-1.0)
build/smk37-v15-s1c3-boundary-ota check baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/{PACKAGE_NAME}
```

Upload command/token:

```sh
{command}
```

Confirmation token: `{token}`

## Evidence boundary and risk

Live evidence used:

- H0/H2 established the first owned-source boundary at `0x01c46520..0x01c465c0` and live H2 consumption of slot 0.
- S1-C1 live-PASS established the additional `0xa0` boundary-only shift through `0x01c46660` while preserving H2 behavior.
- S1-C2 live v2 is the exact parent and established the current two-slot selector/producer package behavior.
- The data-model requires `0x0a90` bytes for 16 resident `0x9c` payload slots plus the 128-note map/header.

This candidate still needs later live heap-headroom testing. It does not close the data-model functional blockers: Pad enumeration, private 16-slot ingress, full selector/map implementation, and stress proof.

## Validation

`validation.txt` records exact official/S1-C2 parent hashes, exact parent bytes before patching, exactly four S1-C2-parent-relative app-byte changes, package embedding, official-v15 rollback reconstruction, and SHA256 inventory.
"""


def render_validate_py() -> str:
    return r'''#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent
PACKAGE = HERE / "SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc"
APP = HERE / "app.bin"
EVIDENCE = HERE / "evidence.json"
SHA256SUMS = HERE / "SHA256SUMS"
def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
def req(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"FAIL: {msg}")
def main() -> int:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    app = evidence["app"]; pkg = evidence["package"]; boundary = app["boundary"]
    req(sha256(APP) == app["output_app_sha256"], "app hash")
    req(sha256(PACKAGE) == pkg["package_sha256"], "package hash")
    req(boundary["data_model_required_reservation_hex"] == "0x0a90", "reservation")
    req(boundary["candidate_heap_begin"] == "0x01c46fb0", "heap begin")
    req(boundary["boot_bss_zero_size_hex"] == "0x0003d5dc", "BSS size")
    req(app["s1c2_parent_relative_changed_byte_count"] == 4, "parent diff count")
    req(pkg["changed_flash_sectors_vs_official"] == ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"], "official changed sectors")
    req(pkg["changed_flash_sectors_vs_s1c2_parent"] == ["0x04000", "0x62000"], "parent changed sectors")
    req(pkg["rollback_restores_official_flash"] is True, "rollback restores official")
    for line in SHA256SUMS.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        req(sha256(HERE / rel) == digest, f"SHA256SUMS {rel}")
    print("S1-C3 16-slot boundary-only validation PASS")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_tool(package_sha: str) -> str:
    pretty = ", ".join(f"0x{package_sha[i:i+2]}" for i in range(0, 64, 2))
    token = f"INSTALL-SMK37PRO-V15-S1C3-16SLOT-BOUNDARY-{package_sha[:8].upper()}"
    return f'''/* Exact-hash v15-only OTA uploader for S1-C3 16-slot boundary-only diagnostic. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{
    {pretty},
}};
static const char CONFIRM[] = "{token}";
static const char DESCRIPTION[] =
    "SMK37ProMod v15 S1-C3 16-slot boundary-only diagnostic";
/* `check` is offline-only; `upload` is the only transport path and requires CONFIRM. */
static int check_exact(const char *path) {{
    struct smk37_fwsc firmware;
    int status = 1;
    if (!smk37_fwsc_load(path, &firmware)) return 1;
    if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 &&
        memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{
        printf("exact v15 S1-C3 16-slot boundary-only package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length);
        status = 0;
    }} else {{
        fputs("offline check rejected: not exact S1-C3 16-slot boundary-only package\\n", stderr);
    }}
    smk37_fwsc_free(&firmware);
    return status;
}}
static void usage(const char *program) {{
    fprintf(stderr, "usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n", program, program, CONFIRM);
}}
int main(int argc, char **argv) {{
    if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]);
    if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) {{
        return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM,
            "v15 S1-C3 boundary diagnostic installed; S1-C2 behavior preserved, heap shifted to 0x01c46fb0");
    }}
    usage(argv[0]);
    return 2;
}}
'''


def sha_inventory(output_dir: Path) -> None:
    include = []
    for path in sorted(p for p in output_dir.rglob("*") if p.is_file()):
        rel = path.relative_to(output_dir).as_posix()
        if rel == "SHA256SUMS" or "__pycache__" in path.parts: continue
        include.append((sha256_path(path), rel))
    (output_dir / "SHA256SUMS").write_text("".join(f"{digest}  {rel}\n" for digest, rel in include), encoding="utf-8")


def main() -> int:
    require(sha256_path(OFFICIAL_FWSC) == EXPECTED["official_fwsc"], "official FWSC hash")
    require(sha256_path(S1C2_PARENT_APP) == EXPECTED["s1c2_parent_app"], "S1-C2 parent app hash")
    require(sha256_path(S1C2_PARENT_FWSC) == EXPECTED["s1c2_parent_fwsc"], "S1-C2 parent FWSC hash")
    stock_raw, stock_flash, stock_app = extract_app_from_fwsc(OFFICIAL_FWSC)
    parent_raw, parent_flash, parent_app = extract_app_from_fwsc(S1C2_PARENT_FWSC)
    require(parent_app == S1C2_PARENT_APP.read_bytes(), "S1-C2 package app matches parent app")
    candidate_app, app_manifest = build_app(parent_app, stock_app)
    app_path = HERE / "app.bin"; package_path = HERE / PACKAGE_NAME; package_manifest_path = HERE / "package-manifest.json"
    app_path.write_bytes(candidate_app)
    write_json(HERE / "app-manifest.json", app_manifest)
    repack(OFFICIAL_FWSC, app_path, package_path, package_manifest_path)
    package_evidence = validate_package_and_rollback(stock_raw, stock_flash, stock_app, parent_raw, parent_flash, parent_app, candidate_app, package_path, HERE)
    token = f"INSTALL-SMK37PRO-V15-S1C3-16SLOT-BOUNDARY-{package_evidence['package_sha256'][:8].upper()}"
    upload_command = "build/smk37-v15-s1c3-boundary-ota upload " + f"baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/{PACKAGE_NAME} " + "baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/live-install-YYYYMMDDTHHMMZ.txt " + f"--confirm {token}"
    evidence = {
        "format": FORMAT,
        "decision": "PASS",
        "candidate_built": True,
        "scope": "offline-only; no device access; S1-C2-parent-only boundary diagnostic",
        "app": app_manifest,
        "package": package_evidence,
        "flash": {"offline_check_command": f"build/smk37-v15-s1c3-boundary-ota check baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/{PACKAGE_NAME}", "upload_command": upload_command, "confirmation_token": token},
        "evidence_inputs": {
            "official_v15_app_sha256": EXPECTED["official_app"],
            "official_v15_fwsc_sha256": EXPECTED["official_fwsc"],
            "h2_live_policy_source": "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/report.md",
            "s1c1_live_boundary_source": "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/live-validation-20260802.md",
            "s1c2_live_parent_source": "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/live-validation-20260803.md",
            "data_model_source": "baselines/v15/analysis/patch-set-ui/data-model/report.md",
        },
        "risk_statement": "PASS is only for deterministic boundary diagnostic packaging. Functional 16-slot implementation and heap headroom remain unproven until later live/stress gates.",
    }
    write_json(HERE / "evidence.json", evidence)
    (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
    (HERE / "validate.py").write_text(render_validate_py(), encoding="utf-8")
    (ROOT / "tools" / "smk37_v15_s1c3_boundary_ota.c").write_text(render_tool(package_evidence["package_sha256"]), encoding="utf-8")
    (HERE / "validation.txt").write_text("\n".join([
        "S1-C3 16-slot boundary-only build validation PASS",
        f"app_sha256={app_manifest['output_app_sha256']}",
        f"package_sha256={package_evidence['package_sha256']}",
        f"required_reservation=0x{PATCH_SET_SIZE:04x}",
        f"bss_zero_size=0x{BSS_ZERO_SIZE:08x}",
        f"candidate_heap_begin=0x{PATCH_SET_HEAP_BEGIN:08x}",
        f"parent_relative_changed_app_bytes={app_manifest['s1c2_parent_relative_changed_byte_count']}",
        "changed_flash_sectors_vs_official=" + ",".join(package_evidence["changed_flash_sectors_vs_official"]),
        "changed_flash_sectors_vs_s1c2_parent=" + ",".join(package_evidence["changed_flash_sectors_vs_s1c2_parent"]),
        f"rollback_restores_official_flash={package_evidence['rollback_restores_official_flash']}",
        f"confirmation_token={token}",
    ]) + "\n", encoding="utf-8")
    sha_inventory(HERE)
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
