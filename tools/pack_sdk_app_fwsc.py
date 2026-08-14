#!/usr/bin/env python3
"""Pack a Jieli-SDK-built app.bin into the SMK-37 Pro v15 OTA (FWSC/UFW) format.

This is the "from-scratch platform" P0b/P0c bridge: an app.bin produced by
the Jieli AC79 SDK build (text+data+ram0_data+cache_ram_data concatenation,
per the SDK post-build) is substituted into the byte-exact official v15 FWSC
package as the application content, so the device's existing OTA path
(exact_ota) can flash it without any new host tooling.

The substitution keeps every structure byte-identical except the app content:
  - flash layout: protected boot 0x0000..0x3fff, JLFS app-area/app.bin headers
    at 0x4000/0x4020, app data at 0x4120 (617,012 B), protected tail
  - UFW wrapper (header + 8 entries + SFC encryption)
  - FWSC metadata slots

The SDK app.bin is padded with 0xFF to the fixed 617,012 B app-data slot so
all sizes/offsets stay the same.  Only app content bytes and the recomputed
CRCs change (audited by build_package).

Offline only: no device, USB, MIDI, OTA upload, flash, reset, or live send.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_SIZE,
    FWSC_BLOCK_SIZE,
    FWSC_DATA_SIZE,
    FWSC_SLOTS,
    AppImage,
    FormatError,
    Ufw,
    build_package,
    inspect_package,
    require,
    sha256,
)

DEFAULT_TEMPLATE = ROOT / "build" / "SMK-37_Pro_015.fwsc"

EXACT_OTA_TEMPLATE = """\
/* Exact-hash v15-only OTA wrapper for {name}.
 * Default check mode is offline-only; upload requires the exact confirmation token.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "../../../../../src/ota.c"
static const uint8_t PACKAGE_SHA256[SMK37_SHA256_LENGTH] = {{ {bytes} }};
static const char CONFIRM[] = "{token}";
static const char DESCRIPTION[] = "{description}";
static int check_exact(const char *path) {{ struct smk37_fwsc firmware; int status = 1; if (!smk37_fwsc_load(path, &firmware)) return 1; if (strcmp(firmware.name, "SMK-37 Pro") == 0 && firmware.version == 15 && memcmp(firmware.file_sha256, PACKAGE_SHA256, sizeof(PACKAGE_SHA256)) == 0) {{ printf("exact v15 {name} package: PASS (%zu-byte OTA payload)\\n", firmware.payload_length); status = 0; }} else fputs("offline check rejected: not exact {name} package\\n", stderr); smk37_fwsc_free(&firmware); return status; }}
int main(int argc, char **argv) {{ if (argc == 3 && strcmp(argv[1], "check") == 0) return check_exact(argv[2]); if (argc == 6 && strcmp(argv[1], "upload") == 0 && strcmp(argv[4], "--confirm") == 0) return ota_upload_exact(argv[2], argv[3], argv[5], 15, PACKAGE_SHA256, DESCRIPTION, CONFIRM, "v15 {name} installed"); fprintf(stderr, "usage:\\n  %s check <fwsc>\\n  %s upload <fwsc> <transcript> --confirm %s\\n", argv[0], argv[0], CONFIRM); return 2; }}
"""


def extract_fwsc_payload(raw: bytes) -> bytearray:
    """Extract the UFW payload from a FWSC container without the official
    byte-exact hash gate (used to reparse produced packages)."""
    require(len(raw) > FWSC_SLOTS * FWSC_BLOCK_SIZE, "FWSC too small")
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])
    return payload


@dataclass
class PackResult:
    fwsc: bytes
    name: str
    token: str
    package_sha256: str
    manifest: dict[str, object]
    app_bytes: bytes


def pack(template: bytes, app_bin: bytes, name: str, description: str) -> PackResult:
    require(len(app_bin) <= APP_DATA_SIZE, "SDK app.bin larger than v15 app-data slot")
    padded = app_bin + b"\xff" * (APP_DATA_SIZE - len(app_bin))

    output, build_manifest = build_package(template, padded)
    pkg_sha256 = sha256(output)
    token = f"INSTALL-SMK37PRO-V15-{name}-{pkg_sha256[:8].upper()}"

    # Independent reparse of the produced package.
    payload = extract_fwsc_payload(output)
    ufw = Ufw.parse(payload)
    app = AppImage.parse(ufw.flash())
    require(app.app_bytes() == padded, "repacked app content verification failed")

    manifest = {
        "format": "smk37-v15-sdk-app-substitution-v1",
        "safety_gate": "PASS",
        "name": name,
        "token": token,
        "template": {
            "sha256": sha256(template),
        },
        "sdk_app_bin": {
            "size": len(app_bin),
            "sha256": sha256(app_bin),
            "pad_bytes": APP_DATA_SIZE - len(app_bin),
        },
        "output": {
            "size": len(output),
            "sha256": pkg_sha256,
        },
        "build": build_manifest,
    }
    return PackResult(bytes(output), name, token, pkg_sha256, manifest, padded)


def write_exact_ota(out_dir: Path, result: PackResult, description: str) -> Path:
    digest = bytes.fromhex(result.package_sha256)
    byte_list = ", ".join(f"0x{b:02x}" for b in digest)
    source = EXACT_OTA_TEMPLATE.format(
        name=result.name,
        bytes=byte_list,
        token=result.token,
        description=description,
    )
    path = out_dir / "exact_ota.c"
    path.write_text(source, encoding="ascii")
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Pack a Jieli-SDK app.bin into the SMK v15 OTA package."
    )
    parser.add_argument("--template", type=Path, default=DEFAULT_TEMPLATE,
                        help="byte-exact official v15 FWSC template")
    parser.add_argument("--app", type=Path, required=True, help="SDK-built app.bin")
    parser.add_argument("--name", required=True,
                        help="package name slug, e.g. SDK-DEMO-HELLO (used in token)")
    parser.add_argument("--description", default="Jieli SDK app substitution",
                        help="human-readable description")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="output directory (fwsc + manifest + exact_ota.c)")
    args = parser.parse_args()

    template = args.template.read_bytes()
    app_bin = args.app.read_bytes()

    name = args.name
    result = pack(template, app_bin, name, args.description)

    out_dir = args.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    fwsc_path = out_dir / f"SMK37Pro-v15-{name}.fwsc"
    fwsc_path.write_bytes(result.fwsc)

    manifest_path = out_dir / "package-manifest.json"
    manifest_path.write_text(json.dumps(result.manifest, indent=2) + "\n", encoding="utf-8")

    ota_path = write_exact_ota(out_dir, result, args.description)

    # Manual inspection of the produced package (inspect_package is gated on
    # the byte-exact official template).
    payload = extract_fwsc_payload(result.fwsc)
    ufw = Ufw.parse(payload)
    app = AppImage.parse(ufw.flash())
    require(app.app_bytes() == result.app_bytes, "output app content mismatch")
    lines = [
        f"{result.package_sha256}  {fwsc_path.name}",
        f"{sha256(app_bin)}  {args.app.name}",
        f"{sha256(template)}  {args.template.name}",
    ]
    (out_dir / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="ascii")

    print(f"packed: {fwsc_path}")
    print(f"size  : {len(result.fwsc)} bytes")
    print(f"sha256: {result.package_sha256}")
    print(f"token : {result.token}")
    print(f"app   : {len(app_bin)} -> {APP_DATA_SIZE} bytes (0xFF pad {result.manifest['sdk_app_bin']['pad_bytes']})")
    print("inspect: PASS (output parses, app content verified)")
    print(f"exact_ota.c: {ota_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
