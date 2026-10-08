#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Package a built SLOOP-SMK37 app image into the SMK-37 Pro v15 OTA container.

    tools/make_smk37_fwsc.py --app build/smk37-sloop.bin --output-dir OUT \
        [--template path/to/SMK-37_Pro_015.fwsc]

Reuses the repo's proven P0b bridge (tools/pack_sdk_app_fwsc.py): the app
image is substituted byte-exactly into the official v15 FWSC container
(protected boot, JLFS headers, UFW wrapper and CRCs preserved / recomputed),
so the device's existing OTA path -- this repo's exact_ota with its exact
SHA-256 gate -- can flash it. The template is the official v15 package; the
community mirror jonathaslacerda/smk-37-pro-docs ships it
(firmware/smk37pro/SMK-37_Pro_015.fwsc) if you have no local copy.

OFFLINE ONLY. This tool writes files; it never touches a device. Flashing
stays under the repo's gates (docs/firmware-runbook.md,
docs/usb-flash-safety-case.md): baseline dump first, exact-hash check,
rollback plan (esp32c3-usbkey / Jieli forced upgrade) ready.
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", type=Path, required=True, help="build/smk37-sloop.bin")
    ap.add_argument("--output-dir", type=Path, required=True)
    ap.add_argument("--template", type=Path,
                    default=REPO / "build" / "SMK-37_Pro_015.fwsc",
                    help="official v15 FWSC container (default: build/SMK-37_Pro_015.fwsc)")
    ap.add_argument("--name", default="SLOOP-SMK37-P1")
    a = ap.parse_args()
    if not a.app.exists():
        sys.exit(f"make_smk37_fwsc: {a.app} missing (run tools/build_smk37.py first)")
    if not a.template.exists():
        sys.exit(f"make_smk37_fwsc: template {a.template} missing; copy the official "
                 "SMK-37_Pro_015.fwsc there (community mirror: jonathaslacerda/"
                 "smk-37-pro-docs firmware/smk37pro/)")
    a.output_dir.mkdir(parents=True, exist_ok=True)
    r = subprocess.run([sys.executable, str(REPO / "tools" / "pack_sdk_app_fwsc.py"),
                        "--app", str(a.app), "--template", str(a.template),
                        "--name", a.name,
                        "--description", "SLOOP for SMK-37 Pro (sloop-smk37 port)",
                        "--output-dir", str(a.output_dir)], cwd=REPO)
    if r.returncode:
        return r.returncode
    for f in sorted(a.output_dir.glob("*.fwsc")):
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        print(f"make_smk37_fwsc: {f}  sha256 {h}")
        print("  flash gate: build/smk37-fw exact_ota with the token printed by "
              "pack_sdk_app_fwsc.py; baseline + rollback first (docs/firmware-runbook.md)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
