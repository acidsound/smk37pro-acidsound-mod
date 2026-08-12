#!/usr/bin/env python3
"""Validate S1-C1 additional-0xa0 boundary-only discriminator."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import build_v15_h2_owned_source_corrected_fallback as h2  # noqa: E402
import build_v15_s1c1_boundary_only as b  # noqa: E402
from build_v15_r01_hand_drum import off  # noqa: E402
from build_v15_r03_fixed_prefix import BSS_SIZE_INSN, HEAP_BEGIN_INSN  # noqa: E402

OUTPUT = b.DEFAULT_OUTPUT_DIR
APP = OUTPUT / "app.bin"
PACKAGE = OUTPUT / b.PACKAGE_NAME
EXPECTED_APP = "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e"
EXPECTED_PACKAGE = "ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d"
EXPECTED_SECTORS = ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    subprocess.run([sys.executable, str(TOOLS / "build_v15_s1c1_boundary_only.py"),
                    "--determinism-check"], cwd=ROOT, check=True)
    require(digest(APP) == EXPECTED_APP, "app SHA")
    require(digest(PACKAGE) == EXPECTED_PACKAGE, "package SHA")
    official = b.DEFAULT_INPUT_APP.read_bytes()
    h2_app, h2_manifest = h2.build_app(official)
    child = APP.read_bytes()
    diffs = [i for i, (x, y) in enumerate(zip(h2_app, child)) if x != y]
    require(diffs == [0x20, 0x21, 0x5E9FA, 0x5E9FB], "exact four H2-relative changed bytes")
    cave_end = int(h2_manifest["layout"]["end"], 16)
    require(child[off(h2.CODE_CAVE):off(cave_end)] == h2_app[off(h2.CODE_CAVE):off(cave_end)],
            "H2 code byte identity")
    require(child[off(BSS_SIZE_INSN):off(BSS_SIZE_INSN) + 6] == b.BSS_SIZE_S1C1,
            "S1-C1 BSS size")
    require(child[off(HEAP_BEGIN_INSN):off(HEAP_BEGIN_INSN) + 6] == b.HEAP_BEGIN_S1C1,
            "S1-C1 heap begin")
    manifest = json.loads((OUTPUT / "app-manifest.json").read_text())
    require(manifest["h2_parent_app_sha256"] == h2.sha256(h2_app), "H2 parent identity")
    require(manifest["invariants"] == {
        "additional_heap_reduction": 160,
        "h2_code_byte_identical": True,
        "h2_product_and_consumer_behavior_preserved": True,
        "reserved_end": "0x01c46660",
        "save_policy": "unchanged H2 no-write block",
        "second_slot_access": False,
        "selector_behavior": False,
    }, "boundary invariant set")
    package_manifest = json.loads((OUTPUT / "package-manifest.json").read_text())
    sectors = sorted({f"0x{x['start'] - x['start'] % 0x1000:05x}"
                      for x in package_manifest["changes"]["flash_ranges"]})
    require(sectors == EXPECTED_SECTORS, "sector inventory")
    require(package_manifest["safety_gate"] == "PASS", "package safety gate")
    require(package_manifest["protected_flash_hashes_before"] ==
            package_manifest["protected_flash_hashes_after"], "protected regions")
    with tempfile.TemporaryDirectory(prefix="s1c1-boundary-validation-") as td:
        second = b.build_once(b.DEFAULT_INPUT_APP, b.DEFAULT_INPUT_FWSC, Path(td), None)
        require(second["app_sha256"] == EXPECTED_APP, "scratch app")
        require(second["package_sha256"] == EXPECTED_PACKAGE, "scratch package")
    print("S1-C1 boundary-only artifact: PASS")
    print(f"app {EXPECTED_APP}")
    print(f"package {EXPECTED_PACKAGE}")
    print("H2-relative changes: 4 bytes; selector and second-slot access absent")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
