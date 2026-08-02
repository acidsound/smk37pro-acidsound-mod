#!/usr/bin/env python3
"""Build H2 behavior with only the additional S1-C1 0xa0 RAM boundary.

This discriminator preserves the exact live-proven H2 code and behavior. Relative
to H2, it changes only BSS size and HEAP_BEGIN from 0x01c465c0 to 0x01c46660.
It does not read or write the second slot and adds no selector behavior.
"""
from __future__ import annotations

import argparse
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
from build_v15_r03_fixed_prefix import BSS_SIZE_INSN, HEAP_BEGIN_INSN  # noqa: E402
from build_v15_r01_hand_drum import off, replace_exact, sha256  # noqa: E402
from smk37_v15_app_patch import compact_ranges, difference_offsets  # noqa: E402

FORMAT = "smk37-v15-s1c1-boundary-only-v1"
DEFAULT_INPUT_APP = ROOT / "build/v15-official-app.bin"
DEFAULT_INPUT_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
DEFAULT_OUTPUT_DIR = ROOT / "build/SMK37Pro-v15-S1C1-boundary-only"
BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/S1C1-boundary-only"
PACKAGE_NAME = "SMK37Pro-v15-S1C1-boundary-only.fwsc"

BSS_SIZE_H2 = bytes.fromhex("c2ffeccb0300")
BSS_SIZE_S1C1 = bytes.fromhex("c2ff8ccc0300")
HEAP_BEGIN_H2 = bytes.fromhex("c5ffc065c401")
HEAP_BEGIN_S1C1 = bytes.fromhex("c5ff6066c401")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_app(official: bytes) -> tuple[bytes, dict[str, object]]:
    h2_app, h2_manifest = h2.build_app(official)
    output = bytearray(h2_app)
    changes = []
    change = replace_exact(output, h2_app, BSS_SIZE_INSN, BSS_SIZE_H2, BSS_SIZE_S1C1)
    change["purpose"] = "boundary-only: extend BSS zeroing by 0xa0 through 0x01c46660"
    changes.append(change)
    change = replace_exact(output, h2_app, HEAP_BEGIN_INSN, HEAP_BEGIN_H2, HEAP_BEGIN_S1C1)
    change["purpose"] = "boundary-only: move H2 heap begin forward by exactly 0xa0"
    changes.append(change)
    out = bytes(output)
    diffs = difference_offsets(h2_app, out)
    require(len(diffs) == 4, "boundary-only child must change exactly four H2 app bytes")
    require(out[off(h2.CODE_CAVE):off(h2_manifest["layout"]["end"] if isinstance(h2_manifest["layout"]["end"], int) else int(h2_manifest["layout"]["end"], 16))] ==
            h2_app[off(h2.CODE_CAVE):off(h2_manifest["layout"]["end"] if isinstance(h2_manifest["layout"]["end"], int) else int(h2_manifest["layout"]["end"], 16))],
            "H2 code changed")
    return out, {
        "format": FORMAT,
        "artifact_scope": "offline boundary discriminator only; no second-slot read/write or selector",
        "official_app_sha256": sha256(official),
        "h2_parent_app_sha256": sha256(h2_app),
        "output_app_sha256": sha256(out),
        "app_size": len(out),
        "h2_to_child_changed_byte_count": len(diffs),
        "h2_to_child_changed_ranges": compact_ranges(diffs),
        "changes": changes,
        "invariants": {
            "h2_code_byte_identical": True,
            "h2_product_and_consumer_behavior_preserved": True,
            "second_slot_access": False,
            "selector_behavior": False,
            "additional_heap_reduction": 0xA0,
            "reserved_end": "0x01c46660",
            "save_policy": "unchanged H2 no-write block",
        },
    }


def write_json(path: Path, obj: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_once(input_app: Path, input_fwsc: Path, output_dir: Path,
               baseline_dir: Path | None) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    app, manifest = build_app(input_app.read_bytes())
    app_path = output_dir / "app.bin"
    package_path = output_dir / PACKAGE_NAME
    app_manifest_path = output_dir / "app-manifest.json"
    package_manifest_path = output_dir / "package-manifest.json"
    app_path.write_bytes(app)
    write_json(app_manifest_path, manifest)
    subprocess.run([sys.executable, str(TOOLS / "smk37_v15_app_patch.py"), "repack-app",
                    str(input_fwsc), str(app_path), str(package_path),
                    "--manifest", str(package_manifest_path)], check=True)
    package_manifest = json.loads(package_manifest_path.read_text(encoding="utf-8"))
    names = ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json"]
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{file_sha(output_dir / n)}  {n}\n" for n in names), encoding="utf-8")
    summary = {
        "app_sha256": file_sha(app_path),
        "package_sha256": file_sha(package_path),
        "h2_parent_app_sha256": manifest["h2_parent_app_sha256"],
        "h2_to_child_changed_byte_count": manifest["h2_to_child_changed_byte_count"],
        "changed_flash_sectors": sorted({
            f"0x{x['start'] - x['start'] % 0x1000:05x}"
            for x in package_manifest["changes"]["flash_ranges"]
        }),
    }
    if baseline_dir is not None:
        baseline_dir.mkdir(parents=True, exist_ok=True)
        for name in ["app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
            (baseline_dir / name).write_bytes((output_dir / name).read_bytes())
        (baseline_dir / "report.md").write_text(
            "\n".join([
                "# S1-C1 additional-0xa0 boundary-only discriminator",
                "",
                "Preserves exact H2 code and behavior. Changes only BSS and HEAP_BEGIN boundary immediates relative to H2.",
                "",
                f"- app SHA-256: `{summary['app_sha256']}`",
                f"- package SHA-256: `{summary['package_sha256']}`",
                f"- H2-to-child changed app bytes: `{summary['h2_to_child_changed_byte_count']}`",
                f"- changed sectors vs official v15: `{', '.join(summary['changed_flash_sectors'])}`",
                "- second slot is never accessed",
                "- no per-note selector exists",
                "- no persistence is enabled",
                "",
            ]), encoding="utf-8")
    return summary


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-app", type=Path, default=DEFAULT_INPUT_APP)
    p.add_argument("--input-fwsc", type=Path, default=DEFAULT_INPUT_FWSC)
    p.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    p.add_argument("--baseline-dir", type=Path, default=BASELINE_DIR)
    p.add_argument("--determinism-check", action="store_true")
    args = p.parse_args()
    first = build_once(args.input_app, args.input_fwsc, args.output_dir, args.baseline_dir)
    if args.determinism_check:
        with tempfile.TemporaryDirectory(prefix="smk37-s1c1-boundary-") as td:
            second_dir = Path(td)
            second = build_once(args.input_app, args.input_fwsc, second_dir, None)
            for name in ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
                require((args.output_dir / name).read_bytes() == (second_dir / name).read_bytes(),
                        f"determinism mismatch: {name}")
            require(first == second, "summary mismatch")
    print(json.dumps(first, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
