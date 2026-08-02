#!/usr/bin/env python3
"""Build exact-v15 H1 producer-unconsumed discriminator.

H1 starts from official v15 and applies:

- H0 BSS/HEAP boundary changes;
- R02 live-proven Note On/Off consumers that source Ch10 from 0x01c37fd0;
- an R03-derived producer that copies accepted staging 0x01c37fd0 to owned
  0x01c46520 and publishes valid/lock with nonblocking PI32 testset;
- accepted product packet callsites point to that producer;
- SAVE is no-write blocked before the first persistent write.

No consumer path reads 0x01c46520 in H1. This tool performs no device access,
OTA, or Flash mutation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from build_v15_r01_hand_drum import (  # noqa: E402
    APP_SHA256,
    APP_SIZE,
    CHANNEL_10,
    CODE_CAVE,
    CODE_CAVE_END,
    MEMCPY,
    RUNTIME_BASE,
    call32,
    jne_imm7,
    mov_imm32,
    mov_reg,
    off,
    replace_exact,
    sha256,
    word,
)
from build_v15_r02_sysex_staging import RAM_STAGING, build_wrapper as build_r02_wrapper  # noqa: E402
from build_v15_r03_fixed_prefix import (  # noqa: E402
    ATOMIC_TRY_PREFIX,
    BSS_SIZE_INSN,
    BSS_SIZE_R03,
    BSS_SIZE_STOCK,
    HEAP_BEGIN_INSN,
    HEAP_BEGIN_R03,
    HEAP_BEGIN_STOCK,
    LOCK,
    PRODUCT_CALLS,
    SAVE_CALL,
    SAVE_REJECT_BRANCH,
    SAVE_REJECT_CALL,
    SAVE_REJECT_STOCK,
    SAVE_STOCK,
    VALID,
    VOICE,
    VOICE_SIZE,
    ifeq,
    load_byte,
    mov_imm8,
    short_call,
    store_byte,
)
from smk37_v15_app_patch import compact_ranges, difference_offsets  # noqa: E402

FORMAT = "smk37-v15-h1-producer-unconsumed-v1"
DEFAULT_INPUT_APP = ROOT / "build/v15-official-app.bin"
DEFAULT_INPUT_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
DEFAULT_OUTPUT_DIR = ROOT / "build/SMK37Pro-v15-H1-producer-unconsumed"
BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/H1-producer-unconsumed"
PACKAGE_NAME = "SMK37Pro-v15-H1-producer-unconsumed.fwsc"

NOTE_OFF_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
NOTE_ON_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")

# Exact stock bytes that H1 must preserve unless explicitly listed as a change.
OFFICIAL_PRESERVED = {
    "consumer_does_not_load_owned_voice_off": (0x0201E156, None),
    "consumer_does_not_load_owned_voice_on": (0x0201E186, None),
    "post_product_direct_reload": (0x0201E46C, bytes.fromhex("bfeaf838")),
    "post_product_segmented_reload": (0x0201E4A0, bytes.fromhex("bfeade38")),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def build_producer(start_address: int) -> tuple[bytes, dict[str, int]]:
    block = bytearray()
    producer = start_address
    block += word(0x0479)                  # push {rets,r9..r4}
    block += mov_reg(4, 0)                 # accepted staging pointer
    block += mov_imm32(0, LOCK)
    block += ATOMIC_TRY_PREFIX             # csync; testset b[r0]
    try_fail_branch = start_address + len(block)
    block += b"\0" * 4
    block += word(0x0020)                  # csync after acquired testset
    block += mov_imm32(5, VALID)
    block += load_byte(0, 5)
    producer_valid_branch = start_address + len(block)
    block += b"\0" * 4
    block += mov_imm32(0, VOICE)
    block += mov_reg(1, 4)
    block += word(0x3C62)                  # r2 = 0x9c
    at = start_address + len(block)
    block += call32(at, MEMCPY)
    block += mov_imm32(5, VALID)
    block += mov_imm8(0, 1)
    block += store_byte(0, 5)              # publish validity last
    producer_unlock = start_address + len(block)
    block += mov_imm32(0, LOCK)
    block += word(0x0020)                  # csync
    block += mov_imm8(1, 0)
    block += store_byte(1, 0)
    block += word(0x0020)                  # csync
    producer_return = start_address + len(block)
    block += word(0x0459)

    block[try_fail_branch - start_address:try_fail_branch - start_address + 4] = ifeq(
        try_fail_branch, producer_return
    )
    block[producer_valid_branch - start_address:producer_valid_branch - start_address + 4] = jne_imm7(
        producer_valid_branch, 0, 0, producer_unlock
    )
    layout = {
        "producer": producer,
        "try_fail_branch": try_fail_branch,
        "producer_unlock": producer_unlock,
        "producer_return": producer_return,
        "end": start_address + len(block),
    }
    return bytes(block), layout


def build_cave() -> tuple[bytes, dict[str, int]]:
    r02_wrapper, r02_layout = build_r02_wrapper()
    producer_start = CODE_CAVE + len(r02_wrapper)
    producer, producer_layout = build_producer(producer_start)
    cave = r02_wrapper + producer
    layout = {
        "r02_entry": CODE_CAVE,
        "r02_special": r02_layout["special"],
        "r02_stock": r02_layout["stock"],
        "producer": producer_layout["producer"],
        "try_fail_branch": producer_layout["try_fail_branch"],
        "producer_unlock": producer_layout["producer_unlock"],
        "producer_return": producer_layout["producer_return"],
        "end": CODE_CAVE + len(cave),
    }
    require(layout["end"] <= CODE_CAVE_END, "H1 cave exceeds official packer body")
    return cave, layout


def build_app(app: bytes) -> tuple[bytes, dict[str, object]]:
    require(len(app) == APP_SIZE and sha256(app) == APP_SHA256, "refusing non-official v15 app")
    cave, layout = build_cave()
    output = bytearray(app)
    changes: list[dict[str, object]] = []

    old_cave = app[off(CODE_CAVE):off(CODE_CAVE) + len(cave)]
    cave_change = replace_exact(output, app, CODE_CAVE, old_cave, cave)
    cave_change["purpose"] = "R02 staging consumer wrapper plus R03-derived producer; no consumer loads owned source"
    changes.append(cave_change)
    changes.append(replace_exact(output, app, NOTE_OFF_CALL, NOTE_OFF_STOCK, call32(NOTE_OFF_CALL, layout["r02_entry"])))
    changes[-1]["purpose"] = "Note Off uses R02 live-proven Ch10 staging consumer"
    changes.append(replace_exact(output, app, NOTE_ON_CALL, NOTE_ON_STOCK, call32(NOTE_ON_CALL, layout["r02_entry"])))
    changes[-1]["purpose"] = "Note On uses R02 live-proven Ch10 staging consumer"
    for address, expected, purpose in PRODUCT_CALLS:
        change = replace_exact(output, app, address, expected, short_call(address, layout["producer"]))
        change["purpose"] = f"accepted {purpose} calls H1 producer after official final-F7 gates"
        changes.append(change)
    reject = replace_exact(output, app, SAVE_REJECT_CALL, SAVE_REJECT_STOCK, SAVE_REJECT_BRANCH)
    reject["purpose"] = "no-write SAVE block before first persistent write because stock packer body is replaced"
    changes.append(reject)
    save = replace_exact(output, app, SAVE_CALL, SAVE_STOCK, b"\0" * 4)
    save["purpose"] = "neutralize now-unreachable SAVE packer call into replaced code cave"
    changes.append(save)
    bss = replace_exact(output, app, BSS_SIZE_INSN, BSS_SIZE_STOCK, BSS_SIZE_R03)
    bss["purpose"] = "H0 BSS zero extension through 0x01c465c0"
    changes.append(bss)
    heap = replace_exact(output, app, HEAP_BEGIN_INSN, HEAP_BEGIN_STOCK, HEAP_BEGIN_R03)
    heap["purpose"] = "H0 HEAP_BEGIN shift to 0x01c465c0"
    changes.append(heap)

    # Explicit H1 discriminator invariants.
    out = bytes(output)
    require(out.find(VOICE.to_bytes(4, "little"), off(CODE_CAVE), off(layout["producer"])) == -1,
            "owned voice immediate appears before producer; consumer must not read owned RAM")
    require(out[off(0x0201E148):off(0x0201E148) + 6] == bytes.fromhex("c1ffd07fc301"),
            "R02 consumer staging source immediate missing")
    require(out[off(0x0201E46C):off(0x0201E46C) + 4] == bytes.fromhex("bfeaf838"),
            "direct product reload call was not preserved")
    require(out[off(0x0201E4A0):off(0x0201E4A0) + 4] == bytes.fromhex("bfeade38"),
            "segmented product reload call was not preserved")

    changed_offsets = difference_offsets(app, out)
    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline H1 discriminator only; not a live functional success claim",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(out),
        "app_size": len(out),
        "changed_app_byte_count": len(changed_offsets),
        "changed_app_ranges": compact_ranges(changed_offsets),
        "changes": changes,
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "h1_policy": {
            "consumer_source": f"0x{RAM_STAGING:08x}",
            "owned_voice_written_by_producer": f"0x{VOICE:08x}..0x{VALID:08x}",
            "valid": f"0x{VALID:08x}",
            "lock": f"0x{LOCK:08x}",
            "copy_size": VOICE_SIZE,
            "no_consumer_owned_ram": True,
            "product_reload_calls_preserved": True,
            "save_policy": "blocked before first persistent write; later packer call neutralized",
        },
        "discriminator_outcomes": {
            "packet_time_reboot": "producer/owned-RAM write or post-product reload path is sufficient to fault before any Ch10 consumer runs",
            "first_pad_reboot": "R02 staging consumer with H0 boundary and producer side effect still faults; investigate event path interaction independent of owned source consumption",
            "PASS": "producer write/publish and R02 staging consumers coexist; R03 first-pad reboot is isolated to owned-source consumption or R03 invalid/fallback consumer behavior",
        },
    }
    return out, manifest


def write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_once(input_app: Path, input_fwsc: Path, output_dir: Path, baseline_dir: Path | None = None) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    app = input_app.read_bytes()
    h1_app, app_manifest = build_app(app)
    app_path = output_dir / "app.bin"
    package_path = output_dir / PACKAGE_NAME
    package_manifest_path = output_dir / "package-manifest.json"
    app_manifest_path = output_dir / "app-manifest.json"
    app_path.write_bytes(h1_app)
    write_json(app_manifest_path, app_manifest)
    subprocess.run([
        sys.executable,
        str(TOOLS / "smk37_v15_app_patch.py"),
        "repack-app",
        str(input_fwsc),
        str(app_path),
        str(package_path),
        "--manifest",
        str(package_manifest_path),
    ], check=True)
    package_manifest = json.loads(package_manifest_path.read_text(encoding="utf-8"))
    summary = {
        "app_sha256": file_sha256(app_path),
        "package_sha256": file_sha256(package_path),
        "app_manifest_sha256": file_sha256(app_manifest_path),
        "package_manifest_sha256": file_sha256(package_manifest_path),
        "changed_app_byte_count": app_manifest["changed_app_byte_count"],
        "changed_flash_byte_count_including_crc_fields": package_manifest["changes"]["flash_byte_count_including_crc_fields"],
        "changed_flash_sectors": sorted({f"0x{item['start'] - (item['start'] % 0x1000):05x}" for item in package_manifest["changes"]["flash_ranges"]}),
    }
    (output_dir / "SHA256SUMS").write_text(
        "".join(f"{file_sha256(output_dir / name)}  {name}\n" for name in ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json"]),
        encoding="utf-8",
    )
    if baseline_dir is not None:
        baseline_dir.mkdir(parents=True, exist_ok=True)
        for name in ["app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
            (baseline_dir / name).write_bytes((output_dir / name).read_bytes())
        write_report(baseline_dir / "report.md", app_manifest, package_manifest, summary)
    return summary


def write_report(path: Path, app_manifest: dict[str, object], package_manifest: dict[str, object], summary: dict[str, object]) -> None:
    lines = [
        "# H1 producer-unconsumed discriminator",
        "",
        "Scope: exact official v15 only. Offline artifact; no device access or flash.",
        "",
        "## Intent",
        "",
        "H1 tests whether the R03 producer writing/publishing owned RAM can coexist with the live-proven R02 Ch10 staging consumers. No H1 consumer reads `0x01c46520`.",
        "",
        "## Hashes",
        "",
        f"- app SHA-256: `{summary['app_sha256']}`",
        f"- package SHA-256: `{summary['package_sha256']}`",
        f"- changed flash sectors: `{', '.join(summary['changed_flash_sectors'])}`",
        "",
        "## Preserved and changed behavior",
        "",
        "- H0 BSS/HEAP boundary is applied.",
        "- Note On/Off use the R02 live-proven wrapper, with `r9` Ch10 gate, stock fallback, and source `0x01c37fd0`.",
        "- Accepted product packet callsites invoke the producer after official final-F7 gates.",
        "- Producer copies `0x9c` bytes from `0x01c37fd0` to `0x01c46520`, sets valid last, and unlocks with the nonblocking PI32 `testset` protocol.",
        "- Product reload calls are preserved, as in the R02 live-success path.",
        "- SAVE is blocked before the first persistent write because the stock packer body is replaced; the later packer call is neutralized.",
        "",
        "## Discriminator outcomes",
        "",
        "| Live outcome if later authorized | Interpretation |",
        "| --- | --- |",
    ]
    for key, value in app_manifest["discriminator_outcomes"].items():
        lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Validation", "", "See `app-manifest.json`, `package-manifest.json`, and `SHA256SUMS`. Full release gates are checked by `tools/validate_v15_h1.py`.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-app", type=Path, default=DEFAULT_INPUT_APP)
    parser.add_argument("--input-fwsc", type=Path, default=DEFAULT_INPUT_FWSC)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--baseline-dir", type=Path, default=BASELINE_DIR)
    parser.add_argument("--determinism-check", action="store_true")
    args = parser.parse_args()
    summary = build_once(args.input_app, args.input_fwsc, args.output_dir, args.baseline_dir)
    if args.determinism_check:
        with tempfile.TemporaryDirectory(prefix="h1-build-") as tmp:
            tmp_dir = Path(tmp)
            summary2 = build_once(args.input_app, args.input_fwsc, tmp_dir, None)
            for rel in ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
                require((args.output_dir / rel).read_bytes() == (tmp_dir / rel).read_bytes(), f"determinism mismatch: {rel}")
            require(summary == summary2, "summary determinism mismatch")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
