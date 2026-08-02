#!/usr/bin/env python3
"""Build exact-v15 H2 owned-source corrected-fallback discriminator.

H2 starts from official v15 and applies:

- H0 BSS/HEAP boundary changes;
- the H1 accepted-packet producer/publication path;
- Ch10 Note On/Off consumers route to owned RAM 0x01c46520 only when valid==1;
- both invalid and non-Ch10 fallbacks restore the original destination r0 and
  leave the stock source/count arguments untouched before calling stock memcpy;
- accepted product packet callsites point to the producer;
- SAVE is no-write blocked before the first persistent write.

No device access, OTA, or Flash mutation is performed by this tool.
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

from build_v15_h1_producer_unconsumed import build_producer  # noqa: E402
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
from build_v15_r03_fixed_prefix import (  # noqa: E402
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
    load_byte,
    short_call,
)
from smk37_v15_app_patch import compact_ranges, difference_offsets  # noqa: E402

FORMAT = "smk37-v15-h2-owned-source-corrected-fallback-v1"
DEFAULT_INPUT_APP = ROOT / "build/v15-official-app.bin"
DEFAULT_INPUT_FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
DEFAULT_OUTPUT_DIR = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback"
BASELINE_DIR = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback"
PACKAGE_NAME = "SMK37Pro-v15-H2-owned-source-corrected-fallback.fwsc"

NOTE_OFF_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
NOTE_ON_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def build_consumer(start_address: int, prefix: str) -> tuple[bytes, dict[str, int]]:
    """Build one corrected Note On/Off consumer wrapper.

    ABI contract on entry follows the v15 dispatcher memcpy callsite:
    r0 = destination, r1 = stock source, r2 = 0x9c, r9 = MIDI channel nibble.
    The wrapper uses only saved registers r3/r4/r5 and temporary r0 for probes.
    Stock fallback restores r0 from r5 immediately before the stock memcpy call;
    r1 and r2 are not touched on either fallback branch.
    """
    block = bytearray()
    entry = start_address
    block += word(0x0479)                 # push {rets,r9..r4}
    block += mov_reg(5, 0)                # preserve original destination before any probe
    block += mov_reg(3, 9)                # channel nibble, R02-live-proven register
    channel_branch = start_address + len(block)
    block += b"\0" * 4                  # if r3 != Ch10, stock fallback
    block += mov_imm32(4, VALID)
    block += load_byte(0, 4)              # r0 clobbered only after r5 saved it
    valid_branch = start_address + len(block)
    block += b"\0" * 4                  # if valid != 1, stock fallback
    owned = start_address + len(block)
    block += mov_reg(0, 5)                # restore destination for owned memcpy
    block += mov_imm32(1, VOICE)
    block += word(0x3C62)                 # r2 = 0x9c
    at = start_address + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)                 # pop {rets,r9..r4}
    stock = start_address + len(block)
    block += mov_reg(0, 5)                # critical R03 bug fix: restore destination for stock memcpy
    at = start_address + len(block)
    block += call32(at, MEMCPY)           # original r1/r2 are untouched
    block += word(0x0459)

    block[channel_branch - start_address:channel_branch - start_address + 4] = jne_imm7(
        channel_branch, 3, CHANNEL_10, stock
    )
    block[valid_branch - start_address:valid_branch - start_address + 4] = jne_imm7(
        valid_branch, 0, 1, stock
    )
    layout = {
        f"{prefix}_entry": entry,
        f"{prefix}_channel_branch": channel_branch,
        f"{prefix}_valid_branch": valid_branch,
        f"{prefix}_owned": owned,
        f"{prefix}_stock": stock,
        f"{prefix}_end": start_address + len(block),
    }
    return bytes(block), layout


def build_cave() -> tuple[bytes, dict[str, int]]:
    block = bytearray()
    off_consumer, off_layout = build_consumer(CODE_CAVE + len(block), "off")
    block += off_consumer
    on_consumer, on_layout = build_consumer(CODE_CAVE + len(block), "on")
    block += on_consumer
    producer, producer_layout = build_producer(CODE_CAVE + len(block))
    block += producer
    layout = {
        **off_layout,
        **on_layout,
        "producer": producer_layout["producer"],
        "try_fail_branch": producer_layout["try_fail_branch"],
        "producer_unlock": producer_layout["producer_unlock"],
        "producer_return": producer_layout["producer_return"],
        "end": CODE_CAVE + len(block),
    }
    require(layout["end"] <= CODE_CAVE_END, "H2 cave exceeds official packer body")
    return bytes(block), layout


def build_app(app: bytes) -> tuple[bytes, dict[str, object]]:
    require(len(app) == APP_SIZE and sha256(app) == APP_SHA256, "refusing non-official v15 app")
    cave, layout = build_cave()
    output = bytearray(app)
    changes: list[dict[str, object]] = []

    old_cave = app[off(CODE_CAVE):off(CODE_CAVE) + len(cave)]
    cave_change = replace_exact(output, app, CODE_CAVE, old_cave, cave)
    cave_change["purpose"] = "corrected owned-source Note Off/On consumers plus H1 producer"
    changes.append(cave_change)
    changes.append(replace_exact(output, app, NOTE_OFF_CALL, NOTE_OFF_STOCK, call32(NOTE_OFF_CALL, layout["off_entry"])))
    changes[-1]["purpose"] = "Note Off uses corrected Ch10 owned-source consumer with stock fallback r0 restore"
    changes.append(replace_exact(output, app, NOTE_ON_CALL, NOTE_ON_STOCK, call32(NOTE_ON_CALL, layout["on_entry"])))
    changes[-1]["purpose"] = "Note On uses corrected Ch10 owned-source consumer with stock fallback r0 restore"
    for address, expected, purpose in PRODUCT_CALLS:
        change = replace_exact(output, app, address, expected, short_call(address, layout["producer"]))
        change["purpose"] = f"accepted {purpose} calls H2 producer after official final-F7 gates"
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

    out = bytes(output)
    for prefix in ("off", "on"):
        stock = layout[f"{prefix}_stock"]
        owned = layout[f"{prefix}_owned"]
        require(out[off(stock):off(stock) + 2] == mov_reg(0, 5), f"{prefix} stock path lacks destination restore")
        require(out[off(owned):off(owned) + 2] == mov_reg(0, 5), f"{prefix} owned path lacks destination restore")
    require(out[off(0x0201E46C):off(0x0201E46C) + 4] == bytes.fromhex("bfeaf838"),
            "direct product reload call was not preserved")
    require(out[off(0x0201E4A0):off(0x0201E4A0) + 4] == bytes.fromhex("bfeade38"),
            "segmented product reload call was not preserved")

    changed_offsets = difference_offsets(app, out)
    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline H2 discriminator only; not a live functional success claim",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(out),
        "app_size": len(out),
        "changed_app_byte_count": len(changed_offsets),
        "changed_app_ranges": compact_ranges(changed_offsets),
        "changes": changes,
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "h2_policy": {
            "consumer_source_when_valid": f"0x{VOICE:08x}",
            "consumer_source_when_invalid_or_non_ch10": "original stock r1 source at dispatcher callsite",
            "stock_fallback_r0_restore": True,
            "stock_fallback_preserves_original_r1_r2": True,
            "producer_source": "accepted packet staging pointer passed in r0 by product parser",
            "producer_owned_destination": f"0x{VOICE:08x}..0x{VALID:08x}",
            "valid": f"0x{VALID:08x}",
            "lock": f"0x{LOCK:08x}",
            "copy_size": VOICE_SIZE,
            "product_reload_calls_preserved": True,
            "save_policy": "blocked before first persistent write; later packer call neutralized",
        },
        "discriminator_outcomes": {
            "intended_mooger_note_off_no_reboot": "owned source 0x01c46520 is consumed safely with corrected fallback semantics",
            "stock_sound_no_reboot": "corrected fallback path is safe, but producer did not publish valid before consumer or product was not accepted",
            "reboot": "H2 FAIL: owned-source consumption or surrounding corrected consumer path still faults",
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
    h2_app, app_manifest = build_app(app)
    app_path = output_dir / "app.bin"
    package_path = output_dir / PACKAGE_NAME
    package_manifest_path = output_dir / "package-manifest.json"
    app_manifest_path = output_dir / "app-manifest.json"
    app_path.write_bytes(h2_app)
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
        "# H2 owned-source corrected-fallback discriminator",
        "",
        "Scope: exact official v15 only. Offline artifact; no device access or flash.",
        "",
        "## Intent",
        "",
        "H2 tests whether Ch10 Note On/Off consumers can safely consume the H1 producer's owned RAM snapshot at `0x01c46520` when the R03 invalid-branch bug is fixed.",
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
        "- Accepted product packet callsites invoke the H1 producer after official final-F7 gates.",
        "- Producer copies `0x9c` bytes from the accepted staging pointer to `0x01c46520`, sets valid last, and unlocks with the nonblocking PI32 `testset` protocol.",
        "- Note On/Off Ch10 consumers read `0x01c46520` only when valid is exactly 1.",
        "- Invalid and non-Ch10 fallbacks restore original `r0` from `r5` before stock memcpy; original `r1` and `r2` are not modified on fallback.",
        "- Product reload calls are preserved, as in the R02/H1 live-success path.",
        "- SAVE is blocked before the first persistent write because the stock packer body is replaced; the later packer call is neutralized.",
        "",
        "## Discriminator outcomes",
        "",
        "| Live outcome if later authorized | Interpretation |",
        "| --- | --- |",
    ]
    for key, value in app_manifest["discriminator_outcomes"].items():
        lines.append(f"| `{key}` | {value} |")
    lines += [
        "",
        "## Validation",
        "",
        "See `app-manifest.json`, `package-manifest.json`, and `SHA256SUMS`. Full release gates are checked by `tools/validate_v15_h2.py`.",
        "",
    ]
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
        with tempfile.TemporaryDirectory(prefix="h2-build-") as tmp:
            tmp_dir = Path(tmp)
            summary2 = build_once(args.input_app, args.input_fwsc, tmp_dir, None)
            for rel in ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
                require((args.output_dir / rel).read_bytes() == (tmp_dir / rel).read_bytes(), f"determinism mismatch: {rel}")
            require(summary == summary2, "summary determinism mismatch")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
