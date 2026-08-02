#!/usr/bin/env python3
"""Address-level R01d incident reanalysis.

Read-only analysis only.  This script inspects official v15 and R01/R01b/R01c/R01d
artifacts already present in the repo.  It performs no patching, flashing, or
USB/device access.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
FLASH_DIR = ROOT / "baselines/v15/analysis/flash-candidates"
BUILD = ROOT / "build"

VARIANTS = {
    "official_v15": {
        "package": BUILD / "SMK-37_Pro_015.fwsc",
        "app": BUILD / "v15-official-app.bin",
        "package_manifest": ROOT / "baselines/v15/official/package-manifest.json",
        "live_status": "official baseline, restored and device-info observed as 015",
    },
    "R01": {
        "package": BUILD / "SMK37Pro-v15-R01-hand-drum.fwsc",
        "app": BUILD / "v15-R01-hand-drum-app.bin",
        "app_manifest": FLASH_DIR / "R01/app-manifest.json",
        "package_manifest": FLASH_DIR / "R01/package-manifest.json",
        "live_status": "live-booted; Ch10 branch reached; Note Off stuck voice remained",
    },
    "R01b": {
        "package": BUILD / "SMK37Pro-v15-R01b-buzz-bass.fwsc",
        "app": BUILD / "v15-R01b-buzz-bass-app.bin",
        "app_manifest": FLASH_DIR / "R01b/app-manifest.json",
        "package_manifest": FLASH_DIR / "R01b/package-manifest.json",
        "live_status": "live-booted; matched Note On/Off source fixed R01 stuck note; named voice failed",
    },
    "R01c": {
        "package": BUILD / "SMK37Pro-v15-R01c-mooger1.fwsc",
        "app": BUILD / "v15-R01c-mooger1-app.bin",
        "app_manifest": FLASH_DIR / "R01c/app-manifest.json",
        "package_manifest": FLASH_DIR / "R01c/package-manifest.json",
        "live_status": "live-booted; matched Note On/Off source worked; named Mooger #1 failed",
    },
    "R01d": {
        "package": BUILD / "SMK37Pro-v15-R01d-ram-mooger1.fwsc",
        "app": BUILD / "v15-R01d-ram-mooger1-app.bin",
        "app_manifest": FLASH_DIR / "R01d/app-manifest.json",
        "package_manifest": FLASH_DIR / "R01d/package-manifest.json",
        "live_status": "BRICKED/REVOKED; OTA completed but firmware did not live-boot to normal USB",
    },
}

EXPECTED = {
    "official_v15": {
        "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
        "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    },
    "R01": {
        "package_sha256": "292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462",
        "app_sha256": "e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7",
    },
    "R01b": {
        "package_sha256": "50aa3b27b17e4f9f8c682dd0ff053d2e3d198b7c736da63ed7b957627ccfa08d",
        "app_sha256": "1bd69fa20d4e4dab35d1d9df12bda36e25516ce2d0c1dff00fd2b7c9e3e96c7f",
    },
    "R01c": {
        "package_sha256": "b34d19e144281e21d1aae141315c3214950d4cf06aa9b0db840d9ebdc15770a7",
        "app_sha256": "37fe48e8215b7d8036c5cd98a0ff0962abe260dc2af13f633b749c527b96e2cb",
    },
    "R01d": {
        "package_sha256": "add7baacc38d90bcd28cf51a1d096abe0737c8430ec01f70d5b41423d5dc9a96",
        "app_sha256": "bdcfdcf1b5e6d60e04e8c9316db94aa38e6cae4a7bcfaf63abefd38bb5347bb3",
    },
}

ADDRESS_CLASSIFICATION = {
    "0x02005f9c": {
        "r01d_status": "new_in_R01d",
        "cause_likelihood": "high",
        "classification": "unsafe post-init loader/preload assumption",
        "rationale": "Only R01d patches this early post-init callsite. It changes an existing call to route into a cave that mutates selection state, calls the factory loader twice, and copies from current-source RAM before USB enumeration. The note hooks cannot execute before USB MIDI traffic, while this hook can execute during boot.",
        "reusable_primitive": "none",
    },
    "0x0201c63e": {
        "r01d_status": "reused_from_live_R01b_R01c_with_different_target",
        "cause_likelihood": "low_for_pre_usb",
        "classification": "previously live-booted Note Off memcpy call redirection primitive",
        "rationale": "R01b/R01c introduced this matched Note Off hook and live-booted. It is reached from the MIDI note-off path, not during pre-USB boot.",
        "reusable_primitive": "matched Note On/Off source wrapper redirection, but only post-USB event-path usage is proven",
    },
    "0x0201c67c": {
        "r01d_status": "reused_from_live_R01_R01b_R01c_with_different_target",
        "cause_likelihood": "low_for_pre_usb",
        "classification": "previously live-booted Note On memcpy call redirection primitive",
        "rationale": "R01/R01b/R01c changed this Note On callsite and booted. It requires MIDI event dispatch and is not expected to fire before USB enumeration.",
        "reusable_primitive": "r9 channel-gated Note On source redirection, behavior beyond branch separation not proven",
    },
    "0x0201e13e": {
        "r01d_status": "same cave entry reused, contents materially new",
        "cause_likelihood": "medium_as_callee_of_high_risk_post_init",
        "classification": "unsafe code-cave expansion when invoked at init; post-USB wrapper primitive only partly proven",
        "rationale": "The code-cave location itself was used by live-booted R01/R01b/R01c. R01d replaced the old static snapshot wrapper with a new preload routine plus note wrapper. The unsafe part is executing the cave from post-init before runtime lifecycle is established.",
        "reusable_primitive": "code cave occupancy and compact channel compare wrapper were live-booted; loader-preload body was not",
    },
    "0x0201e468": {
        "r01d_status": "reused_from_live_R01_R01b_R01c",
        "cause_likelihood": "low",
        "classification": "previously live-booted old SysEx direct caller neutralization",
        "rationale": "All R01 variants zeroed this old direct caller and booted. It is not the R01d-specific early-boot change.",
        "reusable_primitive": "neutralize stale direct caller at this exact address only",
    },
    "0x0201e49c": {
        "r01d_status": "reused_from_live_R01_R01b_R01c",
        "cause_likelihood": "low",
        "classification": "previously live-booted old SysEx direct caller neutralization",
        "rationale": "All R01 variants zeroed this old direct caller and booted. It is not the R01d-specific early-boot change.",
        "reusable_primitive": "neutralize stale direct caller at this exact address only",
    },
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def runs(offsets: list[int]) -> list[dict[str, int | str]]:
    if not offsets:
        return []
    out = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        out.append({"start": start, "end_exclusive": prev + 1, "size": prev + 1 - start, "start_hex": f"0x{start:05x}", "end_exclusive_hex": f"0x{prev + 1:05x}"})
        start = prev = off
    out.append({"start": start, "end_exclusive": prev + 1, "size": prev + 1 - start, "start_hex": f"0x{start:05x}", "end_exclusive_hex": f"0x{prev + 1:05x}"})
    return out


def diff_runs(left: bytes, right: bytes) -> list[dict[str, int | str]]:
    assert len(left) == len(right)
    return runs([i for i, (a, b) in enumerate(zip(left, right)) if a != b])


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def app_flash(addr: str) -> str:
    app_off = int(addr, 16) - 0x02000000
    return f"0x{app_off + 16672:05x}"


def main() -> int:
    official_app = VARIANTS["official_v15"]["app"].read_bytes()
    result: dict[str, Any] = {
        "format": "smk37-v15-r01d-incident-reanalysis-v1",
        "scope": "official v15 plus R01/R01b/R01c live-booted artifacts and R01d bricked artifact; no v12 assumptions",
        "artifact_hashes": {},
        "variants": {},
        "r01d_address_classification": [],
        "r01d_diff_ranges": {},
        "unsafe_assumptions": [],
        "reusable_patch_primitives": [],
    }

    for name, spec in VARIANTS.items():
        package_manifest = load_json(spec["package_manifest"])
        entry = {
            "live_status": spec["live_status"],
            "package_path": str(spec["package"].relative_to(ROOT)),
            "app_path": str(spec["app"].relative_to(ROOT)),
            "package_sha256": sha(spec["package"]),
            "app_sha256": sha(spec["app"]),
            "package_sha256_expected": EXPECTED[name]["package_sha256"],
            "app_sha256_expected": EXPECTED[name]["app_sha256"],
            "hashes_match_expected": sha(spec["package"]) == EXPECTED[name]["package_sha256"] and sha(spec["app"]) == EXPECTED[name]["app_sha256"],
        }
        if name != "official_v15":
            app_manifest = load_json(spec["app_manifest"])
            app_data = spec["app"].read_bytes()
            entry["manifest_format"] = app_manifest["format"]
            entry["input_app_sha256"] = app_manifest["input_app_sha256"]
            entry["output_app_sha256"] = app_manifest["output_app_sha256"]
            entry["manifest_changed_addresses"] = [c["address"] for c in app_manifest["changes"]]
            entry["actual_app_diff_ranges_vs_official"] = diff_runs(official_app, app_data)
            entry["package_flash_ranges"] = package_manifest["changes"]["flash_ranges"]
            entry["package_app_ranges"] = package_manifest["changes"]["app_ranges"]
        else:
            entry["manifest_package_sha256"] = package_manifest["package_sha256"]
            entry["manifest_app_sha256"] = package_manifest["app_sha256"]
        result["variants"][name] = entry

    r01d_manifest = load_json(VARIANTS["R01d"]["app_manifest"])
    previous_addresses = {v: set(load_json(VARIANTS[v]["app_manifest"])["changes"][i]["address"] for i in range(len(load_json(VARIANTS[v]["app_manifest"])["changes"]))) for v in ("R01", "R01b", "R01c")}
    for change in r01d_manifest["changes"]:
        address = change["address"]
        present_in = [v for v, addrs in previous_addresses.items() if address in addrs]
        classification = ADDRESS_CLASSIFICATION[address]
        result["r01d_address_classification"].append({
            "address": address,
            "app_file_offset": change["file_offset"],
            "flash_offset": app_flash(address),
            "old_len": len(bytes.fromhex(change["old_hex"])),
            "new_len": len(bytes.fromhex(change["new_hex"])),
            "present_in_live_booted_prior_variants": present_in,
            "old_hex": change["old_hex"],
            "new_hex": change["new_hex"],
            **classification,
        })

    result["r01d_diff_ranges"] = {
        "app_ranges_manifest": load_json(VARIANTS["R01d"]["package_manifest"])["changes"]["app_ranges"],
        "flash_ranges_manifest": load_json(VARIANTS["R01d"]["package_manifest"])["changes"]["flash_ranges"],
        "actual_app_diff_ranges_vs_official": result["variants"]["R01d"]["actual_app_diff_ranges_vs_official"],
        "changed_sectors_vs_official_v15": ["0x04000", "0x0a000", "0x20000", "0x22000"],
    }
    result["unsafe_assumptions"] = [
        "Calling the factory loader from a post-init callsite before USB enumeration is safe.",
        "The live object base 0x01c33260 and selected-bank offsets 0x03a0..0x03a4 are valid and initialized at 0x02005f9c time.",
        "The current-source buffer at 0x01c34c74 is populated by the loader and stable immediately after the injected early call.",
        "A dedicated RAM staging buffer at 0x01c37fd0 is unused by official firmware and survives until MIDI events.",
        "The 0x0201e13e cave is safe as both an early-boot callee and a later MIDI-event callee, despite prior live proof covering only event-path use.",
        "A 156-byte runtime source object can be cloned or staged without recovering its full producer, lifecycle, and post-load initialization.",
    ]
    result["reusable_patch_primitives"] = [
        "At 0x0201c67c, redirecting Note On memcpy to a small wrapper is live-booted by R01/R01b/R01c, but only for post-USB event-path use.",
        "At 0x0201c63e, redirecting Note Off memcpy to the same Ch10 source wrapper is live-booted by R01b/R01c and fixes the R01 stuck-note class.",
        "At 0x0201e468 and 0x0201e49c, zeroing the two stale SysEx direct callers is live-booted by R01/R01b/R01c.",
        "The code cave starting at 0x0201e13e can hold a compact channel-gated wrapper in live-booted builds. R01d's early preload body is not included in this reusable primitive.",
    ]
    result["conclusion"] = {
        "most_likely_pre_usb_cause": "0x02005f9c post-init callsite redirection to the new R01d preload body at 0x0201e13e",
        "confidence": "high for address family, medium for exact failing instruction inside preload body without trace hardware",
        "reason": "It is the only R01d-only executable change that can run before USB enumeration. All other R01d addresses were previously live-booted as event-path or stale-caller changes, or cannot execute until after USB MIDI is available.",
    }

    out_json = OUT / "evidence.json"
    out_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    lines = []
    lines.append("# R01d incident reanalysis")
    lines.append("")
    lines.append("Scope: official v15, live-booted R01/R01b/R01c, and bricked/revoked R01d only. No v12 firmware assumptions are used. No patching, flashing, or device access is performed.")
    lines.append("")
    lines.append("## Conclusion")
    lines.append("")
    c = result["conclusion"]
    lines.append(f"Most likely pre-USB boot-failure cause: **{c['most_likely_pre_usb_cause']}**.")
    lines.append("")
    lines.append(f"Confidence: {c['confidence']}. {c['reason']}")
    lines.append("")
    lines.append("## Hash validation")
    lines.append("")
    lines.append("| Artifact | Package SHA-256 | App SHA-256 | Status |")
    lines.append("|---|---|---|---|")
    for name, entry in result["variants"].items():
        lines.append(f"| {name} | `{entry['package_sha256']}` | `{entry['app_sha256']}` | {'PASS' if entry['hashes_match_expected'] else 'FAIL'}; {entry['live_status']} |")
    lines.append("")
    lines.append("## R01d address-by-address classification")
    lines.append("")
    lines.append("| Address | Flash offset | Prior live-booted presence | R01d status | Cause likelihood | Classification |")
    lines.append("|---|---:|---|---|---|---|")
    for row in result["r01d_address_classification"]:
        prior = ", ".join(row["present_in_live_booted_prior_variants"]) or "none"
        lines.append(f"| `{row['address']}` | `{row['flash_offset']}` | {prior} | {row['r01d_status']} | {row['cause_likelihood']} | {row['classification']} |")
    lines.append("")
    lines.append("## Address evidence and rationale")
    lines.append("")
    for row in result["r01d_address_classification"]:
        lines.append(f"### `{row['address']}`")
        lines.append("")
        lines.append(f"- App offset: `{row['app_file_offset']}`; flash offset: `{row['flash_offset']}`; byte length: `{row['new_len']}`.")
        lines.append(f"- Present in previous live-booted variants: {', '.join(row['present_in_live_booted_prior_variants']) or 'none'}.")
        lines.append(f"- Classification: **{row['classification']}**.")
        lines.append(f"- Cause likelihood: **{row['cause_likelihood']}**.")
        lines.append(f"- Rationale: {row['rationale']}")
        lines.append(f"- Reusable primitive: {row['reusable_primitive']}.")
        lines.append("")
    lines.append("## Validated R01d diff ranges")
    lines.append("")
    lines.append("Manifest app ranges:")
    for r in result["r01d_diff_ranges"]["app_ranges_manifest"]:
        lines.append(f"- `{r['start']}..{r['end_exclusive']}` exclusive")
    lines.append("")
    lines.append("Manifest flash ranges, including wrapper/header CRC fields:")
    for r in result["r01d_diff_ranges"]["flash_ranges_manifest"]:
        lines.append(f"- `{r['start']}..{r['end_exclusive']}` exclusive")
    lines.append("")
    lines.append("Actual changed app byte runs versus official v15:")
    for r in result["r01d_diff_ranges"]["actual_app_diff_ranges_vs_official"]:
        lines.append(f"- `{r['start_hex']}..{r['end_exclusive_hex']}` exclusive, {r['size']} bytes")
    lines.append("")
    lines.append("R01d changed 4 KiB sectors versus official v15: `0x04000`, `0x0a000`, `0x20000`, `0x22000`.")
    lines.append("")
    lines.append("## Unsafe assumptions explicitly revoked")
    lines.append("")
    for item in result["unsafe_assumptions"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Previously live-booted reusable patch primitives")
    lines.append("")
    for item in result["reusable_patch_primitives"]:
        lines.append(f"- {item}")
    lines.append("")
    lines.append("## Source evidence")
    lines.append("")
    lines.append("- `baselines/v15/analysis/flash-candidates/R01/live-validation-20260802.md` records R01 booting and summarizes R01b/R01c live behavior.")
    lines.append("- `logs/v15/ota-v15-r01d-live-20260802T1813Z.log` records R01d OTA completion through `completion 0xf0000000 acknowledged`.")
    lines.append("- `recovery/v15/post-recovery-baseline-20260802.json` records R01d as `BRICKED_REVOKED` and the exact changed sectors.")
    lines.append("- `tools/validate_v15_r01d.py` validates R01d artifact integrity and explicitly says it is not a functional success claim.")
    lines.append("")
    (OUT / "report.md").write_text("\n".join(lines) + "\n")

    sha_lines = []
    for p in [OUT / "analyze_r01d_incident.py", OUT / "evidence.json", OUT / "report.md"]:
        sha_lines.append(f"{sha(p)}  {p.name}")
    (OUT / "SHA256SUMS").write_text("\n".join(sha_lines) + "\n")
    print(json.dumps({"status": "PASS", "output": str(out_json.relative_to(ROOT))}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
