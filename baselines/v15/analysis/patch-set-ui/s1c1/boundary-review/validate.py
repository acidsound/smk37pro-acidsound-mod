#!/usr/bin/env python3
"""Independent offline validator for the exact v15 S1-C1 boundary-only candidate."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import build_v15_h2_owned_source_corrected_fallback as h2  # noqa: E402
import build_v15_s1c1_boundary_only as candidate_builder  # noqa: E402
import build_v15_s1c1_boundary_rollback as rollback_builder  # noqa: E402
from build_v15_r01_hand_drum import off  # noqa: E402
from build_v15_r03_fixed_prefix import BSS_SIZE_INSN, HEAP_BEGIN_INSN  # noqa: E402
from smk37_v15_app_patch import protected_hashes  # noqa: E402

OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
H2_DIR = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback"
H2_APP = H2_DIR / "app.bin"
H2_PACKAGE = H2_DIR / "SMK37Pro-v15-H2-owned-source-corrected-fallback.fwsc"
CANDIDATE_DIR = ROOT / "build/SMK37Pro-v15-S1C1-boundary-only"
CANDIDATE_APP = CANDIDATE_DIR / "app.bin"
CANDIDATE_PACKAGE = CANDIDATE_DIR / candidate_builder.PACKAGE_NAME
ROLLBACK_DIR = ROOT / "build/SMK37Pro-WL82-v15-S1C1B-rollback-20260802-v1"
ROLLBACK_ZIP = ROOT / "build/SMK37Pro-WL82-v15-S1C1B-rollback-20260802-v1.zip"
ROLLBACK_TEMPLATE = ROOT / "build/SMK37Pro-WL82-v15-H2-rollback-20260802-v1"
OTA_SOURCE = ROOT / "tools/smk37_v15_s1c1_boundary_ota.c"
EVIDENCE = HERE / "evidence.json"
REPORT = HERE / "report.md"

EXPECTED_HASHES = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "official_package": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "h2_app": "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    "h2_package": "c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011",
    "candidate_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "candidate_package": "ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d",
    "rollback_zip": "9cf3a7ec8a24e09d2d2bef9d55d73363c01f8461a3800ad37ba30abb72d332f1",
}
EXPECTED_DIFFS = [0x20, 0x21, 0x5E9FA, 0x5E9FB]
EXPECTED_SECTORS = [0x04000, 0x20000, 0x22000, 0x2A000, 0x62000]
EXPECTED_CONFIRMATIONS = [
    "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_S1C1B_SECTORS",
    "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_S1C1B_TARGET_HASHES",
    "RESTORE_OFFICIAL_V15_SECTORS_NOW",
]
EXPECTED_PROTECTED = {
    "boot_and_flash_layout_0x0000_0x3fff": "d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67",
    "isd_config_raw_0x38d0_0x3b8a": "0952afd96f533dd0fba72a8fab9cb4a4336f55424a1a89eecb13ff8a51a0eff0",
    "post_app_resources_and_reserved": "53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7",
    "uboot_boot_raw_0x00a0_0x38cf": "b5a0715940db344f951595e2d5a66050631c7721703cb06d33d8dc94eca3c861",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require(condition: bool, label: str, detail: object, checks: list[str]) -> None:
    if not condition:
        raise SystemExit(f"FAIL\t{label}\t{detail}")
    checks.append(f"PASS\t{label}\t{detail}")


def run(command: list[str], *, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


def directory_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*")) if path.is_file()
    }


def validate_hash_inventory(root: Path, checks: list[str]) -> None:
    lines = (root / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines()
    expected = {}
    for line in lines:
        digest, relative = line.split("  ", 1)
        require(relative not in expected, "rollback-hash-inventory-unique", relative, checks)
        expected[relative] = digest
    actual_names = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*") if path.is_file() and path.name != "SHA256SUMS.txt"
    }
    require(set(expected) == actual_names, "rollback-hash-inventory-complete", len(actual_names), checks)
    for relative, digest in sorted(expected.items()):
        require(sha256_file(root / relative) == digest, "rollback-member-sha256", relative, checks)


def validate_zip(root: Path, archive_path: Path, checks: list[str]) -> None:
    top = root.name
    expected_files = directory_files(root)
    with zipfile.ZipFile(archive_path) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        require(len(names) == len(set(names)), "rollback-zip-no-duplicates", len(names), checks)
        file_infos = {info.filename: info for info in infos if not info.is_dir()}
        expected_names = {f"{top}/{name}" for name in expected_files}
        require(set(file_infos) == expected_names, "rollback-zip-file-set", len(expected_names), checks)
        require(archive.testzip() is None, "rollback-zip-crc", "all members", checks)
        for relative, data in expected_files.items():
            name = f"{top}/{relative}"
            info = file_infos[name]
            require(archive.read(name) == data, "rollback-zip-member-bytes", relative, checks)
            require(info.date_time == (2026, 8, 2, 0, 0, 0), "rollback-zip-fixed-time", relative, checks)


def main() -> int:
    checks: list[str] = []
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    report = REPORT.read_text(encoding="utf-8")

    require(evidence["verdict"] == "PASS", "evidence-verdict", "PASS", checks)
    require(evidence["scope"] == {
        "device_accessed": False,
        "flash_performed": False,
        "review_type": "independent offline exact-artifact review",
    }, "review-scope", "offline; no device; no flash", checks)
    require("**PASS**" in report and "No device was accessed" in report,
            "report-verdict-and-scope", "PASS/offline", checks)

    paths = {
        "official_app": OFFICIAL_APP,
        "official_package": OFFICIAL_PACKAGE,
        "h2_app": H2_APP,
        "h2_package": H2_PACKAGE,
        "candidate_app": CANDIDATE_APP,
        "candidate_package": CANDIDATE_PACKAGE,
        "rollback_zip": ROLLBACK_ZIP,
    }
    for name, path in paths.items():
        require(path.is_file(), "artifact-exists", path.relative_to(ROOT), checks)
        actual = sha256_file(path)
        require(actual == EXPECTED_HASHES[name], "exact-sha256", f"{name} {actual}", checks)
        require(evidence["hashes"][name] == actual, "evidence-sha256", name, checks)

    official = OFFICIAL_APP.read_bytes()
    h2_app = H2_APP.read_bytes()
    child = CANDIDATE_APP.read_bytes()
    require(len(official) == len(h2_app) == len(child) == 617012,
            "app-length", len(child), checks)

    rebuilt_h2, h2_manifest = h2.build_app(official)
    require(rebuilt_h2 == h2_app, "h2-rebuild-byte-identical", EXPECTED_HASHES["h2_app"], checks)
    diffs = [index for index, pair in enumerate(zip(h2_app, child)) if pair[0] != pair[1]]
    require(diffs == EXPECTED_DIFFS, "h2-relative-exact-four-byte-delta",
            ",".join(f"0x{x:x}" for x in diffs), checks)
    require(evidence["h2_relative_delta"]["offsets"] == [f"0x{x:x}" for x in diffs],
            "evidence-delta-offsets", len(diffs), checks)

    bss_slice = slice(off(BSS_SIZE_INSN), off(BSS_SIZE_INSN) + 6)
    heap_slice = slice(off(HEAP_BEGIN_INSN), off(HEAP_BEGIN_INSN) + 6)
    require(h2_app[bss_slice] == bytes.fromhex("c2ffeccb0300"),
            "h2-bss-instruction", h2_app[bss_slice].hex(), checks)
    require(child[bss_slice] == bytes.fromhex("c2ff8ccc0300"),
            "candidate-bss-instruction", child[bss_slice].hex(), checks)
    require(h2_app[heap_slice] == bytes.fromhex("c5ffc065c401"),
            "h2-heap-instruction", h2_app[heap_slice].hex(), checks)
    require(child[heap_slice] == bytes.fromhex("c5ff6066c401"),
            "candidate-heap-instruction", child[heap_slice].hex(), checks)
    h2_bss = int.from_bytes(h2_app[bss_slice][2:], "little")
    child_bss = int.from_bytes(child[bss_slice][2:], "little")
    h2_heap = int.from_bytes(h2_app[heap_slice][2:], "little")
    child_heap = int.from_bytes(child[heap_slice][2:], "little")
    require(child_bss - h2_bss == child_heap - h2_heap == 0xA0,
            "paired-boundary-increment", "BSS +0xa0; HEAP_BEGIN +0xa0", checks)
    require(h2_heap - h2_bss == child_heap - child_bss == 0x01C099D4,
            "paired-bss-base", "0x01c099d4", checks)
    require(child_heap == 0x01C46660 and child_bss == 0x0003CC8C,
            "candidate-boundary-values", "BSS=0x3cc8c HEAP_BEGIN=0x01c46660", checks)
    require(evidence["paired_boundaries"] == {
        "bss_start": "0x01c099d4",
        "h2_bss_size": "0x0003cbec",
        "candidate_bss_size": "0x0003cc8c",
        "bss_increment": "0x000000a0",
        "h2_heap_begin": "0x01c465c0",
        "candidate_heap_begin": "0x01c46660",
        "heap_begin_increment": "0x000000a0",
        "candidate_heap_span_to_0x01c7fd30": "0x000396d0",
    }, "evidence-paired-boundaries", "exact values", checks)

    cave_end = int(h2_manifest["layout"]["end"], 16)
    require(child[off(h2.CODE_CAVE):off(cave_end)] == h2_app[off(h2.CODE_CAVE):off(cave_end)],
            "h2-code-cave-byte-identical", f"0x{h2.CODE_CAVE:08x}..0x{cave_end:08x}", checks)
    allowed = set(range(bss_slice.start, bss_slice.stop)) | set(range(heap_slice.start, heap_slice.stop))
    require(set(diffs).issubset(allowed), "only-boundary-immediate-operands-changed", len(diffs), checks)
    require(bytes.fromhex("c065c401") not in child,
            "no-literal-slot1-base-reference", "0x01c465c0 absent after heap immediate moved", checks)
    for address in (0x01C465BE, 0x01C465BF):
        require(address.to_bytes(4, "little") not in child,
                "no-literal-selector-address", f"0x{address:08x}", checks)
    require(evidence["behavior_scope"] == {
        "h2_code_cave_byte_identical": True,
        "new_second_slot_access": False,
        "new_selector_behavior": False,
        "only_boundary_immediate_operands_changed": True,
    }, "evidence-behavior-scope", "H2 behavior retained", checks)

    official_flash = rollback_builder.flash_from_package(OFFICIAL_PACKAGE)
    child_flash = rollback_builder.flash_from_package(CANDIDATE_PACKAGE)
    before = protected_hashes(official_flash)
    after = protected_hashes(child_flash)
    require(before == after == EXPECTED_PROTECTED,
            "protected-flash-hashes", "before == after == locked values", checks)
    require(evidence["protected_flash_hashes"] == EXPECTED_PROTECTED,
            "evidence-protected-flash-hashes", "exact", checks)
    package_manifest = json.loads((CANDIDATE_DIR / "package-manifest.json").read_text())
    require(package_manifest["protected_flash_hashes_before"] == before,
            "package-manifest-protected-before", "exact", checks)
    require(package_manifest["protected_flash_hashes_after"] == after,
            "package-manifest-protected-after", "exact", checks)
    require(package_manifest["safety_gate"] == "PASS", "package-safety-gate", "PASS", checks)

    with tempfile.TemporaryDirectory(prefix="s1c1-boundary-review-", dir=os.environ.get("JCODE_SCRATCH_DIR")) as temp:
        temp_root = Path(temp)
        candidate_scratch = temp_root / "candidate"
        rebuilt = candidate_builder.build_once(OFFICIAL_APP, OFFICIAL_PACKAGE, candidate_scratch, None)
        for name in ["app.bin", candidate_builder.PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "SHA256SUMS"]:
            require((candidate_scratch / name).read_bytes() == (CANDIDATE_DIR / name).read_bytes(),
                    "candidate-deterministic-rebuild", name, checks)
        require(rebuilt["app_sha256"] == EXPECTED_HASHES["candidate_app"] and
                rebuilt["package_sha256"] == EXPECTED_HASHES["candidate_package"],
                "candidate-rebuild-summary", "exact locked hashes", checks)

        ota_binary = temp_root / "s1c1-boundary-ota"
        compile_result = run([
            "cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Isrc",
            *subprocess.check_output(["pkg-config", "--cflags", "libusb-1.0"], text=True).split(),
            str(OTA_SOURCE), "src/device_info.c", "src/fwsc.c", "src/protocol.c", "src/sha256.c", "src/usb_probe.c",
            "-o", str(ota_binary),
            *subprocess.check_output(["pkg-config", "--libs", "libusb-1.0"], text=True).split(),
        ])
        require(compile_result.returncode == 0, "ota-compile", compile_result.stderr.strip() or "clean", checks)
        ota_matrix = [
            ("candidate", CANDIDATE_PACKAGE, 0, "exact v15 S1-C1 boundary-only package: PASS"),
            ("official", OFFICIAL_PACKAGE, 1, "offline check rejected"),
            ("h2", H2_PACKAGE, 1, "offline check rejected"),
            ("malformed", REPORT, 1, "OTA file format validation failed"),
        ]
        for label, package, expected_rc, expected_text in ota_matrix:
            result = run([str(ota_binary), "check", str(package)])
            combined = result.stdout + result.stderr
            require(result.returncode == expected_rc and expected_text in combined,
                    "ota-exact-check", f"{label} rc={result.returncode}", checks)
        source = OTA_SOURCE.read_text(encoding="utf-8")
        require("INSTALL-SMK37PRO-V15-S1C1-BOUNDARY-AE8C44A4" in source,
                "ota-confirmation-token", "exact", checks)
        source_hash = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-fA-F]{2})", source.split("static const char CONFIRM", 1)[0])[-32:])
        require(source_hash.hex() == EXPECTED_HASHES["candidate_package"],
                "ota-embedded-package-hash", source_hash.hex(), checks)

        rebuilt_rollback = temp_root / rollback_builder.BUNDLE_NAME
        rebuilt_zip = temp_root / f"{rollback_builder.BUNDLE_NAME}.zip"
        result = run([
            sys.executable, str(ROOT / "tools/build_v15_s1c1_boundary_rollback.py"),
            "--official", str(OFFICIAL_PACKAGE),
            "--target", str(CANDIDATE_PACKAGE),
            "--template", str(ROLLBACK_TEMPLATE),
            "--output-dir", str(rebuilt_rollback),
            "--output-zip", str(rebuilt_zip),
        ])
        require(result.returncode == 0, "rollback-rebuild", result.stderr.strip() or "PASS", checks)
        require(directory_files(rebuilt_rollback) == directory_files(ROLLBACK_DIR),
                "rollback-directory-deterministic", len(directory_files(ROLLBACK_DIR)), checks)
        require(rebuilt_zip.read_bytes() == ROLLBACK_ZIP.read_bytes(),
                "rollback-zip-deterministic", EXPECTED_HASHES["rollback_zip"], checks)
        require(evidence["determinism"] == {
            "candidate_files_byte_identical": [
                "app.bin", candidate_builder.PACKAGE_NAME, "app-manifest.json",
                "package-manifest.json", "SHA256SUMS",
            ],
            "rollback_directory_byte_identical": True,
            "rollback_zip_byte_identical": True,
        }, "evidence-determinism", "candidate and rollback", checks)

    manifest = json.loads((ROLLBACK_DIR / "recovery-sectors/manifest.json").read_text())
    sectors = [int(record["address"], 16) for record in manifest["sectors"]]
    actual_sectors = [
        address for address in range(0, len(official_flash), rollback_builder.SECTOR_SIZE)
        if official_flash[address:address + rollback_builder.SECTOR_SIZE] !=
           child_flash[address:address + rollback_builder.SECTOR_SIZE]
    ]
    require(sectors == actual_sectors == EXPECTED_SECTORS,
            "rollback-exact-five-sector-set", ",".join(f"0x{x:05x}" for x in sectors), checks)
    require(manifest["confirmations"] == EXPECTED_CONFIRMATIONS,
            "rollback-manifest-confirmations", len(EXPECTED_CONFIRMATIONS), checks)
    require(evidence["rollback"]["confirmations"] == EXPECTED_CONFIRMATIONS,
            "evidence-rollback-confirmations", len(EXPECTED_CONFIRMATIONS), checks)
    require(manifest["stock_package_sha256"] == EXPECTED_HASHES["official_package"] and
            manifest["s1c1b_package_sha256"] == EXPECTED_HASHES["candidate_package"],
            "rollback-manifest-package-hashes", "official and candidate", checks)
    for record in manifest["sectors"]:
        address = int(record["address"], 16)
        stock = official_flash[address:address + rollback_builder.SECTOR_SIZE]
        target = child_flash[address:address + rollback_builder.SECTOR_SIZE]
        require(sha256_bytes(stock) == record["stock_sha256"],
                "rollback-stock-sector-hash", record["address"], checks)
        require(sha256_bytes(target) == record["expected_target_sha256"],
                "rollback-target-sector-hash", record["address"], checks)
        require(sum(a != b for a, b in zip(stock, target)) == record["changed_byte_count"],
                "rollback-sector-changed-count", f"{record['address']} {record['changed_byte_count']}", checks)
        require((ROLLBACK_DIR / "recovery-sectors" / record["stock_file"]).read_bytes() == stock,
                "rollback-stock-sector-bytes", record["stock_file"], checks)
    expected_evidence_records = [
        {
            "address": record["address"],
            "stock_sha256": record["stock_sha256"],
            "target_sha256": record["expected_target_sha256"],
            "changed_byte_count": record["changed_byte_count"],
        }
        for record in manifest["sectors"]
    ]
    require(evidence["rollback"]["sector_records"] == expected_evidence_records,
            "evidence-rollback-sector-records", len(expected_evidence_records), checks)

    guard_path = ROLLBACK_DIR / "restore/smk37_wl82_guarded_restore.py"
    wrapper_path = ROLLBACK_DIR / "restore/run-restore-elevated.ps1"
    guard = guard_path.read_text(encoding="utf-8")
    wrapper = wrapper_path.read_text(encoding="utf-8")
    for token in EXPECTED_CONFIRMATIONS:
        require(guard.count(f'"{token}"') == 1, "rollback-guard-token", token, checks)
        require(wrapper.count(f"--confirm {token}") == 1, "rollback-wrapper-token", token, checks)
    for path in ROLLBACK_DIR.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".md", ".txt", ".py", ".ps1", ".json"}:
            data = path.read_bytes()
            require(b"H2" not in data and b"h2" not in data,
                    "rollback-no-stale-h2-token", path.relative_to(ROLLBACK_DIR), checks)
    self_test = run([sys.executable, str(guard_path), "self-test"])
    require(self_test.returncode == 0 and "self-test PASS" in self_test.stdout,
            "rollback-guard-self-test", "FakeTransport and failure cases", checks)
    validate_hash_inventory(ROLLBACK_DIR, checks)
    validate_zip(ROLLBACK_DIR, ROLLBACK_ZIP, checks)

    require(evidence["rollback"]["sectors"] == [f"0x{x:05x}" for x in EXPECTED_SECTORS],
            "evidence-rollback-sectors", 5, checks)
    require(evidence["ota_check_matrix"] == {
        "candidate": 0,
        "h2_parent": 1,
        "malformed": 1,
        "official_v15": 1,
    }, "evidence-ota-matrix", "exact accept/reject", checks)
    require(evidence["ota_confirmation"] == "INSTALL-SMK37PRO-V15-S1C1-BOUNDARY-AE8C44A4",
            "evidence-ota-confirmation", "exact", checks)

    print("\n".join(checks))
    print(f"PASS\tfinal-verdict\t{len(checks)} independent offline checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
