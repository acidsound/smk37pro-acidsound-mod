#!/usr/bin/env python3
"""Create a hash-locked macOS restore plan after independent recovery proof.

This command is offline only.  It never opens USB, erases Flash, or writes
Flash.  It refuses to create a plan until the two full forced-loader dumps are
byte-identical and a separate proof declares that the forced-loader bytes and
the FWSC-unpacked bytes have the same representation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile


EXPECTED_FORMAT = "smk37-m09-forced-recovery-plan-v1"
EXPECTED_DUMP_FORMAT = "smk37-wl82-readonly-dump-v1"
EXPECTED_PROOF_FORMAT = "smk37-wl82-representation-proof-v1"
EXPECTED_LOADER_SHA256 = (
    "9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27"
)
EXPECTED_STOCK_PACKAGE_SHA256 = (
    "c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a"
)
FLASH_SIZE = 0x100000
SECTOR_SIZE = 0x1000
EXPECTED_SECTORS = (0x04000, 0x20000, 0x21000, 0x27000, 0x5A000, 0x99000)


class SafeStop(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fail(message: str) -> None:
    raise SafeStop(message)


def read_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"cannot read JSON {path}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON root is not an object: {path}")
    return value


def require(value: object, expected: object, label: str) -> None:
    if value != expected:
        fail(f"{label} mismatch: got {value!r}, expected {expected!r}")


def validate_manifest(path: Path) -> dict[str, object]:
    manifest = read_json(path)
    require(manifest.get("format"), EXPECTED_FORMAT, "recovery manifest format")
    sectors = manifest.get("sectors")
    if not isinstance(sectors, list):
        fail("recovery manifest has no sector list")
    addresses = tuple(sorted(int(item["address"], 0) for item in sectors))
    if addresses != EXPECTED_SECTORS:
        fail(f"recovery sector set mismatch: {addresses!r}")
    require(
        manifest.get("stock_package_sha256"),
        EXPECTED_STOCK_PACKAGE_SHA256,
        "stock package hash in recovery manifest",
    )
    for item in sectors:
        require(item.get("length"), SECTOR_SIZE, f"sector {item.get('address')} length")
        for key in ("stock_file", "stock_sha256", "expected_m09_sha256"):
            if not isinstance(item.get(key), str):
                fail(f"sector {item.get('address')} is missing {key}")
    return manifest


def validate_dump_report(path: Path) -> tuple[dict[str, object], dict[int, str]]:
    report = read_json(path)
    require(report.get("format"), EXPECTED_DUMP_FORMAT, "dump report format")
    require(report.get("identity"), {
        "vendor": "WL82",
        "product": "UBOOT1.00",
        "revision": "1.00",
    }, "dump report identity")
    loader = report.get("official_loader")
    if not isinstance(loader, dict):
        fail("dump report has no official loader record")
    require(loader.get("size"), 31232, "dump report loader size")
    require(loader.get("sha256"), EXPECTED_LOADER_SHA256,
            "dump report loader hash")
    require(report.get("flash_size"), FLASH_SIZE, "dump report Flash size")
    require(report.get("dumps_byte_identical"), True, "double-dump equality")
    require(report.get("read_only_acquisition_pass"), True, "read-only acquisition")

    dump_hashes: dict[int, str] = {}
    for key in ("dump_a", "dump_b"):
        item = report.get(key)
        if not isinstance(item, dict) or not isinstance(item.get("file"), str):
            fail(f"dump report missing {key}")
        dump_path = path.parent / item["file"]
        if not dump_path.is_file() or dump_path.stat().st_size != FLASH_SIZE:
            fail(f"{key} is not an exact 1 MiB dump: {dump_path}")
        actual = sha256_file(dump_path)
        require(item.get("sha256"), actual, f"{key} SHA-256")
        dump_hashes[0 if key == "dump_a" else 1] = actual
    require(dump_hashes[0], dump_hashes[1], "dump A/B SHA-256")
    return report, dump_hashes


def validate_representation_proof(path: Path, dump_report: Path,
                                  manifest: dict[str, object]) -> None:
    proof = read_json(path)
    require(proof.get("format"), EXPECTED_PROOF_FORMAT, "representation proof format")
    require(proof.get("status"), "PASS", "representation proof status")
    require(proof.get("mapping"), "identity", "package/dump byte mapping")
    require(proof.get("dump_report"), str(dump_report), "proof dump report path")
    require(proof.get("stock_package_sha256"), EXPECTED_STOCK_PACKAGE_SHA256,
            "proof stock package hash")

    checks = proof.get("sectors")
    if not isinstance(checks, list):
        fail("representation proof has no sector checks")
    by_address = {int(item["address"], 0): item for item in checks}
    manifest_by_address = {
        int(item["address"], 0): item for item in manifest["sectors"]  # type: ignore[index]
    }
    if tuple(sorted(by_address)) != EXPECTED_SECTORS:
        fail("representation proof does not cover exactly the six audited sectors")
    for address in EXPECTED_SECTORS:
        check = by_address[address]
        expected = manifest_by_address[address]
        require(check.get("package_stock_sha256"), expected["stock_sha256"],
                f"proof stock sector hash 0x{address:05x}")
        require(check.get("package_m09_sha256"), expected["expected_m09_sha256"],
                f"proof M09 sector hash 0x{address:05x}")
        require(check.get("forced_dump_matches_m09"), True,
                f"proof current dump match 0x{address:05x}")


def create_plan(manifest_path: Path, dump_report: Path, proof_path: Path,
                stock_package: Path, output: Path) -> None:
    manifest = validate_manifest(manifest_path)
    if not stock_package.is_file():
        fail(f"stock package not found: {stock_package}")
    require(sha256_file(stock_package), EXPECTED_STOCK_PACKAGE_SHA256,
            "stock package SHA-256")
    report, _ = validate_dump_report(dump_report)
    validate_representation_proof(proof_path, dump_report, manifest)

    lines = [
        "format=smk37-macos-restore-plan-v1",
        "restore_authorized=true",
        "target_vid=0x4C4A",
        "target_pid=0x8057",
        "target_vendor=WL82",
        "target_product=UBOOT1.00",
        "target_revision=1.00",
        f"flash_size=0x{FLASH_SIZE:X}",
        "representation_status=PASS",
        "double_dump_status=PASS",
        f"loader_sha256={EXPECTED_LOADER_SHA256}",
        f"stock_package_sha256={EXPECTED_STOCK_PACKAGE_SHA256}",
        f"dump_report={dump_report}",
        f"representation_proof={proof_path}",
    ]
    for item in manifest["sectors"]:  # type: ignore[index]
        address = int(item["address"], 0)
        stock_file = manifest_path.parent / item["stock_file"]
        if stock_file.stat().st_size != SECTOR_SIZE:
            fail(f"stock sector is not 4 KiB: {stock_file}")
        require(sha256_file(stock_file), item["stock_sha256"],
                f"stock sector hash 0x{address:05x}")
        lines.append("sector=" + "|".join([
            f"0x{address:05X}",
            f"0x{SECTOR_SIZE:X}",
            str(stock_file),
            item["stock_sha256"],
            item["expected_m09_sha256"],
        ]))

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=output.parent,
                                     prefix=output.name + ".", delete=False) as handle:
        handle.write("\n".join(lines) + "\n")
        temporary = Path(handle.name)
    temporary.replace(output)
    print(output)
    print("PASS: hash-locked restore plan created; no USB or Flash access")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--dump-report", required=True, type=Path)
    parser.add_argument("--representation-proof", required=True, type=Path)
    parser.add_argument("--stock-package", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        create_plan(args.manifest, args.dump_report, args.representation_proof,
                    args.stock_package, args.output)
    except (OSError, KeyError, TypeError, ValueError, SafeStop) as error:
        print(f"SAFE STOP: {error}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
