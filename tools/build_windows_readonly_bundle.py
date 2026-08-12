#!/usr/bin/env python3
"""Build a self-contained Windows read-only recovery ZIP."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


OFFICIAL_LOADER_SIZE = 31232
OFFICIAL_LOADER_SHA256 = (
    "9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27"
)
EXPECTED_SECTORS = {0x04000, 0x20000, 0x21000, 0x27000, 0x5A000, 0x99000}
EXPECTED_HASH_REPRESENTATION = (
    "FWSC-unpacked flash.bin bytes; not directly comparable to a forced-loader "
    "dump until its returned representation is validated"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate_loader(path: Path) -> None:
    if path.stat().st_size != OFFICIAL_LOADER_SIZE:
        raise SystemExit(
            f"loader size mismatch: {path.stat().st_size} != {OFFICIAL_LOADER_SIZE}"
        )
    actual = sha256(path)
    if actual != OFFICIAL_LOADER_SHA256:
        raise SystemExit(f"loader SHA-256 mismatch: {actual}")


def validate_manifest(path: Path) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("format") != "smk37-m09-forced-recovery-plan-v1":
        raise SystemExit("recovery manifest format mismatch")
    if value.get("hash_representation") != EXPECTED_HASH_REPRESENTATION:
        raise SystemExit("recovery manifest representation boundary mismatch")
    sectors = value.get("sectors")
    if not isinstance(sectors, list):
        raise SystemExit("recovery manifest sector list is missing")
    addresses = {int(item["address"], 0) for item in sectors}
    if addresses != EXPECTED_SECTORS:
        raise SystemExit(f"recovery sector set mismatch: {sorted(addresses)}")


def git_revision(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def git_tree_dirty(root: Path) -> bool:
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return bool(result.stdout.strip())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--loader", required=True, type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build/SMK37Pro-Windows-ReadOnly-Recovery.zip"),
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    source = root / "windows-readonly"
    loader = args.loader.resolve()
    manifest = source / "expected" / "m09-forced-recovery-manifest.json"
    output = args.output if args.output.is_absolute() else root / args.output
    staging = output.with_suffix("")

    validate_loader(loader)
    validate_manifest(manifest)
    generated_manifest = root / "build" / "m09-forced-recovery" / "manifest.json"
    if generated_manifest.exists() and generated_manifest.read_bytes() != manifest.read_bytes():
        raise SystemExit("tracked and generated M09 recovery manifests differ")

    if staging.exists():
        shutil.rmtree(staging)
    output.unlink(missing_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source,
        staging,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "output"),
    )
    (staging / "output").mkdir()
    shutil.copy2(loader, staging / "assets" / "wl82loader.bin")

    files: list[dict[str, object]] = []
    for path in sorted(item for item in staging.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(staging).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256(path),
            }
        )
    bundle_manifest = {
        "format": "smk37-windows-readonly-bundle-v1",
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_revision": git_revision(root),
        "source_tree_dirty": git_tree_dirty(root),
        "safety_scope": "read-only Flash acquisition; volatile RAM loader upload only",
        "files": files,
    }
    (staging / "BUNDLE-MANIFEST.json").write_text(
        json.dumps(bundle_manifest, indent=2) + "\n", encoding="utf-8"
    )

    archive_base = output.with_suffix("")
    made = Path(shutil.make_archive(str(archive_base), "zip", staging.parent, staging.name))
    if made != output:
        raise SystemExit(f"unexpected archive path: {made}")
    print(f"bundle: {output}")
    print(f"size: {output.stat().st_size}")
    print(f"sha256: {sha256(output)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
