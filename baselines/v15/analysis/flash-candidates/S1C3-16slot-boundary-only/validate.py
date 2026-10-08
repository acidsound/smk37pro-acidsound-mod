#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import json
from pathlib import Path
HERE = Path(__file__).resolve().parent
PACKAGE = HERE / "SMK37Pro-v15-S1C3-16slot-boundary-only.fwsc"
APP = HERE / "app.bin"
EVIDENCE = HERE / "evidence.json"
SHA256SUMS = HERE / "SHA256SUMS"
def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
def req(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"FAIL: {msg}")
def main() -> int:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    app = evidence["app"]; pkg = evidence["package"]; boundary = app["boundary"]
    req(sha256(APP) == app["output_app_sha256"], "app hash")
    req(sha256(PACKAGE) == pkg["package_sha256"], "package hash")
    req(boundary["data_model_required_reservation_hex"] == "0x0a90", "reservation")
    req(boundary["candidate_heap_begin"] == "0x01c46fb0", "heap begin")
    req(boundary["boot_bss_zero_size_hex"] == "0x0003d5dc", "BSS size")
    req(app["s1c2_parent_relative_changed_byte_count"] == 4, "parent diff count")
    req(pkg["changed_flash_sectors_vs_official"] == ["0x04000", "0x20000", "0x22000", "0x2a000", "0x62000"], "official changed sectors")
    req(pkg["changed_flash_sectors_vs_s1c2_parent"] == ["0x04000", "0x62000"], "parent changed sectors")
    req(pkg["rollback_restores_official_flash"] is True, "rollback restores official")
    for line in SHA256SUMS.read_text(encoding="utf-8").splitlines():
        if not line.strip(): continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        req(sha256(HERE / rel) == digest, f"SHA256SUMS {rel}")
    print("S1-C3 16-slot boundary-only validation PASS")
    return 0
if __name__ == "__main__":
    raise SystemExit(main())
