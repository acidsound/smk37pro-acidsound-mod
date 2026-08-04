#!/usr/bin/env python3
"""Offline review harness for the exact S1C5-marked playback-note candidate.

No device, USB, MIDI, OTA upload, flash, reset, or live send path is opened.
Only candidate offline validators and exact-hash check mode are executed.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[5]
OUT = pathlib.Path(__file__).resolve().parent
CAND = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return-S1C5-marked"
UNMARKED = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return"
PARENT = ROOT / "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final"
OFFICIAL = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/SMK-37_Pro_015.fwsc"
PKG = CAND / "SMK37Pro-v15-S1C5-playback-register-return-S1C5-marked.fwsc"
BASE = 0x02000000
DISPLAY = 0x020572A2
NOFF_RELOAD = 0x0201C644
NON_RELOAD = 0x0201C682
SEL_START = 0x0201E13E
OWNED_END = 0x0201E254
NON_VELOCITY_STORE = 0x0201C68C
NOFF_HOOK = 0x0201C63E
NON_HOOK = 0x0201C67C
EXPECTED = {
    "head_prefix": "ebedcfe",
    "app_sha256": "c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5",
    "fwsc_sha256": "cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480",
    "unmarked_app_sha256": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "unmarked_fwsc_sha256": "0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91",
    "selector_producer_sha256": "4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1",
    "selector_sha256": "900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f",
    "producer_sha256": "a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438",
    "note_off_reload": "0d4000160016",
    "note_on_reload": "0e4000160016",
    "note_on_velocity_store": "8d42",
    "note_off_hook": "80fffa1a0000",
    "note_on_hook": "80ffc01a0000",
    "ota_token": "INSTALL-SMK37PRO-V15-S1C5-MARKED-PLAYBACK-CFAFA327",
    "sender_token": "SEND-SMK37PRO-V15-S1C5-ALL-C4-7C7A8AC8-523CCBC8-14D65142-EFAB2E0D",
}

def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def sha_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def off(address: int) -> int:
    return address - BASE

def run(args: list[str | pathlib.Path], cwd: pathlib.Path, expect: int = 0) -> dict[str, Any]:
    r = subprocess.run([str(a) for a in args], cwd=cwd, text=True, capture_output=True, check=False)
    return {"cmd": " ".join(str(a) for a in args), "cwd": str(cwd.relative_to(ROOT) if cwd.is_relative_to(ROOT) else cwd), "returncode": r.returncode, "expect": expect, "stdout": r.stdout, "stderr": r.stderr, "pass": r.returncode == expect}

def req(ok: bool, msg: str) -> None:
    if not ok:
        raise AssertionError(msg)

def compact(offsets: list[int]) -> list[dict[str, int]]:
    if not offsets:
        return []
    ranges = []
    start = prev = offsets[0]
    for x in offsets[1:]:
        if x == prev + 1:
            prev = x
        else:
            ranges.append({"start": start, "end_exclusive": prev + 1})
            start = prev = x
    ranges.append({"start": start, "end_exclusive": prev + 1})
    return ranges

def copy_for_rebuild(dst: pathlib.Path) -> pathlib.Path:
    needed = [
        "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return-S1C5-marked",
        "baselines/v15/analysis/flash-candidates/S1C4-playback-note-v3-segmented-final",
        "baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only",
        "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2",
        "baselines/v15/analysis/playback-note/candidate-v3-segmented-final",
        "src",
    ]
    clone = dst / "SMK37ProMod"
    for rel in needed:
        s = ROOT / rel
        d = clone / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(s, d, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))
    return clone

def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    evidence: dict[str, Any] = {"decision": "PASS", "scope": {"offline_only": True, "device_accessed": False, "usb_opened": False, "midi_transport_opened": False, "ota_performed": False, "flash_performed": False, "reset_performed": False}}

    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    evidence["head"] = {"commit": head, "short": head[:12], "expected_prefix": EXPECTED["head_prefix"], "status": "PASS" if head.startswith(EXPECTED["head_prefix"]) else "BLOCK"}
    req(head.startswith(EXPECTED["head_prefix"]), "HEAD is not amended candidate ebedcfe")

    top_fwsc = sorted(p.name for p in CAND.glob("*.fwsc"))
    evidence["candidate_inventory"] = {"path": str(CAND.relative_to(ROOT)), "top_level_fwsc_files": top_fwsc}
    req(top_fwsc == [PKG.name], "unexpected FWSC artifact inventory")

    val = run([sys.executable, "validate.py"], CAND)
    dry = run([sys.executable, "dry_run_validate.py", "--json"], CAND)
    evidence["candidate_validators"] = {"validate_py": val, "dry_run_validate_json": dry}
    req(val["pass"], "candidate validate.py failed")
    req(dry["pass"], "candidate dry_run_validate.py failed")
    dry_json = json.loads(dry["stdout"])
    req(dry_json["status"] == "DRY_RUN_PASS" and dry_json["device_accessed"] is False and dry_json["midi_transport_opened"] is False, "dry run scope failed")

    app = (CAND / "app.bin").read_bytes()
    unmarked_app = (UNMARKED / "app.bin").read_bytes()
    app_sha = sha_bytes(app)
    pkg_sha = sha_file(PKG)
    req(app_sha == EXPECTED["app_sha256"], "marked app hash mismatch")
    req(pkg_sha == EXPECTED["fwsc_sha256"], "marked fwsc hash mismatch")
    req(sha_bytes(unmarked_app) == EXPECTED["unmarked_app_sha256"], "unmarked independently reviewed S1C5 app hash mismatch")
    marker_old = unmarked_app[off(DISPLAY):off(DISPLAY) + 5]
    marker_new = app[off(DISPLAY):off(DISPLAY) + 5]
    diff_vs_unmarked = [i for i, (a, b) in enumerate(zip(app, unmarked_app)) if a != b]
    req(marker_old == b"1.10\0" and marker_new == b"S1C5\0", "display marker transition mismatch")
    req(diff_vs_unmarked == [off(DISPLAY), off(DISPLAY) + 1, off(DISPLAY) + 2, off(DISPLAY) + 3], "marked app differs from reviewed S1C5 outside marker")

    identity_positions = []
    needle = b"SMK-37 Pro_015"
    pos = app.find(needle)
    while pos >= 0:
        identity_positions.append({"app_offset": hex(pos), "runtime": hex(BASE + pos), "value": needle.decode("ascii")})
        pos = app.find(needle, pos + 1)
    req(len(identity_positions) == 2, "USB identity occurrence count mismatch")

    evidence["app_marker_and_identity"] = {
        "app_sha256": app_sha,
        "fwsc_sha256": pkg_sha,
        "marker": {"app_offset": hex(off(DISPLAY)), "runtime": hex(DISPLAY), "old_unmarked_s1c5": marker_old.hex(), "new_marked": marker_new.hex(), "old_text": "1.10\\0", "new_text": "S1C5\\0", "status": "PASS"},
        "usb_identity_strings": identity_positions,
        "fwsc_identity_gate": "exact_ota check requires firmware.name == SMK-37 Pro and firmware.version == 15 before hash acceptance",
    }

    selector_marked = app[off(SEL_START):off(OWNED_END)]
    selector_unmarked = unmarked_app[off(SEL_START):off(OWNED_END)]
    req(selector_marked == selector_unmarked, "selector/producer bytes changed vs independently reviewed S1C5")
    req(sha_bytes(selector_marked) == EXPECTED["selector_producer_sha256"], "selector/producer hash mismatch")
    evidence["abi"] = {
        "compared_to_independently_reviewed_candidate": str(UNMARKED.relative_to(ROOT)),
        "unmarked_app_sha256": EXPECTED["unmarked_app_sha256"],
        "marked_vs_unmarked_changed_ranges": compact(diff_vs_unmarked),
        "selector_producer": {"start": hex(SEL_START), "end_exclusive": hex(OWNED_END), "sha256": sha_bytes(selector_marked), "byte_for_byte_same_as_unmarked_s1c5": True},
        "note_off": {"hook": app[off(NOFF_HOOK):off(NOFF_HOOK) + 6].hex(), "reload_address": hex(NOFF_RELOAD), "reload_bytes": app[off(NOFF_RELOAD):off(NOFF_RELOAD) + 6].hex(), "decode": "lb.z r5,[r0]; mov r0,r0; mov r0,r0"},
        "note_on": {"hook": app[off(NON_HOOK):off(NON_HOOK) + 6].hex(), "reload_address": hex(NON_RELOAD), "reload_bytes": app[off(NON_RELOAD):off(NON_RELOAD) + 6].hex(), "decode": "lb.z r6,[r0]; mov r0,r0; mov r0,r0", "velocity_store_address": hex(NON_VELOCITY_STORE), "velocity_store_bytes": app[off(NON_VELOCITY_STORE):off(NON_VELOCITY_STORE) + 2].hex()},
    }
    req(evidence["abi"]["note_off"]["hook"] == EXPECTED["note_off_hook"], "Note Off hook mismatch")
    req(evidence["abi"]["note_on"]["hook"] == EXPECTED["note_on_hook"], "Note On hook mismatch")
    req(evidence["abi"]["note_off"]["reload_bytes"] == EXPECTED["note_off_reload"], "Note Off reload mismatch")
    req(evidence["abi"]["note_on"]["reload_bytes"] == EXPECTED["note_on_reload"], "Note On reload mismatch")
    req(evidence["abi"]["note_on"]["velocity_store_bytes"] == EXPECTED["note_on_velocity_store"], "velocity store mismatch")

    pkgm = json.loads((CAND / "package-manifest.json").read_text())
    rb = json.loads((CAND / "rollback/official-v15-recovery-sectors/manifest.json").read_text())
    sha_ok = []
    for line in (CAND / "SHA256SUMS").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        p = CAND / rel
        sha_ok.append({"path": rel, "expected": digest, "actual": sha_file(p), "pass": p.exists() and sha_file(p) == digest})
    rollback_files = []
    for item in rb["changed_sectors"]:
        p = CAND / item["file"]
        rollback_files.append({"sector_base": item["sector_base"], "file": item["file"], "expected_sha256": item["sha256"], "actual_sha256": sha_file(p), "pass": p.exists() and sha_file(p) == item["sha256"]})
    evidence["package_and_rollback"] = {"package_manifest_output": pkgm["output"], "package_safety_gate": pkgm.get("safety_gate"), "sha_inventory_all_pass": all(x["pass"] for x in sha_ok), "rollback_manifest": {"rollback_restores_official_flash": rb.get("rollback_restores_official_flash"), "official_flash_sha256": rb.get("official_flash_sha256"), "candidate_flash_sha256": rb.get("candidate_flash_sha256"), "changed_sectors": [x["sector_base"] for x in rollback_files], "files_all_pass": all(x["pass"] for x in rollback_files)}}
    req(pkgm["output"]["sha256"] == EXPECTED["fwsc_sha256"], "package-manifest output hash mismatch")
    req(pkgm.get("safety_gate") == "PASS", "package safety gate not PASS")
    req(all(x["pass"] for x in sha_ok), "SHA256SUMS mismatch")
    req(rb.get("rollback_restores_official_flash") is True and all(x["pass"] for x in rollback_files), "rollback manifest/files failed")

    pkgcfg = subprocess.run(["pkg-config", "--cflags", "--libs", "libusb-1.0"], text=True, capture_output=True, check=True).stdout.split()
    scratch = pathlib.Path(os.environ.get("JCODE_SCRATCH_DIR", "/tmp")) / "s1c5-marked-review-ota"
    scratch.mkdir(parents=True, exist_ok=True)
    ota = scratch / "exact_ota"
    compile_cmd = ["cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "exact_ota.c", "../../../../../src/device_info.c", "../../../../../src/fwsc.c", "../../../../../src/protocol.c", "../../../../../src/sha256.c", "../../../../../src/usb_probe.c", "-o", ota, *pkgcfg]
    compile_res = run(compile_cmd, CAND)
    req(compile_res["pass"], "exact_ota compile failed")
    cases = [
        ("accept_marked", PKG, 0),
        ("reject_s1c4_parent", PARENT / "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc", 1),
        ("reject_official_v15", OFFICIAL, 1),
        ("reject_unmarked_s1c5", UNMARKED / "SMK37Pro-v15-S1C5-playback-register-return.fwsc", 1),
    ]
    ota_cases = []
    for name, path, expect in cases:
        res = run([ota, "check", path], CAND, expect=expect)
        res["name"] = name
        res["input_sha256"] = sha_file(path)
        ota_cases.append(res)
        req(res["pass"], f"exact_ota {name} failed")
    evidence["exact_ota"] = {"compile": compile_res, "cases": ota_cases, "upload_not_invoked": True}

    src_hash = sha_file(CAND / "exact_ota.c")
    text_hits: dict[str, list[str]] = {}
    stale_terms = [
        "0A6AC1AE",
        "INSTALL-SMK37PRO-V15-S1C5-PLAYBACK-REGISTER-RETURN",
        "not exact S1-C5 Playback Register Return package",
        "exact v15 S1-C5 Playback Register Return package",
        "SMK37Pro-v15-S1C5-playback-register-return.fwsc",
    ]
    for term in stale_terms:
        hits = []
        for p in CAND.rglob("*"):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
                try:
                    data = p.read_text(errors="ignore")
                except Exception:
                    continue
                if term in data:
                    hits.append(str(p.relative_to(CAND)))
        text_hits[term] = hits
    evidence["stale_token_scan"] = {"stale_terms": text_hits, "all_stale_terms_absent": all(not hits for hits in text_hits.values()), "exact_ota_c_sha256": src_hash, "ota_token": EXPECTED["ota_token"], "sender_token": EXPECTED["sender_token"]}
    req(evidence["stale_token_scan"]["all_stale_terms_absent"], "stale unmarked token/label found")

    rebuild_root = pathlib.Path(os.environ.get("JCODE_SCRATCH_DIR", "/tmp")) / f"s1c5-marked-review-det-{int(time.time())}"
    clone = copy_for_rebuild(rebuild_root)
    rebuild_cand = clone / CAND.relative_to(ROOT)
    rebuilds = []
    for i in (1, 2):
        r = run([sys.executable, "build_s1c5_playback_register_return.py"], rebuild_cand)
        req(r["pass"], f"rebuild {i} failed")
        rebuilds.append({"iteration": i, "app_sha256": sha_file(rebuild_cand / "app.bin"), "fwsc_sha256": sha_file(rebuild_cand / PKG.name), "evidence_sha256": sha_file(rebuild_cand / "evidence.json")})
    evidence["deterministic_rebuild"] = {"scratch_copy": str(clone), "iterations": rebuilds, "match": rebuilds[0] == {**rebuilds[1], "iteration": 1} if False else (rebuilds[0]["app_sha256"] == rebuilds[1]["app_sha256"] and rebuilds[0]["fwsc_sha256"] == rebuilds[1]["fwsc_sha256"] and rebuilds[0]["evidence_sha256"] == rebuilds[1]["evidence_sha256"])}
    req(evidence["deterministic_rebuild"]["match"], "deterministic rebuild mismatch")
    req(rebuilds[0]["app_sha256"] == EXPECTED["app_sha256"] and rebuilds[0]["fwsc_sha256"] == EXPECTED["fwsc_sha256"], "deterministic rebuild hashes do not match candidate")

    report = f"""# S1C5 marked playback-note review\n\nDecision: **PASS**.\n\nReviewed exact HEAD `{head}` and exact candidate `{CAND.relative_to(ROOT)}` offline only. No device, USB, MIDI, OTA upload, flash, reset, or live-send path was opened.\n\n## Concrete validation\n\n- **PASS** app marker: app offset `0x572a2`, runtime `0x020572a2`, changed from `1.10\\0` in the independently reviewed S1C5 app to `S1C5\\0`; marked app differs from that reviewed S1C5 app only at offsets `{diff_vs_unmarked}`.\n- **PASS** identity: app still contains two `SMK-37 Pro_015` USB identity strings at `{', '.join(x['runtime'] for x in identity_positions)}`; exact OTA check accepts only FWSC name `SMK-37 Pro`, version `15`, and package hash `{pkg_sha}`.\n- **PASS** selector/producer and ABI unchanged from the independently reviewed S1C5 candidate: window `0x0201e13e..0x0201e254` SHA-256 `{sha_bytes(selector_marked)}`; Note Off reload `{EXPECTED['note_off_reload']}` (`lb.z r5,[r0]`), Note On reload `{EXPECTED['note_on_reload']}` (`lb.z r6,[r0]`), velocity store `{EXPECTED['note_on_velocity_store']}` preserved.\n- **PASS** package and rollback gates: FWSC `{PKG.name}` SHA-256 `{pkg_sha}`, package safety gate `PASS`, SHA256SUMS inventory passed, rollback manifest restores official flash with sectors `{', '.join(evidence['package_and_rollback']['rollback_manifest']['changed_sectors'])}`.\n- **PASS** deterministic rebuild: two isolated scratch rebuilds reproduced app `{rebuilds[0]['app_sha256']}`, FWSC `{rebuilds[0]['fwsc_sha256']}`, and evidence `{rebuilds[0]['evidence_sha256']}`.\n- **PASS** exact OTA check matrix: marked candidate accepted with rc 0; S1C4 parent, official v15, and unmarked S1C5 were rejected with rc 1; upload mode was not invoked.\n- **PASS** stale-token scan: no old unmarked OTA token/hash label, unmarked `.fwsc` artifact reference, or old `Playback Register Return package` OTA accept/reject text remained. Top-level candidate contains only `{PKG.name}` as an FWSC artifact.\n\n## Scope\n\nAll checks were local file reads, Python validation, C compilation, and exact-hash `check` mode. This review makes no live-device claim.\n"""
    (OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (OUT / "report.md").write_text(report)
    (OUT / "validation.txt").write_text("S1C5 marked playback-note review PASS\n" + json.dumps({"head": head, "app_sha256": app_sha, "fwsc_sha256": pkg_sha, "ota_cases": [(x["name"], x["returncode"]) for x in ota_cases]}, indent=2) + "\n")
    lines = []
    for name in ["review.py", "evidence.json", "report.md", "validation.txt"]:
        p = OUT / name
        lines.append(f"{sha_file(p)}  {name}")
    (OUT / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    print("PASS", OUT.relative_to(ROOT), app_sha, pkg_sha)

if __name__ == "__main__":
    main()
