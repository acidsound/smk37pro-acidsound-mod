#!/usr/bin/env python3
"""Offline validator for S1-C6 Reset Signature Isolation (S16).

No device, USB, MIDI, OTA upload, flash, reset, or live send is opened.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import build_s1c6_reset_signature_isolation as b

HERE = Path(__file__).resolve().parent
PKG = b.PACKAGE_NAME


def shaf(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def req(ok: bool, msg: str) -> None:
    if not ok:
        raise SystemExit("FAIL: " + msg)


def run(args: list[str | Path], expect: int = 0) -> subprocess.CompletedProcess[str]:
    r = subprocess.run([str(x) for x in args], cwd=HERE, text=True, capture_output=True, check=False)
    if r.returncode != expect:
        raise SystemExit(
            "FAIL: command returned %d expected %d: %s\nstdout:\n%s\nstderr:\n%s"
            % (r.returncode, expect, " ".join(map(str, args)), r.stdout, r.stderr)
        )
    return r


def main() -> None:
    ev = b.build(check=True)
    appm = json.loads((HERE / "app-manifest.json").read_text())
    pkgm = json.loads((HERE / "package-manifest.json").read_text())
    code = json.loads((b.CODEDIR / "evidence.json").read_text())
    app = (HERE / "app.bin").read_bytes()
    parent = (b.PARENT / "app.bin").read_bytes()

    req(ev["decision"] == "PASS" and ev["candidate_built"] is True, "release evidence PASS")
    req(ev["scope"]["offline_only"] is True, "offline scope")
    for key in ["device_accessed", "midi_transport_opened", "flash_performed", "ota_performed", "reset_performed", "live_send_performed"]:
        req(ev["scope"][key] is False, "scope false " + key)
    req(shaf(HERE / "app.bin") == ev["app"]["output_app_sha256"], "app hash matches evidence")
    req(shaf(HERE / PKG) == ev["package"]["package_sha256"], "package hash matches evidence")
    req(pkgm["output"]["sha256"] == ev["package"]["package_sha256"], "package manifest output hash")
    req(ev["basis"]["official_fwsc_sha256"] == b.EXPECTED["official_fwsc"], "official FWSC hash pinned")
    req(ev["basis"]["official_app_sha256"] == b.EXPECTED["official_app"], "official app hash pinned")
    req(ev["basis"]["parent_s1c5_marked_app_sha256"] == b.EXPECTED["parent_app"], "S1-C5 marked app hash pinned")
    req(ev["basis"]["parent_s1c5_marked_package_sha256"] == b.EXPECTED["parent_fwsc"], "S1-C5 marked package hash pinned")

    req(ev["collision_scan"]["status"] == "PASS" and ev["collision_scan"]["collisions"] == 0, "bundled voice collision scan PASS")

    req(hashlib.sha256(app[b.off(b.SEL_START):b.off(b.RESET_ENTRY)]).hexdigest() == b.EXPECTED["core_combined"], "selector+producer core preserved byte-for-byte")
    req(hashlib.sha256(parent[b.off(b.SEL_START):b.off(b.RESET_ENTRY)]).hexdigest() == b.EXPECTED["core_combined"], "parent core hash matches expected")
    req(app[b.off(b.DIRECT_CALL):b.off(b.DIRECT_CALL) + 4].hex() == b.EXPECTED["direct_call"], "direct product callsite preserved")
    req(app[b.off(b.SEG_CALL):b.off(b.SEG_CALL) + 4].hex() == b.EXPECTED["seg_call"], "segmented product callsite preserved")
    req(b.short_target(b.DIRECT_CALL, app[b.off(b.DIRECT_CALL):b.off(b.DIRECT_CALL) + 4]) == b.RESET_ENTRY, "direct product target exact")
    req(b.short_target(b.SEG_CALL, app[b.off(b.SEG_CALL):b.off(b.SEG_CALL) + 4]) == b.RESET_ENTRY, "segmented product target exact")
    req(bytes(app[b.off(b.DISPLAY_VERSION_ADDRESS):b.off(b.DISPLAY_VERSION_ADDRESS) + len(b.S16_DISPLAY)]) == b.S16_DISPLAY, "S16 display marker exact")

    diff_offsets = set(b.difference_offsets(parent, app))
    expected_window_offsets = set(range(b.off(b.RESET_ENTRY), b.off(b.OWNED_END))) | set(range(b.off(b.DISPLAY_VERSION_ADDRESS), b.off(b.DISPLAY_VERSION_ADDRESS) + len(b.S16_DISPLAY)))
    req(diff_offsets.issubset(expected_window_offsets), "no app diffs outside reset wrapper tail and display marker")

    code_ev = json.loads((b.CODEDIR / "evidence.json").read_text())
    req(code_ev["decision"] == "PASS", "code evidence PASS")
    req(code_ev["preserved_code"]["combined_sha256"] == b.EXPECTED["core_combined"], "code evidence preserves core hash")
    req(code_ev["reset_contract"]["signature"]["wire_bytes_6_7"] == list(b.RESET_SIG), "code evidence reset signature")
    req(code_ev["reset_contract"]["on_match"].startswith("clear lock/count/state"), "code evidence reset returns without producer")
    req(code_ev["reset_contract"]["on_mismatch"].startswith("r0 = stage preserved"), "code evidence voice path calls producer")
    req(code_ev["callsites"]["direct"]["status"] == "unchanged" and code_ev["callsites"]["segmented"]["status"] == "unchanged", "code evidence callsites unchanged")

    rb = json.loads((HERE / "rollback/official-v15-recovery-sectors/manifest.json").read_text())
    req(rb["rollback_restores_official_flash"] is True, "rollback manifest PASS")
    for item in rb["changed_sectors"]:
        p = HERE / item["file"]
        req(p.exists() and shaf(p) == item["sha256"], "rollback sector " + item["sector_base"])

    dry = json.loads(run([sys.executable, "dry_run_validate.py", "--json"]).stdout)
    req(dry["status"] == "DRY_RUN_PASS" and dry["device_accessed"] is False and dry["midi_transport_opened"] is False, "dry run PASS")
    man = json.loads((HERE / "inputs/packets/packet-manifest.json").read_text())
    req(man["wire_playback_note_offset"] == 161 and man["payload_playback_note_offset"] == 0x9B, "transport offsets")
    req(man["packet_count"] == 17 and man["reset_packet_count"] == 1 and man["voice_packet_count"] == 16, "17-packet transport")
    req(man["packets"][0]["kind"] == "reset", "reset packet first")
    req(man["reset_signature"]["wire_bytes_6_7"] == list(b.RESET_SIG) and man["reset_signature"]["not_loaded_as_voice"] is True, "reset signature manifest")
    req("direct_163_byte_sysex" in man["supported_ingress_modes"] and "segmented_final_sysex_after_final_f7_total_0x9e" in man["supported_ingress_modes"], "direct and segmented-final ingress modes")
    for i, item in enumerate(man["packets"]):
        pkt = (HERE / "inputs/packets" / item["file"]).read_bytes()
        req(len(pkt) == 163 and pkt.startswith(b.HEADER) and pkt.endswith(b.TERM), f"packet {i} framing")
        if item["kind"] == "reset":
            req(pkt[6] == b.RESET_SIG[0] and pkt[7] == b.RESET_SIG[1] and pkt[161] == b.RESET_PACKET_BYTE_161, f"packet {i} reset signature")
        else:
            req(pkt[161] == item["playback_note"] == 60, f"packet {i} all-C4 playback byte")
            req(item["trigger_note"] == 36 + item["slot"], f"packet {i} trigger note source")

    with tempfile.TemporaryDirectory(prefix="s1c6-reset-validate-") as tmp_s:
        tmp = Path(tmp_s)
        sender = tmp / "exact_17_packet_sender"
        run(["cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "exact_17_packet_sender.c", "../../../../../src/sha256.c", "-o", sender])
        run([sender, "dry-run", "inputs/packets"])
        blocked = run([sender, "send", "inputs/packets", "--confirm", ev["sender"]["confirmation_token"]], expect=2)
        req("send BLOCK" in blocked.stderr, "sender live path blocked by default")

        pkg = subprocess.run(["pkg-config", "--cflags", "--libs", "libusb-1.0"], text=True, capture_output=True, check=False)
        req(pkg.returncode == 0, "pkg-config libusb-1.0 available")
        ota = tmp / "exact_ota"
        run(["cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "exact_ota.c", "../../../../../src/device_info.c", "../../../../../src/fwsc.c", "../../../../../src/protocol.c", "../../../../../src/sha256.c", "../../../../../src/usb_probe.c", "-o", ota, *pkg.stdout.split()])
        run([ota, "check", PKG])
        reject = run([ota, "check", str(b.PARENT / b.PARENT_PACKAGE)], expect=1)
        req("offline check rejected" in reject.stderr, "exact OTA rejects S1-C5 marked parent")

    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        req((HERE / rel).exists(), "SHA path exists " + rel)
        req(shaf(HERE / rel) == digest, "SHA inventory " + rel)

    print(
        "S1-C6 Reset Signature Isolation validation PASS: app_sha256=%s; package_sha256=%s; ota_confirmation_token=%s; sender_confirmation_token=%s; offline only"
        % (ev["app"]["output_app_sha256"], ev["package"]["package_sha256"], ev["flash"]["confirmation_token"], ev["sender"]["confirmation_token"])
    )


if __name__ == "__main__":
    main()
