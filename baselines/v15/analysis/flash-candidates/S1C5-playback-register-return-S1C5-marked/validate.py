#!/usr/bin/env python3
"""Offline validator for S1-C5 Playback Register Return.

No device, USB, MIDI, OTA upload, flash, reset, or live send is opened.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import build_s1c5_playback_register_return as b

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
    req(ev["basis"]["parent_s1c4_v3_app_sha256"] == b.EXPECTED["parent_app"], "S1-C4 v3 app hash pinned")
    req(ev["basis"]["parent_s1c4_v3_package_sha256"] == b.EXPECTED["parent_fwsc"], "S1-C4 v3 package hash pinned")

    req(app[b.off(b.NOFF_HOOK):b.off(b.NOFF_HOOK)+6].hex() == b.EXPECTED["noff_hook"], "Note Off hook unchanged")
    req(app[b.off(b.NON_HOOK):b.off(b.NON_HOOK)+6].hex() == b.EXPECTED["non_hook"], "Note On hook unchanged")
    req(app[b.off(b.NOFF_RELOAD):b.off(b.NOFF_RELOAD)+6].hex() == b.EXPECTED["noff_register_reload"], "Note Off reload window exact")
    req(app[b.off(b.NON_RELOAD):b.off(b.NON_RELOAD)+6].hex() == b.EXPECTED["non_register_reload"], "Note On reload window exact")
    req(bytes(app[b.off(b.DISPLAY_VERSION_ADDRESS):b.off(b.DISPLAY_VERSION_ADDRESS) + len(b.CUSTOM_DISPLAY_VERSION)]) == b.CUSTOM_DISPLAY_VERSION, "S1C5 display marker exact")
    req(parent[b.off(b.NOFF_RELOAD):b.off(b.NOFF_RELOAD)+6].hex() == b.EXPECTED["noff_parent_neutral"], "parent Note Off neutral window exact")
    req(parent[b.off(b.NON_RELOAD):b.off(b.NON_RELOAD)+6].hex() == b.EXPECTED["non_parent_neutral"], "parent Note On neutral window exact")
    req(app[b.off(b.NON_VELOCITY_STORE):b.off(b.NON_VELOCITY_STORE)+2].hex() == b.EXPECTED["velocity_store"], "Note On velocity store preserved")
    req(app[b.off(b.DIRECT_RELOAD):b.off(b.DIRECT_RELOAD)+4].hex() == b.EXPECTED["direct_reload"], "direct reload preserved")
    req(app[b.off(b.SEG_RELOAD):b.off(b.SEG_RELOAD)+4].hex() == b.EXPECTED["seg_reload"], "segmented reload preserved")
    req(app[b.off(b.DIRECT_CALL):b.off(b.DIRECT_CALL)+4].hex() == b.EXPECTED["direct_call"], "direct product callsite preserved")
    req(app[b.off(b.SEG_CALL):b.off(b.SEG_CALL)+4].hex() == b.EXPECTED["seg_call"], "segmented product callsite preserved")
    req(b.short_target(b.DIRECT_CALL, app[b.off(b.DIRECT_CALL):b.off(b.DIRECT_CALL)+4]) == 0x0201E228, "direct product target exact")
    req(b.short_target(b.SEG_CALL, app[b.off(b.SEG_CALL):b.off(b.SEG_CALL)+4]) == 0x0201E228, "segmented product target exact")

    diff_offsets = set(b.difference_offsets(parent, app))
    expected_window_offsets = set(range(b.off(b.NOFF_RELOAD), b.off(b.NOFF_RELOAD) + 6)) | set(range(b.off(b.NON_RELOAD), b.off(b.NON_RELOAD) + 6)) | set(range(b.off(b.DISPLAY_VERSION_ADDRESS), b.off(b.DISPLAY_VERSION_ADDRESS) + len(b.CUSTOM_DISPLAY_VERSION)))
    req(diff_offsets.issubset(expected_window_offsets), "no app diffs outside two post-hook windows vs S1-C4 v3")
    req(hashlib.sha256(app[b.off(b.SEL_START):b.off(b.OWNED_END)]).hexdigest() == b.EXPECTED["parent_combined"], "producer/selector bytes preserved")
    req(code["preserved_code"]["combined_sha256"] == b.EXPECTED["parent_combined"], "code evidence preserves combined hash")

    decoded = {(row["window"], row["address"]): row["asm"] for row in code["changed_instructions"]}
    req(decoded[("note_off", b.hx(b.NOFF_RELOAD))] == "lb.z r5,[r0]", "independent decode Note Off reload")
    req(decoded[("note_on", b.hx(b.NON_RELOAD))] == "lb.z r6,[r0]", "independent decode Note On reload")
    req(code["abi_contract"]["selector_r0_return"].startswith("S1-C4 v3 selector stores"), "selector r0 ABI evidence")
    req(code["abi_contract"]["trigger_source"].startswith("producer and selector source bytes unchanged"), "trigger source invariant")
    req(ev["invariants"]["velocity_preserved"] is True and ev["invariants"]["no_source_slot_from_playback_note"] is True, "invariants preserved")

    rb = json.loads((HERE / "rollback/official-v15-recovery-sectors/manifest.json").read_text())
    req(rb["rollback_restores_official_flash"] is True, "rollback manifest PASS")
    for item in rb["changed_sectors"]:
        p = HERE / item["file"]
        req(p.exists() and shaf(p) == item["sha256"], "rollback sector " + item["sector_base"])

    dry = json.loads(run([sys.executable, "dry_run_validate.py", "--json"]).stdout)
    req(dry["status"] == "DRY_RUN_PASS" and dry["device_accessed"] is False and dry["midi_transport_opened"] is False, "dry run PASS")
    man = json.loads((HERE / "inputs/packets/packet-manifest.json").read_text())
    req(man["wire_playback_note_offset"] == 161 and man["payload_playback_note_offset"] == 0x9B, "transport offsets")
    req(man["duplicate_playback_note_test"]["value"] == 60 and man["duplicate_playback_note_test"]["slots"] == 16, "all C4 duplicate packet manifest")
    req("direct_163_byte_sysex" in man["supported_ingress_modes"] and "segmented_final_sysex_after_final_f7_total_0x9e" in man["supported_ingress_modes"], "direct and segmented-final ingress modes")
    for i, item in enumerate(man["packets"]):
        pkt = (HERE / "inputs/packets" / item["file"]).read_bytes()
        req(len(pkt) == 163 and pkt.startswith(b.HEADER) and pkt.endswith(b.TERM), f"packet {i} framing")
        req(pkt[161] == item["playback_note"] == 60, f"packet {i} all-C4 playback byte")
        req(item["trigger_note"] == 36 + i, f"packet {i} trigger note source")
        req(item["only_changed_wire_offsets_vs_template"] in ([161], []), f"packet {i} template diff offset")

    with tempfile.TemporaryDirectory(prefix="s1c5-playback-validate-") as tmp_s:
        tmp = Path(tmp_s)
        sender = tmp / "exact_16_packet_sender"
        run(["cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "exact_16_packet_sender.c", "../../../../../src/sha256.c", "-o", sender])
        run([sender, "dry-run", "inputs/packets"])
        blocked = run([sender, "send", "inputs/packets", "--confirm", ev["sender"]["confirmation_token"]], expect=2)
        req("send BLOCK" in blocked.stderr, "sender live path blocked by default")

        pkg = subprocess.run(["pkg-config", "--cflags", "--libs", "libusb-1.0"], text=True, capture_output=True, check=False)
        req(pkg.returncode == 0, "pkg-config libusb-1.0 available")
        ota = tmp / "exact_ota"
        run(["cc", "-O2", "-g", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "exact_ota.c", "../../../../../src/device_info.c", "../../../../../src/fwsc.c", "../../../../../src/protocol.c", "../../../../../src/sha256.c", "../../../../../src/usb_probe.c", "-o", ota, *pkg.stdout.split()])
        run([ota, "check", PKG])
        reject = run([ota, "check", str(b.PARENT / "SMK37Pro-v15-S1C4-playback-note-v3-segmented-final.fwsc")], expect=1)
        req("offline check rejected" in reject.stderr, "exact OTA rejects S1-C4 v3 parent")

    for line in (HERE / "SHA256SUMS").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(maxsplit=1)
        rel = rel[1:] if rel.startswith("*") else rel
        req((HERE / rel).exists(), "SHA path exists " + rel)
        req(shaf(HERE / rel) == digest, "SHA inventory " + rel)

    print(
        "S1-C5 Marked Playback Note validation PASS: app_sha256=%s; package_sha256=%s; ota_confirmation_token=%s; sender_confirmation_token=%s; offline only"
        % (ev["app"]["output_app_sha256"], ev["package"]["package_sha256"], ev["flash"]["confirmation_token"], ev["sender"]["confirmation_token"])
    )


if __name__ == "__main__":
    main()
