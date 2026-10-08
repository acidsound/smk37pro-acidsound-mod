#!/usr/bin/env python3
"""Offline evidence pack for the v15 R03 first-pad reboot after Mooger staging.

No device access, patching, flashing, or v12-derived input. Reads only checked-out
v15 official/R02/R03 artifacts plus local pinned-SDK evidence already committed in
this repo.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[6]
OUT = Path(__file__).resolve().parent
APP_BASE = 0x02000000

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def hx(n: int, width: int = 8) -> str:
    return f"0x{n:0{width}x}"

def read(path: Path) -> bytes:
    return path.read_bytes()

def off(va: int) -> int:
    return va - APP_BASE

def raw_hits(data: bytes, value: int) -> list[str]:
    needle = value.to_bytes(4, "little")
    hits = []
    cursor = 0
    while True:
        cursor = data.find(needle, cursor)
        if cursor < 0:
            return [hx(x) for x in hits]
        hits.append(cursor)
        cursor += 1

def mov_payload_hits(data: bytes, start: int, end: int) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for i in range(0, len(data) - 5):
        value = int.from_bytes(data[i + 2:i + 6], "little")
        if start <= value < end:
            hits.append({"va": hx(APP_BASE + i), "file_offset": hx(i), "value": hx(value), "bytes": data[i:i + 6].hex()})
    return hits

def bytes_at(data: bytes, va: int, size: int) -> str:
    return data[off(va):off(va) + size].hex()

def branch16_target(at: int, branch_hex: str) -> str:
    raw = bytes.fromhex(branch_hex)
    disp_hw = int.from_bytes(raw[2:4], "little", signed=True)
    return hx(at + 4 + disp_hw * 2)

def load_trace(path: Path) -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        rows[int(parts[0], 16)] = {
            "address": hx(int(parts[0], 16)),
            "bytes": parts[1],
            "size": parts[2],
            "mnemonic": parts[3],
            "display": parts[4],
            "flow": parts[5] if len(parts) > 5 else "",
            "function": parts[6] if len(parts) > 6 else "",
        }
    return rows

OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
R02_APP = ROOT / "build/v15-R02-sysex-staging-app.bin"
R03_APP = ROOT / "build/v15-R03-fixed-prefix-app.bin"
R02_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R02/app-manifest.json"
R03_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R03/app-manifest.json"
R03_TRACE = ROOT / "baselines/v15/analysis/flash-candidates/R03/decoder-trace.tsv"
HEAP_EVIDENCE = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-prefix-reservation/evidence.json"
HEAP_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-prefix-reservation/report.md"
HEAP_BOUNDARY_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-boundary/report.md"
RAM_OWNERSHIP_REPORT = ROOT / "baselines/v15/analysis/r03-owned-ram/ram-ownership/report.md"
ATOMIC_CONTRACT = ROOT / "baselines/v15/analysis/r03-owned-ram/atomic-publish/pinned-sdk-spinlock-contract.txt"
ATOMIC_SOURCE = ROOT / "baselines/v15/analysis/r03-owned-ram/atomic-publish/r03-trylock.c"
ATOMIC_OBJDUMP = ROOT / "baselines/v15/analysis/r03-owned-ram/atomic-publish/official-objdump.txt"
SDK_SYMLINK = ROOT.parents[1] / "Desktop/PatcherSDK"

official = read(OFFICIAL_APP)
r02 = read(R02_APP)
r03 = read(R03_APP)
r02_manifest = json.loads(R02_MANIFEST.read_text(encoding="utf-8"))
r03_manifest = json.loads(R03_MANIFEST.read_text(encoding="utf-8"))
heap_ev = json.loads(HEAP_EVIDENCE.read_text(encoding="utf-8"))
r03_trace = load_trace(R03_TRACE)

checks = []
def check(name: str, ok: bool, detail: object) -> None:
    checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})
    if not ok:
        raise SystemExit(f"{name} failed: {detail}")

check("official-app-sha256", sha(OFFICIAL_APP) == "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055", sha(OFFICIAL_APP))
check("r02-app-sha256", sha(R02_APP) == "eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948", sha(R02_APP))
check("r03-app-sha256", sha(R03_APP) == "3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788", sha(R03_APP))
check("r03-owned-range-manifest", r03_manifest["owned_ram"]["range"] == "0x01c46520..0x01c465c0", r03_manifest["owned_ram"])
check("heap-sbrk-match", heap_ev["sbrk_match"]["v15_address"] == "0x0205e9da" and heap_ev["sbrk_match"]["fixed_bytes_exact"] == 80, heap_ev["sbrk_match"])
check("heap-symbols", heap_ev["sbrk_match"]["recovered_symbols"] == {"HEAP_BEGIN": "0x01c46520", "HEAP_END": "0x01c7fd30", "sbrk.__init_addr": "0x01c32d94"}, heap_ev["sbrk_match"]["recovered_symbols"])

# Exact R03 heap/BSS patches.
check("r03-bss-size-patch-bytes", bytes_at(r03, 0x0200001E, 6) == "c2ffeccb0300", bytes_at(r03, 0x0200001E, 6))
check("r03-heap-begin-patch-bytes", bytes_at(r03, 0x0205E9F8, 6) == "c5ffc065c401", bytes_at(r03, 0x0205E9F8, 6))

# The exact invalid-fallback bug in R03 consumers.
for va in (0x0201E150, 0x0201E180):
    row = r03_trace[va]
    check(f"r03-valid-branch-{hx(va)}", row["bytes"] == "80f80902" and "jne r0,#0x1" in row["display"], row)
for va in (0x0201E166, 0x0201E196):
    row = r03_trace[va]
    check(f"r03-invalid-fallback-calls-memcpy-{hx(va)}", row["display"] == "call 0x02048cce", row)
# At invalid fallback, r0 was loaded from valid and destination is only in r5, never restored.
check("r03-invalid-fallback-destination-not-restored-off", r03_trace[0x0201E154]["display"] == "mov r0,r5" and 0x0201E154 > 0x0201E150, [r03_trace[x] for x in (0x0201E146,0x0201E14E,0x0201E150,0x0201E154,0x0201E166)])
check("r03-invalid-fallback-destination-not-restored-on", r03_trace[0x0201E184]["display"] == "mov r0,r5" and 0x0201E184 > 0x0201E180, [r03_trace[x] for x in (0x0201E176,0x0201E17E,0x0201E180,0x0201E184,0x0201E196)])

# Producer branch gap and polarity uncertainty.
try_fail = bytes_at(r03, 0x0201E1AC, 4)
check("r03-try-fail-gap-bytes", try_fail == "40e81b00", {"bytes": try_fail, "target": branch16_target(0x0201E1AC, try_fail)})

# R02 live-success wrapper has no valid-byte branch and does not touch HEAP/BSS.
check("r02-no-bss-patch", bytes_at(r02, 0x0200001E, 6) == "c2ff48cb0300", bytes_at(r02, 0x0200001E, 6))
check("r02-no-heap-begin-patch", bytes_at(r02, 0x0205E9F8, 6) == "c5ff2065c401", bytes_at(r02, 0x0205E9F8, 6))
check("r02-staging-source", r02_manifest["design"]["runtime_source"] == "0x01c37fd0", r02_manifest["design"])

# Official/R03 literal scans relevant to whether only sbrk immediate was patched.
scan = {
    "official_control_literals_raw_4le": {
        "BSS_SIZE_0x3cb48": raw_hits(official, 0x0003CB48),
        "HEAP_BEGIN_0x01c46520": raw_hits(official, 0x01C46520),
        "HEAP_END_0x01c7fd30": raw_hits(official, 0x01C7FD30),
    },
    "r03_control_literals_raw_4le": {
        "BSS_SIZE_0x3cbec": raw_hits(r03, 0x0003CBEC),
        "HEAP_BEGIN_NEW_0x01c465c0": raw_hits(r03, 0x01C465C0),
        "HEAP_BEGIN_OLD_0x01c46520": raw_hits(r03, 0x01C46520),
        "VALID_0x01c465bc": raw_hits(r03, 0x01C465BC),
        "LOCK_0x01c465bd": raw_hits(r03, 0x01C465BD),
        "HEAP_END_0x01c7fd30": raw_hits(r03, 0x01C7FD30),
    },
    "official_mov_payload_hits_owned_0x01c46520_0x01c465c0": mov_payload_hits(official, 0x01C46520, 0x01C465C0),
    "official_mov_payload_hits_owned_plus_prior_c0_0x01c46520_0x01c465e0": mov_payload_hits(official, 0x01C46520, 0x01C465E0),
    "r03_mov_payload_hits_owned_and_heap_0x01c46520_0x01c465e0": mov_payload_hits(r03, 0x01C46520, 0x01C465E0),
}
check("official-single-heap-begin-literal", scan["official_control_literals_raw_4le"]["HEAP_BEGIN_0x01c46520"] == ["0x0005e9fa"], scan["official_control_literals_raw_4le"])
check("official-single-heap-end-literal", scan["official_control_literals_raw_4le"]["HEAP_END_0x01c7fd30"] == ["0x0005ea02"], scan["official_control_literals_raw_4le"])
check("official-single-bss-size-literal", scan["official_control_literals_raw_4le"]["BSS_SIZE_0x3cb48"] == ["0x00000020"], scan["official_control_literals_raw_4le"])

sdk_status = {
    "desktop_symlink": str(SDK_SYMLINK),
    "exists": SDK_SYMLINK.exists(),
    "is_symlink": SDK_SYMLINK.is_symlink(),
    "target": os.readlink(SDK_SYMLINK) if SDK_SYMLINK.is_symlink() else None,
    "repo_pinned_contract_sha256": sha(ATOMIC_CONTRACT),
    "repo_trylock_source_sha256": sha(ATOMIC_SOURCE),
    "repo_trylock_objdump_sha256": sha(ATOMIC_OBJDUMP),
    "heap_mem_heap_source_sha256_from_prior_evidence": heap_ev["inputs"]["sdk_mem_heap_source_sha256"],
    "sdk_commit_from_prior_evidence": heap_ev["inputs"]["sdk_commit"],
}

ranking = [
    {
        "rank": 1,
        "cause": "R03 invalid Ch10 fallback calls stock memcpy with r0 clobbered by the valid-byte load if valid != 1",
        "status": "strongly supported exact-code bug; requires producer-not-published precondition",
        "falsifier": "Prove valid byte was 1 immediately before first Pad Ch10, or prove this branch could not be reached in the live sequence.",
    },
    {
        "rank": 2,
        "cause": "Producer did not publish valid before first pad, due to handler gate rejection or testset/ifeq polarity misunderstanding",
        "status": "plausible trigger for rank-1 bug; static artifacts prove branch bytes but not live acceptance or testset condition flags",
        "falsifier": "Independent PI32 ISA/testset flag proof and a non-live trace showing R03 producer sets 0x01c465bc=1 for the exact packet.",
    },
    {
        "rank": 3,
        "cause": "Exact R03 heap-prefix ownership is not fully proven by prior 0xc0 audit because live R03 reserves 0xa0 and changes allocator capacity",
        "status": "possible safety gap, but less consistent with first-pad-only failure than ranks 1-2",
        "falsifier": "Complete allocator/sbrk caller proof plus heap high-water margin showing 0xa0 shrink is harmless under boot, SysEx, and first pad.",
    },
    {
        "rank": 4,
        "cause": "Patching only sbrk HEAP_BEGIN is insufficient because another allocator bound/cache exists elsewhere",
        "status": "weighed down by official-v15 literal scan and exact SDK sbrk match, not fully impossible for computed/indirect state",
        "falsifier": "Full allocator initialization graph proving all allocation paths derive lower bound solely from the matched sbrk relocation.",
    },
    {
        "rank": 5,
        "cause": "Cache/MMU/MPU/DMA incoherence on the owned-RAM buffer",
        "status": "not supported by current local evidence for this CPU-to-CPU memcpy path; no checked pinned SDK constraint found in repo evidence",
        "falsifier": "Pinned SDK/manual evidence requiring cache maintenance or MPU mapping changes for normal RAM writes consumed by the synth path.",
    },
]

evidence = {
    "format": "smk37-v15-r03-live-failure-heap-evidence-v1",
    "scope": "offline only; exact official v15, exact R02, exact R03 3ff9c4; no device access, patch, flash, or v12 assumptions",
    "inputs": {
        "official_app": str(OFFICIAL_APP.relative_to(ROOT)),
        "official_app_sha256": sha(OFFICIAL_APP),
        "r02_app": str(R02_APP.relative_to(ROOT)),
        "r02_app_sha256": sha(R02_APP),
        "r03_app": str(R03_APP.relative_to(ROOT)),
        "r03_app_sha256": sha(R03_APP),
        "r02_manifest": str(R02_MANIFEST.relative_to(ROOT)),
        "r03_manifest": str(R03_MANIFEST.relative_to(ROOT)),
        "r03_trace": str(R03_TRACE.relative_to(ROOT)),
    },
    "live_failure": {
        "r03_app_sha256": "3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788",
        "mooger_packet_sha256": "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
        "observed": "first physical Pad Ch10 input after staging rebooted; official v15 restored",
    },
    "heap_and_bss": {
        "official_bss": {"start": "0x01c099d4", "end_exclusive": "0x01c4651c", "size": "0x0003cb48"},
        "official_heap": heap_ev["sbrk_match"]["recovered_symbols"],
        "r03_patch": r03_manifest["owned_ram"],
        "prior_heap_prefix_option_b_was_not_exact_r03": heap_ev["option_b_fixed_prefix"],
        "prior_reports": {
            "heap_prefix": str(HEAP_REPORT.relative_to(ROOT)),
            "heap_boundary_block": str(HEAP_BOUNDARY_REPORT.relative_to(ROOT)),
            "ram_ownership_block": str(RAM_OWNERSHIP_REPORT.relative_to(ROOT)),
        },
    },
    "literal_and_mov_scans": scan,
    "r02_vs_r03": {
        "r02": {"runtime_source": r02_manifest["design"]["runtime_source"], "heap_patches": "none", "live_result": "PASS as controlled checkpoint"},
        "r03": {"runtime_source": r03_manifest["protocol"]["source"], "owned_ram": r03_manifest["owned_ram"], "live_result": "FAIL first Pad Ch10 reboot"},
    },
    "r03_invalid_fallback_bug": {
        "off_path_rows": [r03_trace[x] for x in (0x0201E146, 0x0201E148, 0x0201E14E, 0x0201E150, 0x0201E154, 0x0201E166)],
        "on_path_rows": [r03_trace[x] for x in (0x0201E176, 0x0201E178, 0x0201E17E, 0x0201E180, 0x0201E184, 0x0201E196)],
        "mechanism": "For Ch10 invalid fallback, r0 is overwritten by lb.z valid before the branch to stock memcpy. The only mov r0,r5 restore is after the jne, so branch-taken fallback does not restore destination.",
    },
    "producer_uncertainties": {
        "try_fail_branch": {"address": "0x0201e1ac", "bytes": try_fail, "target": branch16_target(0x0201E1AC, try_fail)},
        "official_trylock_source_lines": str(ATOMIC_SOURCE.relative_to(ROOT)),
        "official_trylock_objdump": str(ATOMIC_OBJDUMP.relative_to(ROOT)),
        "uncertainty": "objdump proves syntax and bytes, but the live state of handler acceptance and testset condition flags was not observed offline.",
    },
    "pinned_sdk_status": sdk_status,
    "root_cause_ranking": ranking,
    "validation": checks,
}
(OUT / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(OUT / "validation.txt").write_text("\n".join(f"{c['status']}\t{c['check']}\t{c['detail']}" for c in checks) + "\n", encoding="utf-8")
print("wrote", OUT / "evidence.json")
print("checks", len(checks), "PASS")
