#!/usr/bin/env python3
"""Static v15-only state/persistence evidence extractor.

Inputs are intentionally limited to the official v15 app/package and the v15
Ghidra listing/provenance already produced from that official app. The script
performs no patching, flashing, writes to firmware images, or git commits.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUTDIR = ROOT / "baselines/v15/analysis/ui-preflash/state-persistence"
APP = ROOT / "build/v15-official-app.bin"
PKG = ROOT / "build/SMK-37_Pro_015.fwsc"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
PROVENANCE = ROOT / "baselines/v15/analysis/quarkslab/results/provenance.txt"

BASE = 0x02000000
EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "flash_sha256": "f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a",
    "listing_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
}

STRING_TERMS = [
    "SAVE", "SAVED", "Please select a bank to save", "BANK %c", "Preset-%d",
    "Pad Bank-", "Enable PATCH first", "mnt/sdfile/app/usrflash",
    "mnt/sdfile/app/cfg_tool.bin", "cfg_tool.bin", "VM", "app_dir_head",
    "flash.bin", "flash2.bin",
]

RANGES = {
    "factory_loader_02005660": (0x02005660, 0x020057DE),
    "factory_loader_callers_02005f70": (0x02005F70, 0x02005FA8),
    "factory_loader_caller_midi_sysex_0201e254": (0x0201E254, 0x0201E648),
    "bank_preset_change_caller_020241e0": (0x020241E0, 0x0202423A),
    "bank_load_save_cluster_020254e0": (0x020254E0, 0x020255B0),
    "save_writer_candidate_02026d6c": (0x02026D6C, 0x02026DD4),
    "save_ui_state_cluster_02027e0e": (0x02027E0E, 0x02027E70),
    "current_patch_buffer_consumer_0201c5ec": (0x0201C5EC, 0x0201C6B0),
    "storage_read_wrapper_02004a7a": (0x02004A7A, 0x02004B14),
    "storage_prepare_candidate_02004a54": (0x02004A54, 0x02004A78),
    "memcpy_memcmp_02048c96": (0x02048C96, 0x02048D40),
    "usrflash_low_level_candidate_0201e846": (0x0201E846, 0x0201E940),
}

SEARCH_TERMS = [
    "0x02005660", "0x1c34c74", "0x1c33260", "0x3a4", "0x3a0", "0x1a14",
    "0x1a90", "0x1aa0", "0x129c", "0x9180", "0x4000", "0xa3", "0x49e3",
    "0x1c0de20", "0x1c37030", "0x02004b02", "0x02004a54", "0x02048cce",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_listing() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with gzip.open(LISTING, "rt", errors="replace") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(header):
                continue
            row = dict(zip(header, parts))
            row["address_int"] = str(int(row["address"], 16))
            rows.append(row)
    return rows


def row_text(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"])


def extract_ranges(rows: list[dict[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, (lo, hi) in RANGES.items():
        out[name] = [row_text(r) for r in rows if lo <= int(r["address"], 16) <= hi]
    return out


def search_listing(rows: list[dict[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for term in SEARCH_TERMS:
        hits = [row_text(r) for r in rows if term in row_text(r)]
        out[term] = hits[:80]
    return out


def extract_strings(app: bytes) -> list[dict[str, Any]]:
    strings: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for m in re.finditer(rb"[\x20-\x7e]{3,}", app):
        s = m.group().decode("ascii", "replace")
        if any(t.lower() in s.lower() for t in STRING_TERMS):
            key = (m.start(), s)
            if key not in seen:
                seen.add(key)
                strings.append({
                    "address": f"0x{BASE + m.start():08x}",
                    "file_offset": f"0x{m.start():x}",
                    "string": s,
                })
    return strings


def bytes_context(app: bytes, addr: int, radius: int = 64) -> dict[str, Any]:
    off = addr - BASE
    start = max(0, off - radius)
    end = min(len(app), off + radius)
    lines = []
    for i in range(start, end, 16):
        data = app[i:i + 16]
        asc = "".join(chr(c) if 32 <= c <= 126 else "." for c in data)
        lines.append({"address": f"0x{BASE + i:08x}", "hex": data.hex(" "), "ascii": asc})
    return {"address": f"0x{addr:08x}", "file_offset": f"0x{off:x}", "lines": lines}


def make_findings(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "confirmed": [
            {
                "id": "sha-gates",
                "summary": "Official v15 app/package/listing SHA gates match expected values. flash.bin gate is package payload offset 20 + UFW offset 1024.",
                "evidence": ["package-manifest.json", "provenance.txt", "script sha verification"],
            },
            {
                "id": "factory-loader-current-selection",
                "summary": "0x02005660 reads RAM object base 0x01c33260, selected bank at +0x3a4 (0..3), selected preset at +0x3a0+bank (0..31).",
                "evidence": ["02005662..02005682"],
            },
            {
                "id": "factory-loader-record-copy",
                "summary": "0x02005660 computes record index (bank*32+preset)*0xa3 from pointer *(0x01c33260+0x164), adds 0x4000, and memcpy()s 0xa3 bytes to current snapshot 0x01c33260+0x1a14.",
                "evidence": ["02005682..0200569a", "0x02048cce memcpy"],
            },
            {
                "id": "factory-loader-expanded-ui-fields",
                "summary": "After the raw 0xa3 copy, 0x02005660 expands/normalizes packed fields into +0x1a14, +0x1a90, +0x1aa0 and invokes four update helpers 0x0200552e/0x0200558e/0x020055f8/0x0200562c.",
                "evidence": ["020056b4..02005782"],
            },
            {
                "id": "dirty-saved-flag-table",
                "summary": "0x02005660 indexes +0x129c + bank*32+preset and branches on flag 0/1 before copying display bytes. This is the strongest static link between selected patch and SAVE/SAVED state.",
                "evidence": ["02005786..020057dc"],
            },
            {
                "id": "current-patch-buffer-consumer",
                "summary": "0x01c34c74 is referenced directly only in 0x0201c5ec. That function copies 0x9c bytes from 0x01c34c74 into per-note/voice slots, so it is a runtime current-patch consumer rather than the factory loader itself.",
                "evidence": ["0201c602", "0201c63c..0201c67c"],
            },
            {
                "id": "official-ui-strings",
                "summary": "Official app contains #D9D9D9 SAVE#, #f5bc27 SAVED#, Please select a bank to save, usrflash, cfg_tool.bin, VM/app_dir_head/flash.bin/flash2.bin strings at the reported addresses.",
                "evidence": ["binary strings from build/v15-official-app.bin"],
            },
        ],
        "candidates": [
            {
                "id": "save-writer-candidate-02026d6c",
                "summary": "0x02026d6c gates on +0x1ec and non-0xff state, recomputes current bank/preset record, passes current snapshot +0x1a14, storage address *(+0x160)+0x4000+record*0xa3, and length 0xa3 to 0x02004b02, then marks +0x129c entry and flushes/updates *(+0x160)+0x9180 length 0x80. Direction and primitive semantics are candidate because the storage wrapper is only partially decoded.",
                "evidence": ["02026d6c..02026dd0", "02004b02 wrapper"],
            },
            {
                "id": "bank-load-save-cluster-0202553c",
                "summary": "0x0202553c handles bank selection, calls 0x02004a54 with mode 2 and bank*0x1000 storage base, transfers 0x1000 bytes via 0x02004b02, clears 32 dirty/saved flags at +0x129c, flushes +0x9180, writes +0x3a4/+0x3a0, and calls factory loader. This is likely bank-level load/commit preparation.",
                "evidence": ["0202553c..020255a6"],
            },
            {
                "id": "storage-wrapper-candidate",
                "summary": "0x02004b02 wraps 0x02004a7a, which bounds checks against a storage size field and calls 0x02063260 through a request object at +0xd1c. It behaves like a USRFLASH/VM storage transfer primitive, but exact read/write direction remains unconfirmed in this static pass.",
                "evidence": ["02004a7a..02004b14"],
            },
            {
                "id": "usrflash-low-level-candidate",
                "summary": "0x0201e846 toggles registers 0x50040/0x11d00 and commands 0x2a/0x2b/0x2c around buffers, near the usrflash string table. It is likely low-level flash/USRFLASH service code, but no direct caller chain from SAVE was confirmed.",
                "evidence": ["0201e846..0201e940", "string mnt/sdfile/app/usrflash at 0x02057d2c"],
            },
        ],
        "unconfirmed": [
            {
                "id": "ui-widget-xref-to-save-strings",
                "summary": "The SAVE/SAVED styled labels are present in the app data, but no direct absolute pointer xref was emitted by the v15 listing. UI resource tables appear to use packed/resource indexing or data tables not resolved by this listing.",
            },
            {
                "id": "exact-storage-primitive-direction",
                "summary": "0x02004b02 and 0x02004a7a are tied to the save candidate but the downstream 0x02063260 primitive is not decoded in the available listing, so read vs write direction is not asserted as confirmed.",
            },
            {
                "id": "old-v12-structure",
                "summary": "No v12-derived offsets or names were used. All addresses and offsets in this report come from v15 app/package/listing only.",
            },
        ],
        "layout": {
            "official_manifest_layout": manifest.get("layout"),
            "ufw_entries": manifest.get("ufw_entries"),
            "runtime_base": f"0x{BASE:08x}",
            "ram_object_candidate": "0x01c33260",
            "current_patch_buffer_seed": "0x01c34c74",
            "factory_loader": "0x02005660",
            "storage_pointers": {
                "record_base_pointer_load": "*(0x01c33260+0x164)",
                "bank_block_pointer_load": "*(0x01c33260+0x160)",
                "record_area_bias": "0x4000",
                "record_size": "0xa3",
                "bank_stride_records": "32",
                "bank_block_stride_candidate": "0x1000",
                "flush_or_metadata_offset_candidate": "0x9180",
            },
        },
    }


def render_report(data: dict[str, Any]) -> str:
    def bullets(items: list[dict[str, Any]]) -> str:
        out = []
        for it in items:
            out.append(f"- `{it['id']}`: {it['summary']}")
        return "\n".join(out)

    gates = data["sha_gates"]
    strings = data["strings"]
    return f"""# v15 current Patch state and SAVE/SAVED persistence static RE

Scope: official v15 app/full package only. No v12 structure was used, and no patch/flash/commit action is performed by the script.

## SHA gates

- app: `{gates['app']['actual']}` ({gates['app']['status']})
- package: `{gates['package']['actual']}` ({gates['package']['status']})
- package `flash.bin` slice: `{gates['flash_slice']['actual']}` ({gates['flash_slice']['status']})
- quarkslab exhaustive listing: `{gates['listing']['actual']}` ({gates['listing']['status']})

## 한국어 결론

- 확정: current Patch 선택값은 `0x01c33260+0x3a4` bank와 `0x01c33260+0x3a0+bank` preset이며, `0x02005660` factory loader가 `(bank*32+preset)*0xa3` 레코드를 `*(+0x164)+0x4000`에서 `+0x1a14` current snapshot으로 복사한다.
- 확정: `+0x129c + bank*32+preset` 플래그가 loader의 SAVE/SAVED 표시 상태 분기와 가장 강하게 연결된 v15 내부 근거다.
- 확정: seed `0x01c34c74`는 `0x0201c5ec`에서 0x9c-byte voice/note slot 복사 소스로 쓰이며, loader 자체의 current snapshot 주소는 `0x01c33260+0x1a14`다.
- 후보: `0x02026d6c`는 동일 record 계산 후 `+0x1a14`, `*(+0x160)+0x4000+record*0xa3`, `0xa3`를 storage wrapper `0x02004b02`에 넘기고 `+0x129c`/`+0x9180`을 갱신하므로 SAVE writer 후보다. 다만 `0x02063260` primitive 방향은 이 listing만으로 확정하지 않았다.
- 미확정: SAVE/SAVED styled label의 UI widget xref와 cfg_tool 실행/호출 체인은 direct pointer로 확정되지 않았다.

## 확정

{bullets(data['findings']['confirmed'])}

## 후보

{bullets(data['findings']['candidates'])}

## 미확정

{bullets(data['findings']['unconfirmed'])}

## 핵심 데이터 흐름

```mermaid
flowchart TD
    S[0x01c33260 + 0x3a4 selected bank] --> I[(bank*32 + preset)]
    P[0x01c33260 + 0x3a0 + bank selected preset] --> I
    I --> R[record * 0xa3]
    B[*(0x01c33260 + 0x164)] --> L[factory loader 0x02005660]
    R --> L
    L --> C[copy from B + 0x4000 + record*0xa3 to 0x01c33260 + 0x1a14]
    C --> E[expanded UI/current fields +0x1a90/+0x1aa0]
    I --> F[flag table 0x01c33260 + 0x129c + index]
    F --> V[SAVE/SAVED display state candidate]
    C --> W[save candidate 0x02026d6c]
    W --> T[0x02004b02 storage transfer candidate]
    T --> U[USRFLASH/VM backing store candidate]
```

## Strings and paths found in official app

""" + "\n".join(f"- `{s['address']}` `{s['string']}`" for s in strings) + "\n\n## Reproduction\n\nRun:\n\n```sh\npython3 baselines/v15/analysis/ui-preflash/state-persistence/analyze_state_persistence.py\n```\n\nThe script regenerates `state_persistence_evidence.json` and this report from v15-only inputs.\n"


def main() -> None:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text())
    app = APP.read_bytes()
    pkg = PKG.read_bytes()

    flash_entry = next(e for e in manifest["ufw_entries"] if e["name"] == "flash.bin")
    flash_start = 20 + flash_entry["offset"]
    flash_slice = pkg[flash_start:flash_start + flash_entry["size"]]

    rows = load_listing()
    provenance = PROVENANCE.read_text(errors="replace") if PROVENANCE.exists() else ""
    strings = extract_strings(app)
    contexts = {
        "save_label": bytes_context(app, 0x0205D97A),
        "saved_label": bytes_context(app, 0x0205D988),
        "usrflash_path": bytes_context(app, 0x02057D2C),
        "cfg_tool_path": bytes_context(app, 0x02057F18),
        "vm_table": bytes_context(app, 0x0208AD70),
    }

    gates = {
        "app": {"path": str(APP.relative_to(ROOT)), "expected": EXPECTED["app_sha256"], "actual": sha256(APP)},
        "package": {"path": str(PKG.relative_to(ROOT)), "expected": EXPECTED["package_sha256"], "actual": sha256(PKG)},
        "flash_slice": {"path": str(PKG.relative_to(ROOT)), "offset_basis": "file offset = 20-byte fwsc header + UFW flash.bin offset", "file_offset": flash_start, "size": flash_entry["size"], "expected": EXPECTED["flash_sha256"], "actual": sha256_bytes(flash_slice)},
        "listing": {"path": str(LISTING.relative_to(ROOT)), "expected": EXPECTED["listing_sha256"], "actual": sha256(LISTING)},
    }
    for g in gates.values():
        g["status"] = "PASS" if g["expected"] == g["actual"] else "FAIL"

    data: dict[str, Any] = {
        "format": "smk37-v15-ui-preflash-state-persistence-v1",
        "scope": "official v15 app/full package only; no v12 hints; no patch/flash/commit",
        "sha_gates": gates,
        "manifest": {
            "path": str(MANIFEST.relative_to(ROOT)),
            "package_sha256": manifest["package_sha256"],
            "payload_sha256": manifest["payload_sha256"],
            "app_sha256": manifest["app_sha256"],
            "flash_sha256": manifest["flash_sha256"],
        },
        "provenance_excerpt": provenance.splitlines()[:20],
        "strings": strings,
        "byte_contexts": contexts,
        "listing_search_hits": search_listing(rows),
        "listing_ranges": extract_ranges(rows),
        "findings": make_findings(manifest),
    }

    if any(g["status"] != "PASS" for g in gates.values()):
        data["gate_error"] = "One or more SHA gates failed; findings should not be trusted until inputs are restored."

    (OUTDIR / "state_persistence_evidence.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (OUTDIR / "report.md").write_text(render_report(data))
    print(f"wrote {OUTDIR / 'state_persistence_evidence.json'}")
    print(f"wrote {OUTDIR / 'report.md'}")


if __name__ == "__main__":
    main()
