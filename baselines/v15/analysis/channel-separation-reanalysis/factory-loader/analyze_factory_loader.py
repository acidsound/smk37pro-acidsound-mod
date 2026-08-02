#!/usr/bin/env python3
"""Official-v15-only factory-loader reanalysis for 0x02005660.

Inputs are official v15 app/package metadata, the v15 Ghidra/Quarkslab listing,
and clean v15 full-flash baseline dumps. The script performs no patching,
flashing, v12 reads, or firmware writes. It regenerates JSON evidence and a
human report under this directory.
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUTDIR = ROOT / "baselines/v15/analysis/channel-separation-reanalysis/factory-loader"
APP = ROOT / "build/v15-official-app.bin"
PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
OFFICIAL_MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
LISTING_PROVENANCE = ROOT / "baselines/v15/analysis/quarkslab/results/provenance.txt"
DUMP_A = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-a.bin"
DUMP_B = ROOT / "baselines/v15/device-dumps/v15-clean-baseline-b.bin"

RUNTIME_BASE = 0x02000000
RAM_BASE = 0x01C33260
LIVE_SOURCE = RAM_BASE + 0x1A14
VOICE_SIZE = 156
RAW_RECORD_SIZE = 0xA3
PACKED_VOICE_SIZE = 0x80
CLEAN_DUMP_FACTORY_BASE = 0x000F4000
BANK = 3
PRESET = 13
DISPLAY_INDEX = 14
VOICE_NAME = b"Mooger #1 "
INDEX = BANK * 32 + PRESET
PACKED_OFFSET = CLEAN_DUMP_FACTORY_BASE + BANK * 0x1000 + PRESET * PACKED_VOICE_SIZE
RAW_RECORD_OFFSET = CLEAN_DUMP_FACTORY_BASE + 0x4000 + INDEX * RAW_RECORD_SIZE
FLAG_OFFSET = CLEAN_DUMP_FACTORY_BASE + 0x9180 + INDEX

EXPECTED = {
    "app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "package_sha256": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "flash_sha256": "f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a",
    "listing_sha256": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "clean_dump_sha256": "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b",
}

RANGES = {
    "previous_function_tail_02005650_0200565e": (0x02005650, 0x0200565E),
    "factory_loader_02005660_020057de": (0x02005660, 0x020057DE),
    "next_function_head_020057e0_020057f0": (0x020057E0, 0x020057F0),
    "caller_post_init_02005f80_02005faa": (0x02005F80, 0x02005FAA),
    "caller_sysex_short_0201e448_0201e470": (0x0201E448, 0x0201E470),
    "caller_sysex_long_0201e480_0201e4a4": (0x0201E480, 0x0201E4A4),
    "caller_ui_bank_preset_020241e0_0202423a": (0x020241E0, 0x0202423A),
    "caller_default_load_0202553c_020255aa": (0x0202553C, 0x020255AA),
    "live_source_consumer_0201c5ec_0201c698": (0x0201C5EC, 0x0201C698),
}

SEARCH_TERMS = [
    "call 0x02005660",
    "0x1c33260",
    "0x1c34c74",
    "0x1a14",
    "0x1a90",
    "0x1aa0",
    "0x1ab0",
    "0x129c",
    "0x02048cce",
    "0x0200552e",
    "0x0200558e",
    "0x020055f8",
    "0x0200562c",
]

PSEUDOCODE = r'''void factory_loader_02005660(void) {
    uint8_t *g = (uint8_t *)0x01c33260;
    uint8_t bank = g[0x3a4];
    if (bank > 3) return;
    uint8_t preset = g[0x3a0 + bank];
    if (preset > 31) return;

    uint8_t *factory = *(uint8_t **)(g + 0x164);
    unsigned index = bank * 32u + preset;
    uint8_t *raw163 = factory + 0x4000 + index * 0xa3;
    uint8_t *packed128 = factory + bank * 0x1000 + preset * 0x80;
    uint8_t *cur = g + 0x1a14;       // 0x01c34c74 live source

    memcpy(cur, raw163, 0xa3);       // preserves cur[0x9c..0xa2]

    for (unsigned op = 0; op < 6; op++) {
        uint8_t *src = packed128 + op * 17;
        uint8_t *dst = cur + op * 21;
        memcpy(dst, src, 11);
        dst[11] = src[11] & 3;
        dst[12] = (src[11] >> 2) & 3;
        dst[13] = src[12] & 7;
        dst[20] = (src[12] >> 3) & 15;
        dst[14] = src[13] & 3;
        dst[15] = (src[13] >> 2) & 7;
        dst[16] = src[14];
        dst[17] = src[15] & 1;
        dst[18] = (src[15] >> 1) & 31;
        dst[19] = src[16];
    }

    memcpy(cur + 126, packed128 + 102, 9);
    cur[135] = packed128[111] & 7;
    cur[136] = (packed128[111] >> 3) & 1;
    memcpy(cur + 137, packed128 + 112, 4);
    cur[141] = packed128[116] & 1;
    cur[142] = (packed128[116] >> 1) & 7;
    cur[143] = (packed128[116] >> 4) & 7;
    cur[144] = packed128[117];
    memcpy(cur + 145, packed128 + 118, 10);
    cur[155] = 0x3f;

    update_0200552e(cur[0x9c]);
    update_0200558e(cur[0x9d]);
    update_020055f8(cur[0x9e]);
    update_0200562c(cur[0x9f]);

    *(uint8_t *)(*(uint32_t *)(g + 0x15c) + 0x16) = cur[0xa2];
    *(uint32_t *)(*(uint32_t *)(g + 0x15c) + 0x9c) = 0x1b9;

    switch (g[0x129c + index]) {
    case 0:
        cur[0xa0] = cur[0x86];
        cur[0xa1] = cur[0x87];
        break;
    case 1:
        cur[0x86] = cur[0xa0];
        cur[0x87] = cur[0xa1];
        break;
    default:
        break;
    }
}'''


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_listing() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    with gzip.open(LISTING, "rt", errors="replace") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == len(header):
                rows.append(dict(zip(header, parts)))
    return rows


def row_text(row: dict[str, str]) -> str:
    return "\t".join(row[k] for k in ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"])


def rows_in(rows: list[dict[str, str]], lo: int, hi: int) -> list[str]:
    return [row_text(r) for r in rows if lo <= int(r["address"], 16) <= hi]


def search(rows: list[dict[str, str]]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for term in SEARCH_TERMS:
        out[term] = [row_text(r) for r in rows if term in row_text(r)][:100]
    return out


def expand_v15_factory_voice(packed: bytes) -> bytes:
    if len(packed) != PACKED_VOICE_SIZE:
        raise ValueError("packed voice must be exactly 128 bytes")
    out = bytearray(VOICE_SIZE)
    for operator in range(6):
        src = operator * 17
        dst = operator * 21
        out[dst:dst + 11] = packed[src:src + 11]
        curves = packed[src + 11]
        out[dst + 11] = curves & 3
        out[dst + 12] = (curves >> 2) & 3
        detune_rate = packed[src + 12]
        out[dst + 13] = detune_rate & 7
        velocity_amp = packed[src + 13]
        out[dst + 14] = velocity_amp & 3
        out[dst + 15] = (velocity_amp >> 2) & 7
        out[dst + 16] = packed[src + 14]
        coarse_mode = packed[src + 15]
        out[dst + 17] = coarse_mode & 1
        out[dst + 18] = (coarse_mode >> 1) & 0x1F
        out[dst + 19] = packed[src + 16]
        out[dst + 20] = (detune_rate >> 3) & 0x0F
    out[126:135] = packed[102:111]
    feedback_sync = packed[111]
    out[135] = feedback_sync & 7
    out[136] = (feedback_sync >> 3) & 1
    out[137:141] = packed[112:116]
    lfo = packed[116]
    out[141] = lfo & 1
    out[142] = (lfo >> 1) & 7
    out[143] = (lfo >> 4) & 7
    out[144] = packed[117]
    out[145:155] = packed[118:128]
    out[155] = 0x3F
    return bytes(out)


def simulate_loader_for_mooger(dump: bytes) -> dict[str, Any]:
    packed = dump[PACKED_OFFSET:PACKED_OFFSET + PACKED_VOICE_SIZE]
    raw = dump[RAW_RECORD_OFFSET:RAW_RECORD_OFFSET + RAW_RECORD_SIZE]
    flag = dump[FLAG_OFFSET]
    static156 = expand_v15_factory_voice(packed)
    live163 = bytearray(raw)
    live163[:VOICE_SIZE] = static156
    postprocessing: list[dict[str, Any]] = []
    if flag == 0:
        before = (live163[0xA0], live163[0xA1])
        live163[0xA0] = live163[0x86]
        live163[0xA1] = live163[0x87]
        postprocessing.append({
            "flag": 0,
            "operation": "cur[0xa0]=cur[0x86]; cur[0xa1]=cur[0x87]",
            "before_tail_a0_a1": [f"0x{x:02x}" for x in before],
            "after_tail_a0_a1": [f"0x{live163[0xA0]:02x}", f"0x{live163[0xA1]:02x}"],
        })
    elif flag == 1:
        before = (live163[0x86], live163[0x87])
        live163[0x86] = live163[0xA0]
        live163[0x87] = live163[0xA1]
        postprocessing.append({
            "flag": 1,
            "operation": "cur[0x86]=cur[0xa0]; cur[0x87]=cur[0xa1]",
            "before_0x86_0x87": [f"0x{x:02x}" for x in before],
            "after_0x86_0x87": [f"0x{live163[0x86]:02x}", f"0x{live163[0x87]:02x}"],
        })
    first_156_diffs = [
        {"offset": f"0x{i:02x}", "static": f"0x{static156[i]:02x}", "live": f"0x{live163[i]:02x}"}
        for i in range(VOICE_SIZE) if static156[i] != live163[i]
    ]
    tail_diffs = [
        {
            "offset": f"0x{i:02x}",
            "static_has_byte": False,
            "live": f"0x{live163[i]:02x}",
            "raw_before_postprocess": f"0x{raw[i]:02x}",
        }
        for i in range(VOICE_SIZE, RAW_RECORD_SIZE)
    ]
    return {
        "selection": {
            "bank_zero_based": BANK,
            "bank_display": "D",
            "preset_zero_based": PRESET,
            "preset_display": DISPLAY_INDEX,
            "index_formula": "bank*32+preset",
            "index_decimal": INDEX,
            "index_hex": f"0x{INDEX:x}",
            "voice_name": packed[118:128].decode("ascii", "replace"),
        },
        "offsets": {
            "clean_dump_factory_base_model": f"0x{CLEAN_DUMP_FACTORY_BASE:08x}",
            "packed128": f"0x{PACKED_OFFSET:08x}",
            "raw163": f"0x{RAW_RECORD_OFFSET:08x}",
            "flag": f"0x{FLAG_OFFSET:08x}",
            "runtime_destination": f"0x{LIVE_SOURCE:08x}",
            "runtime_tail_0x9c": f"0x{LIVE_SOURCE + 0x9c:08x}",
            "runtime_flag_pair_inside_0x86_0x87": [f"0x{LIVE_SOURCE + 0x86:08x}", f"0x{LIVE_SOURCE + 0x87:08x}"],
            "runtime_flag_pair_tail_0xa0_0xa1": [f"0x{LIVE_SOURCE + 0xa0:08x}", f"0x{LIVE_SOURCE + 0xa1:08x}"],
        },
        "identity_checks": {
            "packed_name_bytes": packed[118:128].hex(),
            "packed_name_expected": VOICE_NAME.decode("ascii"),
            "packed_name_status": "PASS" if packed[118:128] == VOICE_NAME else "FAIL",
            "flag_value": flag,
        },
        "hashes": {
            "packed128_sha256": sha256_bytes(packed),
            "raw163_sha256": sha256_bytes(raw),
            "static_128_to_156_sha256": sha256_bytes(static156),
            "simulated_live_first_0x9c_sha256": sha256_bytes(bytes(live163[:VOICE_SIZE])),
            "simulated_live_full_0xa3_sha256": sha256_bytes(bytes(live163)),
        },
        "static_vs_live_source": {
            "clean_mooger_first_0x9c_equal": not first_156_diffs,
            "first_0x9c_diffs": first_156_diffs,
            "not_equivalent_reasons": [
                "0x02005660 first copies a full 0xa3-byte raw record to 0x01c34c74, while the R01-style static expansion materializes only the first 0x9c bytes.",
                "For the clean Mooger #1 flag=0 path, bytes 0x9c..0xa2 remain live-only tail state; +0xa0/+0xa1 are postprocessed from +0x86/+0x87.",
                "If the selected +0x129c flag is 1, the branch direction reverses and live bytes +0x86/+0x87, which are inside the 0x9c note source, are overwritten from the tail. That case is not represented by a pure 128-to-156 expansion.",
                "0x02005660 also calls four update helpers with cur[0x9c..0x9f] and updates *(+0x15c)+0x16/+0x9c, so the loader has side effects that a static code-cave snapshot cannot reproduce.",
            ],
            "tail_diffs_static_absent_vs_live_0x9c_0xa2": tail_diffs,
            "postprocessing_applied": postprocessing,
        },
        "byte_samples": {
            "packed128_hex": packed.hex(),
            "raw163_hex": raw.hex(),
            "static156_hex": static156.hex(),
            "simulated_live163_hex": bytes(live163).hex(),
        },
    }


def build_gates(manifest: dict[str, Any], package: bytes, dump_a: bytes, dump_b: bytes) -> dict[str, Any]:
    flash_entry = next(e for e in manifest["ufw_entries"] if e["name"] == "flash.bin")
    flash_start = 20 + flash_entry["offset"]
    flash_slice = package[flash_start:flash_start + flash_entry["size"]]
    gates = {
        "app": {"path": str(APP.relative_to(ROOT)), "expected": EXPECTED["app_sha256"], "actual": sha256_file(APP)},
        "package": {"path": str(PACKAGE.relative_to(ROOT)), "expected": EXPECTED["package_sha256"], "actual": sha256_file(PACKAGE)},
        "flash_slice": {"path": str(PACKAGE.relative_to(ROOT)), "file_offset": flash_start, "size": flash_entry["size"], "expected": EXPECTED["flash_sha256"], "actual": sha256_bytes(flash_slice)},
        "listing": {"path": str(LISTING.relative_to(ROOT)), "expected": EXPECTED["listing_sha256"], "actual": sha256_file(LISTING)},
        "clean_dump_a": {"path": str(DUMP_A.relative_to(ROOT)), "expected": EXPECTED["clean_dump_sha256"], "actual": sha256_bytes(dump_a)},
        "clean_dump_b": {"path": str(DUMP_B.relative_to(ROOT)), "expected": EXPECTED["clean_dump_sha256"], "actual": sha256_bytes(dump_b)},
        "clean_dump_a_b_cmp": {"expected": "identical", "actual": "identical" if dump_a == dump_b else "different"},
    }
    for gate in gates.values():
        if "expected" in gate and "actual" in gate:
            gate["status"] = "PASS" if gate["expected"] == gate["actual"] else "FAIL"
    return gates


def render_report(data: dict[str, Any]) -> str:
    gates = data["sha_gates"]
    sel = data["bank_d_mooger_path"]
    loader = data["factory_loader"]
    cmp = sel["static_vs_live_source"]
    ranges = data["listing_ranges"]

    def gate_line(name: str) -> str:
        g = gates[name]
        return f"- {name}: `{g['actual']}` ({g['status']})"

    def block(name: str) -> str:
        return "```text\n" + "\n".join(ranges[name]) + "\n```"

    callers = "\n".join(
        f"- `{c['callsite']}`: {c['path']}; return consumer: {c['return_consumer']}"
        for c in loader["callsites"]
    )
    helper_lines = "\n".join(
        f"- `{h['callsite']}` -> `{h['target']}` with source `{h['source']}`"
        for h in loader["postprocessing_helpers"]
    )
    tail_lines = "\n".join(
        f"- offset `{d['offset']}` live `{d['live']}` (raw before postprocess `{d['raw_before_postprocess']}`), no byte exists in 156-byte static expansion"
        for d in cmp["tail_diffs_static_absent_vs_live_0x9c_0xa2"]
    )
    first_diff = cmp["first_0x9c_diffs"]
    if first_diff:
        first_diff_text = "\n".join(f"- `{d['offset']}` static {d['static']} live {d['live']}" for d in first_diff)
    else:
        first_diff_text = "- clean Mooger #1 flag=0 path: first `0x9c` bytes are byte-equal to the pure 128→156 expansion."

    return f"""# v15 factory loader 0x02005660 reanalysis

Scope: official v15 artifacts only. This script does not read v12, generate a patch, touch flash, or modify firmware images.

## SHA gates

{gate_line('app')}
{gate_line('package')}
{gate_line('flash_slice')}
{gate_line('listing')}
{gate_line('clean_dump_a')}
{gate_line('clean_dump_b')}
- clean_dump_a_b_cmp: `{gates['clean_dump_a_b_cmp']['actual']}` ({gates['clean_dump_a_b_cmp']['status']})

## 결론

- `0x02005660` 함수 경계는 `0x02005660..0x020057de`이다. 직전 함수는 `0x0200565e`에서 `rts`, 다음 함수는 `0x020057e0`에서 `push`로 시작한다.
- 인자는 호출자 전달값을 사용하지 않는 `void factory_loader(void)` 형태다. 함수 내부에서 전역 RAM base `0x01c33260`, selected bank `+0x3a4`, selected preset `+0x3a0+bank`를 직접 읽는다.
- destination은 `0x01c33260+0x1a14 = 0x01c34c74`이다. 이 주소는 Note On/Off dispatcher `0x0201c5ec`의 `0x9c` byte memcpy source이기도 하다.
- Bank D display 14, zero-based index 13 `Mooger #1` 경로는 index `109`, packed128 dump offset `{sel['offsets']['packed128']}`, raw163 offset `{sel['offsets']['raw163']}`, flag offset `{sel['offsets']['flag']}`이다.
- R01식 128→156 정적 expansion은 clean Mooger #1의 첫 `0x9c` bytes와는 같다. 그러나 live source object와 동등하지는 않다. loader는 먼저 `0xa3` bytes를 복사하고, tail `0x9c..0xa2`, flag-dependent display byte swap/copy, helper side effects를 추가 수행한다.

## Function boundary and callers

{callers}

### Boundary evidence

{block('previous_function_tail_02005650_0200565e')}

{block('factory_loader_02005660_020057de')}

{block('next_function_head_020057e0_020057f0')}

## C-like pseudocode

```c
{PSEUDOCODE}
```

## Bank D display14/index13 Mooger #1 actual path

- UI-selected fields: bank `D` = zero-based `{sel['selection']['bank_zero_based']}` read at `0x01c33260+0x3a4`; preset display `{DISPLAY_INDEX}` = zero-based `{PRESET}` read at `0x01c33260+0x3a0+bank`.
- record index: `(3*32)+13 = {INDEX}`.
- packed 128-byte source: `*(0x01c33260+0x164) + bank*0x1000 + preset*0x80`; clean dump model offset `{sel['offsets']['packed128']}`; name `{sel['selection']['voice_name']}`.
- raw 0xa3 source: `*(0x01c33260+0x164) + 0x4000 + index*0xa3`; clean dump model offset `{sel['offsets']['raw163']}`.
- dirty/SAVED flag: `0x01c33260+0x129c+index`; persisted table model offset `{sel['offsets']['flag']}`; clean value `{sel['identity_checks']['flag_value']}`.
- destination/live source: `{sel['offsets']['runtime_destination']}`; Note event consumer copies first `0x9c` bytes.

Hashes:

- packed128: `{sel['hashes']['packed128_sha256']}`
- raw163 before loader expansion: `{sel['hashes']['raw163_sha256']}`
- pure static 128→156 expansion: `{sel['hashes']['static_128_to_156_sha256']}`
- simulated live first 0x9c: `{sel['hashes']['simulated_live_first_0x9c_sha256']}`
- simulated live full 0xa3 object: `{sel['hashes']['simulated_live_full_0xa3_sha256']}`

## Static expansion vs live source differences

First `0x9c` comparison:

{first_diff_text}

Full live object tail not represented by a 156-byte static expansion:

{tail_lines}

Postprocessing applied for this clean Mooger selection:

```json
{json.dumps(cmp['postprocessing_applied'], indent=2)}
```

Why this matters:

""" + "\n".join(f"- {reason}" for reason in cmp["not_equivalent_reasons"]) + f"""

## 128→156 expansion plus extra postprocessing evidence

Expansion and raw copy are inside `0x02005682..0x02005766`; helper/UI/flag postprocessing follows:

{helper_lines}

- `0x02005786..0x02005798`: writes `cur[0xa2]` to `*(+0x15c)+0x16` and stores `0x1b9` at `*(+0x15c)+0x9c`.
- `0x0200579c..0x020057b4`: recomputes selected `bank*32+preset` and loads `+0x129c[index]`.
- `0x020057b8..0x020057dc`: flag `0` copies `cur[0x86..0x87]` to tail `cur[0xa0..0xa1]`; flag `1` copies tail `cur[0xa0..0xa1]` back into `cur[0x86..0x87]`.

## Return consumers and live source consumer

### `0x02005f9c` caller

{block('caller_post_init_02005f80_02005faa')}

### `0x0201e46c` caller

{block('caller_sysex_short_0201e448_0201e470')}

### `0x0201e4a0` caller

{block('caller_sysex_long_0201e480_0201e4a4')}

### `0x0202422e` UI bank/preset caller

{block('caller_ui_bank_preset_020241e0_0202423a')}

### `0x020255a6` default-load caller

{block('caller_default_load_0202553c_020255aa')}

### `0x01c34c74` Note On/Off consumer

{block('live_source_consumer_0201c5ec_0201c698')}

## Reproduction

```sh
python3 baselines/v15/analysis/channel-separation-reanalysis/factory-loader/analyze_factory_loader.py
```

The command regenerates `factory_loader_evidence.json` and this report from official-v15 inputs only.
"""


def main() -> None:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(OFFICIAL_MANIFEST.read_text())
    package = PACKAGE.read_bytes()
    dump_a = DUMP_A.read_bytes()
    dump_b = DUMP_B.read_bytes()
    rows = load_listing()
    gates = build_gates(manifest, package, dump_a, dump_b)
    listing_ranges = {name: rows_in(rows, lo, hi) for name, (lo, hi) in RANGES.items()}

    data: dict[str, Any] = {
        "format": "smk37-v15-channel-separation-factory-loader-reanalysis-v1",
        "scope": "official v15 app/package/listing and clean v15 dumps only; no v12; no patch; no flash",
        "sha_gates": gates,
        "provenance_excerpt": LISTING_PROVENANCE.read_text(errors="replace").splitlines()[:30] if LISTING_PROVENANCE.exists() else [],
        "factory_loader": {
            "function": "0x02005660",
            "boundary": {"start": "0x02005660", "end_inclusive": "0x020057de", "previous_function_return": "0x0200565e", "next_function_start": "0x020057e0"},
            "abi": {
                "prototype": "void factory_loader_02005660(void)",
                "arguments": "No caller-provided argument is consumed; r0/r1/r2 are overwritten before use.",
                "saved_registers": ["rets", "r8", "r7", "r6", "r5", "r4"],
                "return_value": "none/ignored; callers do not consume r0 as a status",
            },
            "global_inputs": {
                "ram_base": "0x01c33260",
                "selected_bank": "*(uint8_t *)(0x01c33260+0x3a4), valid 0..3",
                "selected_preset": "*(uint8_t *)(0x01c33260+0x3a0+bank), valid 0..31",
                "factory_pointer": "*(uint32_t *)(0x01c33260+0x164)",
                "display_flag": "*(uint8_t *)(0x01c33260+0x129c+bank*32+preset)",
                "ui_pointer": "*(uint32_t *)(0x01c33260+0x15c)",
            },
            "destinations": {
                "current_live_source": "0x01c33260+0x1a14 = 0x01c34c74",
                "expanded_ui_fields": ["0x01c33260+0x1a90", "0x01c33260+0x1aa0", "0x01c33260+0x1ab0"],
                "ui_side_effects": ["*( *(0x01c33260+0x15c) + 0x16 )", "*(uint32_t *)(*(0x01c33260+0x15c)+0x9c)"],
            },
            "callsites": [
                {"callsite": "0x02005f9c", "path": "post-init or state refresh path; copies +0x3a6/+0x3a7 to UI fields before loader", "return_consumer": "loads *(r6+0x15c) into r0 and calls 0x020057e0 at 0x02005fa4"},
                {"callsite": "0x0201e46c", "path": "SysEx/product packet path after 0x0201e13e", "return_consumer": "immediate pop; return value ignored"},
                {"callsite": "0x0201e4a0", "path": "alternate SysEx/product packet path after 0x0201e13e", "return_consumer": "jumps to common continuation 0x0201e538; return value ignored"},
                {"callsite": "0x0202422e", "path": "UI bank/preset change; invokes 0x02024070 before loader", "return_consumer": "loads *(0x01c33260+0x15c) and calls 0x020057e0 at 0x02024236"},
                {"callsite": "0x020255a6", "path": "default-load/bank-block path after writing bank block and clearing flag table", "return_consumer": "falls through with r0=0x64; loader return ignored"},
            ],
            "postprocessing_helpers": [
                {"callsite": "0x02005770", "target": "0x0200552e", "source": "cur[0x9c] = *(0x01c33260+0x1ab0)"},
                {"callsite": "0x02005776", "target": "0x0200558e", "source": "cur[0x9d] = *(0x01c33260+0x1ab1)"},
                {"callsite": "0x0200577c", "target": "0x020055f8", "source": "cur[0x9e] = *(0x01c33260+0x1ab2)"},
                {"callsite": "0x02005782", "target": "0x0200562c", "source": "cur[0x9f] = *(0x01c33260+0x1ab3)"},
            ],
            "pseudocode": PSEUDOCODE,
        },
        "bank_d_mooger_path": simulate_loader_for_mooger(dump_a),
        "listing_search_hits": search(rows),
        "listing_ranges": listing_ranges,
    }
    if any(g.get("status") == "FAIL" for g in gates.values()):
        data["gate_error"] = "One or more SHA gates failed; do not trust derived conclusions until inputs are restored."

    (OUTDIR / "factory_loader_evidence.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (OUTDIR / "report.md").write_text(render_report(data))
    print(f"wrote {OUTDIR / 'factory_loader_evidence.json'}")
    print(f"wrote {OUTDIR / 'report.md'}")


if __name__ == "__main__":
    main()
