#!/usr/bin/env python3
"""Build an analysis-only PI32 S1-C2 fixed-note extended producer candidate.

This emits raw bytes and evidence only. It never creates app.bin, FWSC, ZIP,
rollback, or device/flash artifacts.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]

FORMAT = "smk37-v15-s1c2-extended-producer-candidate-v1"
RUNTIME_BASE = 0x02000000
APP_SIZE = 617_012
H2_APP = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
H2_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json"
STOCK_HELPERS_REPORT = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/stock-helpers/report.md"
PROTOCOL_REPORT = ROOT / "baselines/v15/analysis/patch-set-ui/s1c2-unblock/protocol-alternatives/report.md"
QUARK_LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
KAGA_LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"

EXPECTED = {
    "official_app_sha256": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "h2_app_sha256": "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    "h2_manifest_sha256": "dc6fba4ddb887424d6bd76b6d1477f66f97096e2d6656f203eec423680572cf3",
}

PRODUCER_START = 0x0201E1A2
PRODUCER_END_LIMIT = 0x0201E254
MAX_BYTES = PRODUCER_END_LIMIT - PRODUCER_START
SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
GAP_START = 0x0201E19E
GAP_END = 0x0201E1A2
OFFICIAL_HANDLER = 0x0201E254
MEMCPY = 0x02048CCE
DIRECT_PRODUCT_CALL = 0x0201E468
SEGMENTED_PRODUCT_CALL = 0x0201E49C
DIRECT_RELOAD_CALL = 0x0201E46C
SEGMENTED_RELOAD_CALL = 0x0201E4A0

SLOT0 = 0x01C46520
VALID0 = 0x01C465BC
LOCK = 0x01C465BD
NOTE0 = 0x01C465BE
STATE = 0x01C465BF
SLOT1 = 0x01C465C0
VALID1 = 0x01C4665C
NOTE1 = 0x01C4665E
EMPTY = 0
LOADING = 1
ARMED = 2
FIXED_NOTE0 = 36
FIXED_NOTE1 = 45
VOICE_SIZE = 0x9C

PRODUCER_OLD_SIZE = 0x0201E1EC - PRODUCER_START


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def off(address: int) -> int:
    value = address - RUNTIME_BASE
    require(0 <= value <= APP_SIZE, f"address outside app: 0x{address:08x}")
    return value


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def mov_reg(dst: int, src: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15, "mov_reg operands")
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    require(0 <= dst <= 15, "mov_imm32 register")
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def call32(at: int, target: int) -> bytes:
    displacement = target - (at + 6)
    require(-(1 << 31) <= displacement < (1 << 31), "call32 displacement")
    return b"\x80\xff" + struct.pack("<i", displacement)


def short_call(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "short_call alignment")
    halfwords = displacement // 2
    require((at + 4 + ((halfwords & 0xFFFF) * 2)) % 0x20000 == target % 0x20000, "short_call window")
    return b"\xbf\xea" + struct.pack("<H", halfwords & 0xFFFF)


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "jne alignment")
    halfwords = displacement // 2
    require(-256 <= halfwords <= 255, "jne reach")
    require(0 <= register <= 7 and 0 <= immediate <= 0x7F, "jne operands")
    return word(0xF880 | register) + word((immediate << 9) | (halfwords & 0x1FF))


def ifeq(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0 and -0x10000 <= displacement <= 0xFFFE, "ifeq reach")
    return bytes.fromhex("40e8") + struct.pack("<h", displacement // 2)


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    require(displacement >= 0 and displacement % 2 == 0, "forward goto direction/alignment")
    halfwords = displacement // 2
    require(halfwords <= 31, "forward goto reach")
    return word(0x8004 | (halfwords << 8))


def mov_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and 0 <= immediate <= 0xFF, "mov_imm8 operands")
    return word(0x2040 | register | ((immediate >> 5) << 3) | ((immediate & 0x1F) << 8))


def add_imm12(destination: int, source: int, immediate: int) -> bytes:
    require(0 <= destination <= 15 and 0 <= source <= 15 and 0 <= immediate <= 0xFFF, "add_imm12 operands")
    return bytes((destination, 0xE1, immediate & 0xFF, (source << 4) | (immediate >> 8)))


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (destination, base)), "load_byte registers")
    require(-16 <= offset <= 15, "load_byte offset")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(source: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (source, base)), "store_byte registers")
    require(-16 <= offset <= 15, "store_byte offset")
    return word(0x4088 | source | (base << 4) | ((offset & 0x1F) << 8))


class Builder:
    def __init__(self, start: int) -> None:
        self.start = start
        self.block = bytearray()
        self.insns: list[dict[str, Any]] = []
        self.labels: dict[str, int] = {"entry": start}

    @property
    def pc(self) -> int:
        return self.start + len(self.block)

    def mark(self, name: str) -> int:
        self.labels[name] = self.pc
        return self.pc

    def emit(self, name: str, blob: bytes, meaning: str) -> int:
        at = self.pc
        self.block.extend(blob)
        self.insns.append({"address": f"0x{at:08x}", "bytes": blob.hex(), "name": name, "meaning": meaning})
        return at

    def patch(self, at: int, blob: bytes) -> None:
        start = at - self.start
        self.block[start:start + len(blob)] = blob
        for insn in self.insns:
            if int(insn["address"], 16) == at:
                insn["bytes"] = blob.hex()
                return
        raise AssertionError(f"no instruction at 0x{at:08x}")


def build_producer() -> tuple[bytes, dict[str, int], list[dict[str, Any]]]:
    b = Builder(PRODUCER_START)

    b.emit("push_saved", word(0x0479), "save rets,r9..r4 like H2 producer")
    b.emit("save_stage", mov_reg(4, 0), "r4 = accepted product staging pointer from H2 producer ABI")
    b.emit("lock_pointer", mov_imm32(0, LOCK), "r0 = lock byte 0x01c465bd")
    b.emit("trylock", bytes.fromhex("2000b000"), "csync; testset b[r0], nonblocking H2-compatible trylock")
    try_fail_branch = b.emit("trylock_failed_return_branch", b"\0" * 4, "ifeq -> return without clearing somebody else's lock")
    b.emit("acquired_csync", word(0x0020), "csync after acquired lock")
    b.emit("metadata_base", mov_imm32(5, VALID0), "r5 = slot0 metadata base: valid0")
    b.emit("state_load", load_byte(0, 5, STATE - VALID0), "r0 = state byte at 0x01c465bf")
    state_not_empty_branch = b.emit("state_not_empty_branch", b"\0" * 4, "state != EMPTY -> loading/armed path")

    b.mark("empty_path")
    b.emit("state_loading_value", mov_imm8(0, LOADING), "r0 = LOADING")
    b.emit("state_loading_store", store_byte(0, 5, STATE - VALID0), "state = LOADING before slot0 copy")
    b.emit("loading_csync", word(0x0020), "order LOADING before slot0 data publication")
    b.emit("note0_value", mov_imm8(0, FIXED_NOTE0), "r0 = fixed note 36")
    b.emit("note0_store", store_byte(0, 5, NOTE0 - VALID0), "note0 = 36")
    b.emit("slot0_destination", mov_imm32(0, SLOT0), "r0 = slot0 destination")
    b.emit("slot0_source", mov_reg(1, 4), "r1 = accepted staging pointer")
    b.emit("copy_size", mov_imm8(2, VOICE_SIZE), "r2 = 0x9c")
    at = b.pc
    b.emit("slot0_memcpy", call32(at, MEMCPY), "memcpy(slot0, staging, 0x9c)")
    b.emit("slot0_csync", word(0x0020), "order slot0 copy before valid0")
    b.emit("valid0_value", mov_imm8(0, 1), "r0 = 1")
    b.emit("valid0_store", store_byte(0, 5), "valid0 = 1 last for first product")
    empty_done_goto = b.emit("empty_done_unlock_goto", b"\0" * 2, "skip loading path and unlock")

    not_empty = b.mark("not_empty_path")
    state_not_loading_branch = b.emit("state_not_loading_branch", b"\0" * 4, "state != LOADING -> unlock/no mutation, including ARMED")
    b.emit("valid0_load", load_byte(0, 5), "r0 = valid0")
    valid0_missing_branch = b.emit("valid0_missing_branch", b"\0" * 4, "valid0 != 1 -> unlock/no mutation")
    b.emit("slot1_metadata_base", add_imm12(6, 5, VALID1 - VALID0), "r6 = slot1 metadata base: valid1")
    b.emit("valid1_load", load_byte(0, 6), "r0 = valid1")
    valid1_present_branch = b.emit("valid1_present_branch", b"\0" * 4, "valid1 != 0 -> unlock/no mutation")
    b.emit("note1_value", mov_imm8(0, FIXED_NOTE1), "r0 = fixed note 45")
    b.emit("note1_store", store_byte(0, 6, NOTE1 - VALID1), "note1 = 45")
    b.emit("slot1_destination", mov_imm32(0, SLOT1), "r0 = slot1 destination")
    b.emit("slot1_source", mov_reg(1, 4), "r1 = accepted staging pointer")
    b.emit("slot1_copy_size", mov_imm8(2, VOICE_SIZE), "r2 = 0x9c")
    at = b.pc
    b.emit("slot1_memcpy", call32(at, MEMCPY), "memcpy(slot1, staging, 0x9c)")
    b.emit("slot1_csync", word(0x0020), "order slot1 copy before valid1")
    b.emit("valid1_value", mov_imm8(0, 1), "r0 = 1")
    b.emit("valid1_store", store_byte(0, 6), "valid1 = 1 before ARMED")
    b.emit("armed_csync", word(0x0020), "order valid1 before ARMED")
    b.emit("armed_value", mov_imm8(0, ARMED), "r0 = ARMED")
    b.emit("armed_store", store_byte(0, 5, STATE - VALID0), "state = ARMED last")

    unlock = b.mark("unlock")
    b.emit("unlock_pointer", mov_imm32(0, LOCK), "r0 = lock byte")
    b.emit("unlock_csync_before", word(0x0020), "csync before unlock store")
    b.emit("unlock_zero", mov_imm8(1, 0), "r1 = 0")
    b.emit("unlock_store", store_byte(1, 0), "lock = 0")
    b.emit("unlock_csync_after", word(0x0020), "csync after unlock store")
    ret = b.mark("return")
    b.emit("return_restore", word(0x0459), "pop pc,r9..r4; caller reload/return ABI preserved")

    b.patch(try_fail_branch, ifeq(try_fail_branch, ret))
    b.patch(state_not_empty_branch, jne_imm7(state_not_empty_branch, 0, EMPTY, not_empty))
    b.patch(empty_done_goto, forward_goto(empty_done_goto, unlock))
    b.patch(state_not_loading_branch, jne_imm7(state_not_loading_branch, 0, LOADING, unlock))
    b.patch(valid0_missing_branch, jne_imm7(valid0_missing_branch, 0, 1, unlock))
    b.patch(valid1_present_branch, jne_imm7(valid1_present_branch, 0, 0, unlock))

    for insn in b.insns:
        address = int(insn["address"], 16)
        size = len(bytes.fromhex(insn["bytes"]))
        insn["bytes"] = bytes(b.block[address - b.start:address - b.start + size]).hex()

    layout = dict(b.labels)
    layout.update({
        "try_fail_branch": try_fail_branch,
        "state_not_empty_branch": state_not_empty_branch,
        "empty_done_goto": empty_done_goto,
        "state_not_loading_branch": state_not_loading_branch,
        "valid0_missing_branch": valid0_missing_branch,
        "valid1_present_branch": valid1_present_branch,
        "end": PRODUCER_START + len(b.block),
    })
    return bytes(b.block), layout, b.insns


def listing_rows(path: Path, addresses: set[int]) -> dict[str, str]:
    found: dict[str, str] = {}
    if not path.exists():
        return found
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                addr = int(line.split("\t", 1)[0], 16)
            except (ValueError, IndexError):
                continue
            if addr in addresses:
                found[f"0x{addr:08x}"] = line.rstrip("\n")
    return found


def render_decode(insns: list[dict[str, Any]]) -> str:
    lines = ["address\tbytes\tname\tmeaning"]
    for insn in insns:
        lines.append(f"{insn['address']}\t{insn['bytes']}\t{insn['name']}\t{insn['meaning']}")
    return "\n".join(lines) + "\n"


def render_report(evidence: dict[str, Any]) -> str:
    branch_lines = "\n".join(
        f"| `{b['address']}` | `{b['kind']}` | `{b['target']}` | {b['reach_bytes']} | {b['status']} |"
        for b in evidence["branch_proofs"]
    )
    return f"""# S1-C2 extended H2 producer candidate

Date: 2026-08-02 UTC  
Status: **CANDIDATE, analysis-only bytes, no firmware package**

## Decision

A reduced producer-only implementation fits the requested replacement window. It replaces the live-PASS H2 producer entry at `0x0201e1a2` and extends into the positively owned residual tail, ending at `{evidence['layout']['end']}`. It does not touch the selector range `0x0201e13e..0x0201e19e`, the 4-byte gap `0x0201e19e..0x0201e1a2`, or the official handler at `0x0201e254`.

This is not a firmware image and not a flashable package. It is an offline byte candidate for review.

## Exact byte budget

- Candidate range: `0x0201e1a2..{evidence['layout']['end']}`
- Candidate bytes: `{evidence['candidate_size']}`
- Maximum authorized bytes: `{evidence['max_size']}`
- Margin: `{evidence['size_margin']}` bytes
- Old H2 producer bytes covered: `0x0201e1a2..0x0201e1ec` ({PRODUCER_OLD_SIZE} bytes)
- Residual tail used: `{evidence['residual_tail_used_bytes']}` bytes
- Official handler first byte: `0x0201e254`, untouched

## ABI and gate admission

- Producer entry ABI used: `r0 = accepted product staging pointer`, proven by the H2 producer and product callsites.
- H2 accepted-packet ingress preserved: the direct and segmented accepted-product callsites still enter at `0x0201e1a2`, the producer still copies exactly `0x9c` bytes from the accepted staging pointer, and the caller still resumes to the existing reload calls after `pop pc`.
- S1-C2 publication intentionally changes the H2 one-slot immediate-visible policy into the requested two-slot `LOADING -> ARMED` policy.
- Preserved return ABI: same saved-register shape as H2, `push {{rets,r9..r4}}` and `pop {{pc,r9..r4}}`.
- Preserved caller reloads: direct and segmented product reload callsites after producer return remain outside this candidate.
- Exact packet/route length gate: **omitted by requirement**, because producer ABI evidence does not prove length or route state at `0x0201e1a2`. The only admitted source is the existing official/H2 accepted-product calls after their gates.

## Unlock semantics

- Nonblocking trylock-fail exits directly without clearing the lock, matching H2 semantics and avoiding clearing another owner.
- Every path after a successful trylock reaches the single unlock block before return.
- `ARMED`, malformed lifecycle state, missing `valid0`, and already-present `valid1` all unlock with no publication mutation.

## Publication behavior

- Boot-zero `state=EMPTY`, `valid0=0`, `valid1=0` is expected from the existing S1-C1 BSS extension through `0x01c46660`.
- First accepted product payload under the nonblocking trylock stores `state=LOADING`, stores fixed `note0=36`, copies `0x9c` bytes to slot0, then writes `valid0=1` last.
- Second accepted product payload when `state=LOADING`, `valid0=1`, and `valid1=0` stores fixed `note1=45`, copies `0x9c` bytes to slot1, writes `valid1=1`, then writes `state=ARMED` last.
- `state != LOADING` in the second path, including `ARMED`, unlocks with no mutation.
- Consumers continue to fall back until `ARMED`; that consumer behavior is supplied by the existing fixed-selector evidence, not changed here.

## Branch reach proof

| branch | kind | target | reach bytes | status |
|---|---|---|---:|---|
{branch_lines}

## Generated artifacts

- `producer.bin`: raw candidate bytes only.
- `producer.hex`: raw candidate bytes as hex.
- `decode.tsv`: builder ledger for the encoded instructions.
- `independent-decode.tsv`: validator-produced decode from the raw bytes only.
- `evidence.json`: machine-readable evidence and hashes.
- `validate.py`: independent decoder and invariant checker.
- `validation.txt`: captured validation output.

## Validation

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/build_extended_producer.py
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/validate.py
(cd baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer && shasum -a 256 -c SHA256SUMS)
```
"""


def branch_proofs(candidate: bytes) -> list[dict[str, Any]]:
    # Decode only branch forms that this candidate emits. This proof is separate
    # from the instruction ledger, but kept in the builder so evidence is useful
    # before validate.py is run.
    proofs: list[dict[str, Any]] = []
    i = 0
    while i < len(candidate):
        at = PRODUCER_START + i
        if candidate[i:i + 2] == b"\x40\xe8":
            half = struct.unpack("<h", candidate[i + 2:i + 4])[0]
            target = at + 4 + half * 2
            proofs.append({"address": f"0x{at:08x}", "kind": "ifeq", "target": f"0x{target:08x}", "reach_bytes": target - (at + 4), "status": "PASS"})
            i += 4
            continue
        w = int.from_bytes(candidate[i:i + 2], "little")
        if candidate[i:i + 2] == b"\x80\xff":
            i += 6
            continue
        if (w & 0xFFC0) == 0xFFC0:
            i += 6
            continue
        if i + 4 <= len(candidate) and candidate[i + 1] == 0xE1:
            i += 4
            continue
        if candidate[i:i + 4] == bytes.fromhex("2000b000"):
            i += 4
            continue
        if (w & 0xF887) == 0xF880:
            w2 = int.from_bytes(candidate[i + 2:i + 4], "little")
            half = w2 & 0x1FF
            if half & 0x100:
                half -= 0x200
            target = at + 4 + half * 2
            proofs.append({"address": f"0x{at:08x}", "kind": "jne_imm7", "target": f"0x{target:08x}", "reach_bytes": target - (at + 4), "status": "PASS"})
            i += 4
            continue
        if (w & 0x80FF) == 0x8004:
            target = at + 2 + ((w >> 8) & 0x1F) * 2
            proofs.append({"address": f"0x{at:08x}", "kind": "forward_goto", "target": f"0x{target:08x}", "reach_bytes": target - (at + 2), "status": "PASS"})
            i += 2
            continue
        if candidate[i:i + 2] == b"\x80\xff":
            i += 6
        elif (w & 0xFFC0) == 0xFFC0:
            i += 6
        elif i + 4 <= len(candidate) and candidate[i + 1] == 0xE1:
            i += 4
        elif candidate[i:i + 4] == bytes.fromhex("2000b000"):
            i += 4
        else:
            i += 2
    return proofs


def main() -> int:
    for key, path in [("official_app_sha256", OFFICIAL_APP), ("h2_app_sha256", H2_APP), ("h2_manifest_sha256", H2_MANIFEST)]:
        require(path.exists(), f"missing {path}")
        require(sha256_path(path) == EXPECTED[key], f"unexpected hash for {path}")

    h2 = H2_APP.read_bytes()
    require(len(h2) == APP_SIZE, "H2 app size")
    producer, layout, insns = build_producer()
    require(len(producer) <= MAX_BYTES, "candidate size budget")
    require(layout["end"] <= PRODUCER_END_LIMIT, "candidate does not reach official handler")
    require(PRODUCER_START >= GAP_END and PRODUCER_START >= SELECTOR_END, "candidate starts after selector and gap")
    require(layout["end"] <= OFFICIAL_HANDLER, "candidate ends before official handler")
    require(h2[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL) + 4] == short_call(DIRECT_PRODUCT_CALL, PRODUCER_START), "H2 direct product calls producer")
    require(h2[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL) + 4] == short_call(SEGMENTED_PRODUCT_CALL, PRODUCER_START), "H2 segmented product calls producer")
    require(h2[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL) + 4] == bytes.fromhex("bfeaf838"), "direct reload preserved in H2 parent")
    require(h2[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL) + 4] == bytes.fromhex("bfeade38"), "segmented reload preserved in H2 parent")

    old_covered = h2[off(PRODUCER_START):off(PRODUCER_START) + len(producer)]
    evidence: dict[str, Any] = {
        "format": FORMAT,
        "decision": "CANDIDATE",
        "candidate_created": True,
        "artifact_scope": "analysis-only producer bytes; no app.bin, FWSC, ZIP, device, flash, OTA, or rollback",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "candidate_start": f"0x{PRODUCER_START:08x}",
        "candidate_end_exclusive": f"0x{layout['end']:08x}",
        "candidate_size": len(producer),
        "max_size": MAX_BYTES,
        "size_margin": MAX_BYTES - len(producer),
        "replaced_h2_producer_range": "0x0201e1a2..0x0201e1ec",
        "residual_tail_available": "0x0201e1ec..0x0201e254",
        "residual_tail_used_bytes": max(0, layout["end"] - 0x0201E1EC),
        "forbidden_ranges_untouched": {
            "selector": "0x0201e13e..0x0201e19e",
            "gap": "0x0201e19e..0x0201e1a2",
            "official_handler_entry": "0x0201e254",
        },
        "source_hashes": {
            str(OFFICIAL_APP.relative_to(ROOT)): sha256_path(OFFICIAL_APP),
            str(H2_APP.relative_to(ROOT)): sha256_path(H2_APP),
            str(H2_MANIFEST.relative_to(ROOT)): sha256_path(H2_MANIFEST),
            str(STOCK_HELPERS_REPORT.relative_to(ROOT)): sha256_path(STOCK_HELPERS_REPORT),
            str(PROTOCOL_REPORT.relative_to(ROOT)): sha256_path(PROTOCOL_REPORT),
        },
        "producer_abi": {
            "entry_r0": "accepted product staging pointer",
            "entry_length_register": "not proven at producer entry",
            "entry_route_state": "not proven at producer entry",
            "packet_route_length_gate": "omitted because ABI evidence is absent; existing official/H2 product callsites are the only admitted entry source",
            "saved_register_shape": "push/pop rets,r9..r4, matching H2 producer",
            "h2_accepted_packet_ingress_preserved": True,
            "h2_publication_policy_changed_by_s1c2_requirement": "one-slot immediate valid0 is replaced with two-slot LOADING then ARMED publication",
            "trylock_fail_unlocks": False,
            "trylock_fail_unlock_reason": "no lock was acquired; clearing lock on trylock failure would break nonblocking H2 semantics",
            "all_acquired_exits_unlock": True,
        },
        "memory_contract": {
            "slot0": f"0x{SLOT0:08x}..0x{VALID0:08x}",
            "valid0": f"0x{VALID0:08x}",
            "lock": f"0x{LOCK:08x}",
            "note0": f"0x{NOTE0:08x}",
            "state": f"0x{STATE:08x}",
            "slot1": f"0x{SLOT1:08x}..0x{VALID1:08x}",
            "valid1": f"0x{VALID1:08x}",
            "note1": f"0x{NOTE1:08x}",
            "fixed_notes": [FIXED_NOTE0, FIXED_NOTE1],
            "states": {"EMPTY": EMPTY, "LOADING": LOADING, "ARMED": ARMED},
        },
        "candidate_sha256": sha256_bytes(producer),
        "candidate_hex": producer.hex(),
        "old_h2_bytes_covered_sha256": sha256_bytes(old_covered),
        "old_h2_bytes_covered_hex": old_covered.hex(),
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "instruction_ledger": insns,
        "branch_proofs": branch_proofs(producer),
        "listing_rows": {
            "quarkslab": listing_rows(QUARK_LISTING, {DIRECT_PRODUCT_CALL, SEGMENTED_PRODUCT_CALL, DIRECT_RELOAD_CALL, SEGMENTED_RELOAD_CALL, OFFICIAL_HANDLER}),
            "kagaimiq": listing_rows(KAGA_LISTING, {DIRECT_PRODUCT_CALL, SEGMENTED_PRODUCT_CALL, DIRECT_RELOAD_CALL, SEGMENTED_RELOAD_CALL, OFFICIAL_HANDLER}),
        },
    }

    (HERE / "producer.bin").write_bytes(producer)
    (HERE / "producer.hex").write_text(producer.hex() + "\n", encoding="utf-8")
    (HERE / "decode.tsv").write_text(render_decode(insns), encoding="utf-8")
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (HERE / "report.md").write_text(render_report(evidence), encoding="utf-8")
    print(f"candidate bytes: {len(producer)} / {MAX_BYTES}")
    print(f"range: 0x{PRODUCER_START:08x}..0x{layout['end']:08x}")
    print(f"sha256: {sha256_bytes(producer)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
