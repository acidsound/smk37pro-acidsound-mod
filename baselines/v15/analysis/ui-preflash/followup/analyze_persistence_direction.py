#!/usr/bin/env python3
"""Focused v15 storage-direction analysis for 0x02004b02 -> 0x02004a7a -> 0x02063260.

Scope is deliberately narrow:
- official v15 Quarkslab exhaustive listing only
- no patching, flashing, firmware writes, or git commits
- cfg_tool/USRFLASH strings are not used as proof, only auxiliary hints
"""
from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[5]
OUTDIR = ROOT / "baselines/v15/analysis/ui-preflash/followup"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
EXPECTED_LISTING_SHA256 = "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"

TARGETS = [0x02004B02, 0x02004A7A, 0x02063260]
FOCUS_RANGES = {
    "write_prepare_02004a54": (0x02004A54, 0x02004A78),
    "write_inner_02004a7a": (0x02004A7A, 0x02004B00),
    "write_wrapper_02004b02": (0x02004B02, 0x02004B14),
    "read_inner_comparator_020047d8": (0x020047D8, 0x0200486E),
    "read_wrapper_comparator_02004870": (0x02004870, 0x02004882),
    "io_mode_body_decoder_gap_02004896": (0x02004896, 0x02004A52),
    "save_writer_path_02026d6c": (0x02026D6C, 0x02026DDC),
    "default_bank_load_path_0202553c": (0x0202553C, 0x020255B0),
}

# Manual backward slices from the v15 listing. These are intentionally terse and
# point to exact instructions captured in the JSON contexts.
CALLSITE_02004B02: list[dict[str, Any]] = [
    {
        "call": "0x02005042", "function": "FUN_02004f06", "group": "config block save",
        "r0_source": "0x01c33260+0x2a90 RAM block", "r1_storage": "*(0x01c33260+0x1d4)", "r2_len": "0x224",
        "mode_setup": "0x0200502e..02005032 calls 0x02004a54(mode=2, storage=*(+0x1d4))",
        "return_use": "ignored", "direction": "RAM -> storage write",
        "evidence": ["02005036", "0200503a", "0200503c", "0200503e", "02005042"],
    },
    {
        "call": "0x02005050", "function": "FUN_02004f06", "group": "config trailer save",
        "r0_source": "sp+0x24 8-byte local trailer", "r1_storage": "*(0x01c33260+0x1d4)+0x224", "r2_len": "0x8",
        "mode_setup": "same prepared region as 0x02005042", "return_use": "ignored", "direction": "RAM -> storage write",
        "evidence": ["02005046", "02005048", "0200504c", "0200504e", "02005050"],
    },
    {
        "call": "0x0200514a", "function": "FUN_0200506a", "group": "descriptor/header save",
        "r0_source": "sp+0x4 local descriptor copied from +0x494 and tagged 0x3aa3", "r1_storage": "*(0x01c33260+0x20c)", "r2_len": "0x86",
        "mode_setup": "none adjacent", "return_use": "ignored", "direction": "RAM -> storage write",
        "evidence": ["02005130", "02005132", "02005134", "0200513a", "02005142", "02005146", "02005148", "0200514a"],
    },
    {
        "call": "0x02005528", "function": "FUN_02005512", "group": "current bank/preset selection save",
        "r0_source": "0x01c33260+0x3a0 selection bytes", "r1_storage": "*(0x01c33260+0x160)+0x9200", "r2_len": "0x9",
        "mode_setup": "none adjacent", "return_use": "ignored", "direction": "RAM -> storage write",
        "evidence": ["02005514", "0200551a", "0200551e", "02005522", "02005526", "02005528"],
    },
    {
        "call": "0x020064ba", "function": "unlabeled block", "group": "default image block 0",
        "r0_source": "r6 default/source image base", "r1_storage": "*(0x01c33260)+0x0", "r2_len": "0x49e3",
        "mode_setup": "0x02006440..020064ac prepares multiple sectors; mode 1 for first two, mode 2 for following sectors",
        "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02006420", "02006430", "02006432", "020064b0", "020064b4", "020064b8", "020064ba"],
    },
    {
        "call": "0x020064c8", "function": "unlabeled block", "group": "default image block 1",
        "r0_source": "r6+0x49e3", "r1_storage": "*(0x01c33260)+0x5000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["020064be", "020064c0", "020064c2", "020064c6", "020064c8"],
    },
    {
        "call": "0x020064dc", "function": "unlabeled block", "group": "default image block 2",
        "r0_source": "r6+0x93c6", "r1_storage": "*(0x01c33260)+0xa000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["020064cc", "020064d2", "020064d4", "020064d6", "020064da", "020064dc"],
    },
    {
        "call": "0x020064f0", "function": "unlabeled block", "group": "default image block 3",
        "r0_source": "r6+0xdda9", "r1_storage": "*(0x01c33260)+0xf000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["020064e0", "020064e6", "020064e8", "020064ea", "020064ee", "020064f0"],
    },
    {
        "call": "0x02006504", "function": "unlabeled block", "group": "default image block 4",
        "r0_source": "r6+0x1278c", "r1_storage": "*(0x01c33260)+0x14000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["020064f4", "020064fa", "020064fc", "020064fe", "02006502", "02006504"],
    },
    {
        "call": "0x02006518", "function": "unlabeled block", "group": "default image block 5",
        "r0_source": "r6+0x1716f", "r1_storage": "*(0x01c33260)+0x19000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02006508", "0200650e", "02006510", "02006512", "02006516", "02006518"],
    },
    {
        "call": "0x0200652c", "function": "unlabeled block", "group": "default image block 6",
        "r0_source": "r6+0x1bb52", "r1_storage": "*(0x01c33260)+0x1e000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0200651c", "02006522", "02006524", "02006526", "0200652a", "0200652c"],
    },
    {
        "call": "0x02006540", "function": "unlabeled block", "group": "default image block 7",
        "r0_source": "r6+0x20535", "r1_storage": "*(0x01c33260)+0x23000", "r2_len": "0x49e3",
        "mode_setup": "sector prepare sequence at 0x02006440..020064ac", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02006530", "02006536", "02006538", "0200653a", "0200653e", "02006540"],
    },
    {
        "call": "0x02006552", "function": "unlabeled block", "group": "default image usrdata marker",
        "r0_source": "sp+0x50 containing ASCII usrdata", "r1_storage": "*(0x01c33260)+0x27ff8", "r2_len": "0x8",
        "mode_setup": "after block-image writes", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02006420", "02006426", "0200642c", "02006544", "02006546", "0200654e", "02006550", "02006552"],
    },
    {
        "call": "0x0201dfe8", "function": "unlabeled block", "group": "config block save duplicate path",
        "r0_source": "0x01c33260+0x2a90", "r1_storage": "*(0x01c33260+0x1d4)", "r2_len": "0x224",
        "mode_setup": "0x0201dfd2..0201dfd6 calls 0x02004a54(mode=2, storage=*(+0x1d4))", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0201dfda", "0201dfde", "0201dfe2", "0201dfe4", "0201dfe8"],
    },
    {
        "call": "0x0201dff8", "function": "unlabeled block", "group": "config trailer save duplicate path",
        "r0_source": "sp+0x0 local marker trimdat", "r1_storage": "*(0x01c33260+0x1d4)+0x224", "r2_len": "0x8",
        "mode_setup": "same prepared region as 0x0201dfe8", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0201dfb0", "0201dfbc", "0201dfec", "0201dff0", "0201dff4", "0201dff6", "0201dff8"],
    },
    {
        "call": "0x0201e236", "function": "unlabeled block", "group": "packed patch/current record default-load save",
        "r0_source": "sp scratch buffer built by 0x0201e13e", "r1_storage": "*(0x01c33260+0x160)+bank*0x1000+preset*0x80", "r2_len": "0x80",
        "mode_setup": "none adjacent; after call clears +0x129c flag for bank/preset", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0201e216", "0201e222", "0201e22a", "0201e22e", "0201e232", "0201e234", "0201e236", "0201e246"],
    },
    {
        "call": "0x02023338", "function": "FUN_0202330c", "group": "descriptor/header save duplicate path",
        "r0_source": "sp+0x0 local descriptor copied from 0x01c33260+0x161c and tagged 0x3aa3", "r1_storage": "*(0x01c33260+0x20c)", "r2_len": "0x86",
        "mode_setup": "none adjacent", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202331c", "02023320", "02023322", "02023328", "02023330", "02023334", "02023336", "02023338"],
    },
    {
        "call": "0x02024e5c", "function": "FUN_02024e02", "group": "bank image/default bank save",
        "r0_source": "0x01c0de20 + bank*0x49e3", "r1_storage": "*(0x01c33260+0x200)+bank*0x5000", "r2_len": "0x49e3",
        "mode_setup": "0x02024e1c..02024e44 prepares five 0x1000 sectors with mode 2", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02024e0c", "02024e12", "02024e16", "02024e48", "02024e4e", "02024e56", "02024e5a", "02024e5c"],
    },
    {
        "call": "0x02024e84", "function": "FUN_02024e02", "group": "bank image usrdata marker",
        "r0_source": "sp+0x0 ASCII usrdata", "r1_storage": "*(0x01c33260+0x200)+0x27ff8", "r2_len": "0x8",
        "mode_setup": "only on bank index 7", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02024e60", "02024e64", "02024e68", "02024e74", "02024e78", "02024e80", "02024e82", "02024e84"],
    },
    {
        "call": "0x0202556e", "function": "unlabeled UI bank-select path", "group": "default-load selected bank block write",
        "r0_source": "r10+0xfa0 RAM/default bank image", "r1_storage": "*(0x01c33260+0x160)+bank*0x1000", "r2_len": "0x1000",
        "mode_setup": "0x0202555c..02025560 calls 0x02004a54(mode=2, selected-bank storage)", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02025550", "02025558", "0202555a", "0202555c", "02025560", "02025564", "02025568", "0202556c", "0202556e"],
    },
    {
        "call": "0x0202558e", "function": "unlabeled UI bank-select path", "group": "dirty/saved flag table flush after default-load",
        "r0_source": "0x01c33260+0x129c flag table just cleared", "r1_storage": "*(0x01c33260+0x160)+0x9180", "r2_len": "0x80",
        "mode_setup": "after 32-byte flag clear at 0x0202557a..0202557c", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02025572", "0202557a", "0202557c", "02025580", "02025584", "0202558a", "0202558c", "0202558e"],
    },
    {
        "call": "0x02026da6", "function": "unlabeled SAVE writer path", "group": "current patch record save",
        "r0_source": "0x01c33260+0x1a14 current patch snapshot", "r1_storage": "*(0x01c33260+0x160)+0x4000+(bank*32+preset)*0xa3", "r2_len": "0xa3",
        "mode_setup": "none adjacent; save gate +0x1ec==0 and r6!=0xff", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02026d70", "02026d7a", "02026d84", "02026d86", "02026d94", "02026d9a", "02026d9e", "02026da2", "02026da4", "02026da6"],
    },
    {
        "call": "0x02026dd0", "function": "unlabeled SAVE writer path", "group": "dirty/saved flag table flush after SAVE",
        "r0_source": "0x01c33260+0x129c flag table after selected entry is set", "r1_storage": "*(0x01c33260+0x160)+0x9180", "r2_len": "0x80",
        "mode_setup": "after +0x129c[bank*32+preset] = r15", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["02026dba", "02026dbe", "02026dc2", "02026dc6", "02026dcc", "02026dce", "02026dd0"],
    },
    {
        "call": "0x0202b850", "function": "unlabeled tail wrapper", "group": "thin passthrough wrapper",
        "r0_source": "caller-supplied", "r1_storage": "caller-supplied", "r2_len": "caller-supplied",
        "mode_setup": "none; wrapper only pushes/calls/pops", "return_use": "returned to caller", "direction": "RAM -> storage write by callee contract", "evidence": ["0202b84e", "0202b850", "0202b854"],
    },
    {
        "call": "0x0202c64c", "function": "FUN_0202c616", "group": "allocator/metadata marker save",
        "r0_source": "sp+0x0 local marker 0x3154", "r1_storage": "lw [r5++=0x18] from storage metadata structure", "r2_len": "0x4",
        "mode_setup": "0x0202c55c may prepare storage ranges before marker write", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202c61a", "0202c620", "0202c644", "0202c648", "0202c64a", "0202c64c"],
    },
    {
        "call": "0x0202c692", "function": "FUN_0202c674", "group": "chunked copyback write",
        "r0_source": "sp+0x0 temp chunk read by 0x02004870", "r1_storage": "r6 destination storage cursor", "r2_len": "r7 chunk length capped at 0x100",
        "mode_setup": "paired with 0x02004870 read from r8 into temp, then write temp to r6", "return_use": "ignored", "direction": "RAM temp -> storage write", "evidence": ["0202c680", "0202c684", "0202c688", "0202c68c", "0202c68e", "0202c690", "0202c692", "0202c696"],
    },
    {
        "call": "0x0202c6fc", "function": "FUN_0202c6ac", "group": "journal magic write ddeebb77",
        "r0_source": "sp+0x0 local 0xddeebb77", "r1_storage": "metadata pointer loaded from active bank structure", "r2_len": "0x4",
        "mode_setup": "none adjacent", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202c6de", "0202c6ec", "0202c6f0", "0202c6f6", "0202c6f8", "0202c6fa", "0202c6fc"],
    },
    {
        "call": "0x0202c7e6", "function": "FUN_0202c6ac", "group": "journal/current pointer write",
        "r0_source": "sp+0x0 local pointer/value", "r1_storage": "alternate active metadata pointer", "r2_len": "0x4",
        "mode_setup": "inside journal rewrite loop", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202c7dc", "0202c7e0", "0202c7e2", "0202c7e4", "0202c7e6"],
    },
    {
        "call": "0x0202c81e", "function": "FUN_0202c6ac", "group": "journal magic write 55aaaa55",
        "r0_source": "sp+0x0 local 0x55aaaa55/value", "r1_storage": "alternate active metadata pointer", "r2_len": "0x4",
        "mode_setup": "after toggling active slot bit", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202c7fc", "0202c800", "0202c80e", "0202c812", "0202c818", "0202c81c", "0202c81e"],
    },
    {
        "call": "0x0202cc82", "function": "unlabeled compaction path", "group": "chunked copyback write duplicate",
        "r0_source": "r5 temp buffer filled by 0x02004870", "r1_storage": "r14+r11 destination cursor", "r2_len": "r6 chunk length capped at 0x200",
        "mode_setup": "paired with 0x02004870 read from old offset into r5, then 0x02004b02 writes to new offset", "return_use": "ignored", "direction": "RAM temp -> storage write", "evidence": ["0202cc6e", "0202cc72", "0202cc74", "0202cc76", "0202cc7a", "0202cc7e", "0202cc80", "0202cc82"],
    },
    {
        "call": "0x0202cd1e", "function": "unlabeled metadata path", "group": "metadata name/header save",
        "r0_source": "r4 local metadata structure", "r1_storage": "r15 caller-held destination", "r2_len": "0x20",
        "mode_setup": "fills structure with string at 0x0205dc5a and short from 0x020028b0", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202ccfc", "0202cd04", "0202cd0e", "0202cd14", "0202cd18", "0202cd1a", "0202cd1c", "0202cd1e"],
    },
    {
        "call": "0x0202cf30", "function": "FUN_0202cdf2", "group": "formatted object/header save",
        "r0_source": "sp+0x0 local 0x50-byte object", "r1_storage": "r8 destination", "r2_len": "0x50",
        "mode_setup": "0x0202cf1e..0202cf22 calls 0x02004a54(mode=2, storage=r11)", "return_use": "ignored", "direction": "RAM -> storage write", "evidence": ["0202cf1e", "0202cf20", "0202cf22", "0202cf2a", "0202cf2c", "0202cf2e", "0202cf30"],
    },
]

DIRECT_02004A7A = [
    {
        "call": "0x02004b0a", "function": "FUN_02004b02", "argument_order": "r0=source RAM, r1=len, r2=storage", "return_use": "wrapper returns original len if inner r0==len else 0", "direction": "write", "evidence": ["02004b04", "02004b06", "02004b08", "02004b0a", "02004b0c", "02004b10", "02004b12"],
    },
    {
        "call": "0x0202cd66", "function": "FUN_0202cd42", "argument_order": "r0=sp+0x50 local block, r1=0x50 len, r2=storage cursor loaded earlier", "return_use": "ignored then function returns 0", "direction": "write by 0x02004a7a contract", "evidence": ["0202cd52", "0202cd58", "0202cd60", "0202cd64", "0202cd66"],
    },
    {
        "call": "0x0202dd28", "function": "unlabeled chunk writer", "argument_order": "r0=r4 source, r1=r5 len, r2=r6 storage", "return_use": "requires r0==r5, then advances [r7] by r5 and returns r5; else falls through error", "direction": "write", "evidence": ["0202dd24", "0202dd26", "0202dd28", "0202dd2c", "0202dd30", "0202dd34"],
    },
]

DECODER_GAPS = [
    {
        "id": "0x02063260-call-terminator-body",
        "exact_gap": "The Quarkslab/Ghidra listing marks calls to 0x02063260 as CALL_TERMINATOR. For 0x02004a7a, control resumes at 0x02004b00 without an emitted post-call basic block. Registers r7/r10/r6 hold source/len/storage before the call, but the listing does not decode the callee or request-object ABI that consumes them.",
        "impact": "Primitive-level implementation details, device command ID, and internal errno mapping remain unproven from this listing alone.",
    },
    {
        "id": "0x02004896-mode-body-split",
        "exact_gap": "0x02004a54 calls 0x02004896 after table lookup at 0x02057954. The listing shows a body fragment 0x02004902..0x02004a52 after the CALL_TERMINATOR at 0x020048a8, but function ownership is '-' for many rows. That permits a mode/preparation interpretation but not a fully typed device operation decode.",
        "impact": "mode=1/2/3 preparation is visible at callsites, but exact erase/open/commit names are not assigned.",
    },
]

CONCLUSIONS = {
    "wrapper_contract": "0x02004b02 external ABI is (r0=RAM/source buffer, r1=storage offset/address, r2=length). It calls 0x02004a7a as (r0=source, r1=length, r2=storage), then returns length on full success and 0 otherwise.",
    "direction": "0x02004b02 -> 0x02004a7a is statically write/copy-to-storage for all decoded v15 callsites. The paired read wrapper is 0x02004870 -> 0x020047d8, whose post-call path allocates/reads and memcpy()s into r0 destination, providing contrast.",
    "bounds": "0x02004a7a checks storage+length <= *(0x01c454b0+0x18). On overflow it returns 0 before 0x02063260.",
    "save_path": "0x02026d6c saves 0x01c33260+0x1a14 to *(+0x160)+0x4000+(bank*32+preset)*0xa3 for 0xa3 bytes, then sets +0x129c[index] and flushes the 0x80-byte flag table to *(+0x160)+0x9180.",
    "default_load_path": "0x0202553c writes a 0x1000-byte RAM/default bank image to selected-bank storage, clears 32 dirty/saved flags, flushes the 0x80-byte table, updates +0x3a4/+0x3a0, then calls factory loader 0x02005660.",
    "save_failure_path": "The SAVE writer ignores the 0/len return from both 0x02004b02 calls. Therefore wrapper-level failure is detectable in 0x02004b02 but not propagated by 0x02026d6c before marking saved/clearing +0x1ec in the decoded listing.",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_listing() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with gzip.open(LISTING, "rt", errors="replace") as f:
        header = f.readline().rstrip("\n").split("\t")
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) != len(header):
                continue
            row = dict(zip(header, parts))
            row["address_int"] = int(row["address"], 16)
            rows.append(row)
    return rows


def row_text(row: dict[str, Any]) -> str:
    return "\t".join(str(row[k]) for k in ["address", "bytes", "length", "mnemonic", "text", "flow_type", "function"])


def context(rows: list[dict[str, Any]], addr: int, before: int = 12, after: int = 3) -> list[str]:
    for i, row in enumerate(rows):
        if row["address_int"] == addr:
            return [row_text(r) for r in rows[max(0, i - before): min(len(rows), i + after + 1)]]
    return []


def extract_calls(rows: list[dict[str, Any]], target: int) -> list[dict[str, Any]]:
    needle = f"call 0x{target:08x}"
    out = []
    for row in rows:
        if row["text"] == needle:
            out.append({
                "address": f"0x{row['address']}",
                "function": row["function"],
                "flow_type": row["flow_type"],
                "row": row_text(row),
                "context": context(rows, row["address_int"]),
            })
    return out


def extract_ranges(rows: list[dict[str, Any]]) -> dict[str, list[str]]:
    return {
        name: [row_text(r) for r in rows if lo <= r["address_int"] <= hi]
        for name, (lo, hi) in FOCUS_RANGES.items()
    }


def make_json(rows: list[dict[str, Any]]) -> dict[str, Any]:
    listing_sha = sha256(LISTING)
    calls = {f"0x{target:08x}": extract_calls(rows, target) for target in TARGETS}
    call_counts = {target: len(items) for target, items in calls.items()}
    return {
        "format": "smk37-v15-ui-preflash-persistence-direction-v1",
        "scope": "Focused static analysis of 0x02004b02 -> 0x02004a7a -> 0x02063260 only; no patch/flash/commit.",
        "sha_gates": {
            "listing_sha256": listing_sha,
            "listing_expected_sha256": EXPECTED_LISTING_SHA256,
            "listing_pass": listing_sha == EXPECTED_LISTING_SHA256,
        },
        "target_call_counts": call_counts,
        "conclusions": CONCLUSIONS,
        "wrapper_instruction_proof": {
            "0x02004b02": [row_text(r) for r in rows if 0x02004B02 <= r["address_int"] <= 0x02004B14],
            "0x02004a7a": [row_text(r) for r in rows if 0x02004A7A <= r["address_int"] <= 0x02004B00],
            "read_comparator_0x02004870_0x020047d8": [row_text(r) for r in rows if 0x020047D8 <= r["address_int"] <= 0x02004882],
        },
        "callsite_analysis_02004b02": CALLSITE_02004B02,
        "direct_callsite_analysis_02004a7a": DIRECT_02004A7A,
        "all_raw_calls": calls,
        "focus_ranges": extract_ranges(rows),
        "decoder_gaps": DECODER_GAPS,
        "auxiliary_hints_only": ["cfg_tool strings", "USRFLASH/path strings"],
    }


def md_table(headers: list[str], rows: list[list[str]]) -> str:
    def esc(s: str) -> str:
        return str(s).replace("|", "\\|").replace("\n", " ")
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(esc(c) for c in row) + " |")
    return "\n".join(out)


def make_md(data: dict[str, Any]) -> str:
    rows = []
    for c in CALLSITE_02004B02:
        rows.append([c["call"], c["group"], c["r0_source"], c["r1_storage"], c["r2_len"], c["mode_setup"], c["return_use"]])
    direct_rows = []
    for c in DIRECT_02004A7A:
        direct_rows.append([c["call"], c["function"], c["argument_order"], c["return_use"], c["direction"]])
    return f"""# v15 persistence direction follow-up

Scope: official v15 Quarkslab exhaustive listing only. This report focuses only on `0x02004b02 -> 0x02004a7a -> 0x02063260`. It performs no patching, flashing, firmware writes, or git commit. `cfg_tool` and `USRFLASH` strings are treated only as auxiliary hints, not proof.

## SHA gate

- listing: `{data['sha_gates']['listing_sha256']}` ({'PASS' if data['sha_gates']['listing_pass'] else 'FAIL'})

## Conclusion

- `0x02004b02` external ABI is `r0=RAM/source buffer`, `r1=storage offset/address`, `r2=length`.
- `0x02004b02` swaps arguments and calls `0x02004a7a` as `r0=source`, `r1=length`, `r2=storage`.
- `0x02004a7a` enforces `storage + length <= *(0x01c454b0+0x18)`, then calls `0x02063260` with request object `0x01c33260+0xd1c` while preserving `source/length/storage` in `r7/r10/r6`.
- Return mode is count-style: `0x02004b02` returns the requested length only when `0x02004a7a` returns that same length. Otherwise it returns `0`.
- Direction is statically `RAM -> storage` for every decoded v15 caller of `0x02004b02`. The contrasting read path is `0x02004870 -> 0x020047d8`, which later copies from an allocated/read buffer into the caller's destination with `0x02048cce`.
- Primitive-level command names inside `0x02063260` remain a decoder gap because the listing marks it `CALL_TERMINATOR` and does not decode its callee/request ABI.

## Wrapper proof

```text
""" + "\n".join(data["wrapper_instruction_proof"]["0x02004b02"]) + """
```

```text
""" + "\n".join(data["wrapper_instruction_proof"]["0x02004a7a"]) + """
```

Read-wrapper comparator:

```text
""" + "\n".join(data["wrapper_instruction_proof"]["read_comparator_0x02004870_0x020047d8"]) + """
```

## All v15 callers of `0x02004b02`

""" + md_table(["call", "group", "r0 source", "r1 storage", "r2 length", "mode/default-load/save context", "return/error use"], rows) + f"""

Raw xref count: `{data['target_call_counts']['0x02004b02']}`. The JSON stores the original context window for each xref.

## Direct v15 callers of `0x02004a7a`

""" + md_table(["call", "function", "arg order", "return/error use", "direction"], direct_rows) + f"""

Raw xref count: `{data['target_call_counts']['0x02004a7a']}`.

## `0x02063260` caller comparison

Raw direct xref count in v15 listing: `{data['target_call_counts']['0x02063260']}`. JSON includes all raw contexts. Only the focused path caller `0x02004a9e` is used as proof here. Many other callers use `0x02063260` as a general request/scheduler primitive, so they are not assigned storage direction unless they participate in the wrapper path.

## Bounds, default-load, save failure path

- Bounds: `0x02004a7a` loads `r3 = *(0x01c454b0+0x18)`, computes `r1 = storage + length`, preloads `r0=0`, and branches to return if `r1 > r3`.
- Default-load path: `0x0202553c` prepares selected-bank storage with `0x02004a54(mode=2)`, writes `r10+0xfa0` to `*(+0x160)+bank*0x1000` for `0x1000`, clears 32 flags at `+0x129c`, writes that flag table to `*(+0x160)+0x9180` for `0x80`, updates selected bank/preset, then calls factory loader `0x02005660`.
- Save path: `0x02026d6c` gates on `+0x1ec==0` and `r6!=0xff`, writes current snapshot `+0x1a14` to `*(+0x160)+0x4000+(bank*32+preset)*0xa3` for `0xa3`, calls `0x0201e13e`, sets the `+0x129c` entry, flushes `0x80` bytes to `*(+0x160)+0x9180`, then clears/sets `+0x1ec` and exits.
- Save failure path: both SAVE calls ignore the `0/len` return from `0x02004b02`. The wrapper can report failure, but the decoded SAVE path does not branch on it before marking saved or clearing `+0x1ec`.

## Decoder gaps

""" + "\n".join(f"- `{g['id']}`: {g['exact_gap']} Impact: {g['impact']}" for g in DECODER_GAPS) + """

## Reproduction

```sh
python3 baselines/v15/analysis/ui-preflash/followup/analyze_persistence_direction.py
```

Outputs:

- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.md`
- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.json`
"""


def main() -> None:
    rows = load_listing()
    data = make_json(rows)
    OUTDIR.mkdir(parents=True, exist_ok=True)
    (OUTDIR / "persistence-direction.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (OUTDIR / "persistence-direction.md").write_text(make_md(data))
    print(f"wrote {OUTDIR / 'persistence-direction.md'}")
    print(f"wrote {OUTDIR / 'persistence-direction.json'}")
    if not data["sha_gates"]["listing_pass"]:
        raise SystemExit("listing SHA gate failed")


if __name__ == "__main__":
    main()
