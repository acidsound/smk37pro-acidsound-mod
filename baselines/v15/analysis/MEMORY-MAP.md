# v15 Memory Map and Placement Status

Date: 2026-08-04  
Scope: official v15 and the live-validated S1C5 baseline. This is a navigation and decision document for future memory/placement work. It does **not** promote any unreviewed listing gap to free space.

## 1. Baseline and address model

| Item | Value | Status / source |
|---|---:|---|
| Runtime/XIP base | `0x02000000` | Strongly supported by v15 internal pointers and the app/XIP analysis |
| Official app runtime range | `0x02000000..0x02096a34` | Official app image mapping |
| Official app file size | `0x96a34` | `patch-set-ui/s1c2-unblock/app-extension/report.md` |
| S1C5 app SHA-256 | `8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189` | Live-validated S1C5 candidate |
| S1C5 FWSC SHA-256 | `0a6ac1ae7d4bd34e252eb8f23a4d2c5f39d7454376ade1a3b75ff7d03155ea91` | Live-validated S1C5 candidate |

Address ranges are written end-exclusive unless explicitly stated otherwise.

## 2. Placement decision legend

- **OCCUPIED**: exact code/data ownership is established. Do not overwrite.
- **BLOCKED**: a possible cave or hook was considered, but safe use is not proven or the byte budget is insufficient.
- **REFUTED**: an apparent listing gap was independently audited and shown to contain reachable/continuation code or data. It is not free space.
- **PARTIAL**: a narrow use may be possible under an explicit prerequisite, but it cannot support the requested persistence design.
- **UNREVIEWED**: not individually audited. It must not be used.

## 3. Exact v15/S1C5 code and hook regions

| Runtime range | Size | Classification | Evidence and consequence |
|---|---:|---|---|
| `0x0201e13e..0x0201e254` | 278 B | **OCCUPIED / S1C5 hot window** | Contains the exact selector and producer used by direct and segmented Ch10 paths. The preserved selector/producer consume 276 B, leaving only a 2-byte tail. No persistence helper can be inserted without changing the proven S1C5 path. See `flash-candidates/S1C5-playback-register-return/report.md` and `persistence-s2/restore-placement-audit/report.md`. |
| `0x02026d80..0x02026dd4` | 84 B | **PARTIAL / BLOCKED** | Can become a small callable leaf only after the UI SAVE branch at `0x02026d7a` is changed. It cannot hold manifest/magic/CRC validation, readback, segmented/reset support, and safe publication. See `persistence-s2/save-cave-helper/report.md`. |
| `0x02026da8..0x02026dd4` | 44 B | **BLOCKED** | Dead after the current SAVE `goto`, but too small for a checked persistence/materialization body. |
| `0x02026dd4..0x02026dde` | 10 B | **OCCUPIED** | Stock local SAVE exit. Must remain intact. |
| `0x02005f9c` | call site | **REJECTED** | Early post-init/boot hook used by withdrawn R01d/S1C7-style approaches. It is not an approved persistence lifecycle hook. |
| `0x02005fa4` | call site | **BLOCKED** | Post-storage hook is syntactically plausible but lacks live/post-USB safety proof and must preserve the stock `0x020057e0` path. |
| `0x0202422e` | call site | **BLOCKED** | User-action UI bank/preset reload path, not autonomous boot restore. Repurposing would alter stock UI behavior. |
| `0x020255a6` | call site | **BLOCKED** | Conditional default-load path with storage side effects. Not proven to be an every-boot, side-effect-free restore hook. |

## 4. Apparent large listing gaps, now audited

These four regions were initially ranked as the largest apparent gaps. Their dedicated audits now refute treating them as free placement.

| Runtime range | Size | Final status | Positive reason it is not free | Evidence |
|---|---:|---|---|---|
| `0x02016a88..0x02016ce2` | 602 B | **REFUTED** | Normal fall-through continuation after `0x02016a84: call 0x0200ad74`; Kagaimiq decodes 148 rows, with internal branches and returns. | `persistence-s2/gap-02016a88-audit/report.md` |
| `0x02039be6..0x02039e2a` | 580 B | **REFUTED** | TBH switch-table entry at `0x020399a2` targets the range; Quarkslab recursively decodes 186 rows and covers 576/580 bytes. | `persistence-s2/gap-02039be6-audit/report.md` |
| `0x0202bc62..0x0202be5a` | 504 B | **REFUTED** | Region lies inside `FUN_0202bc22`; recursive decode covers 164 rows and ends at the live function epilogue. | `persistence-s2/gap-0202bc62-audit/report.md` |
| `0x02007248..0x02007390` | 328 B | **REFUTED** | Recursive decode starts at the apparent gap and covers 133 rows; the range is a continuation after `0x02007242: call 0x02063260`. | `persistence-s2/gap-02007248-audit/report.md` |

The earlier 602-byte candidate was therefore not merely “unconfirmed”. It has a dedicated refutation. The same is now true of the other three large candidates.

## 5. App tail and container boundaries

| Range / boundary | Size | Classification | Reason |
|---|---:|---|---|
| `0x02096a34..0x02096bb3` | 383 B | **OCCUPIED / `cfg_tool.bin`** | The first byte after `app.bin` is the start of named JLFS `cfg_tool.bin`. Extending `app.bin` would overwrite a stock file. |
| `0x02096bb3..0x02097ee0` | 4909 B | **BLOCKED / protected post-app** | Outside the `app_area_head` CRC envelope. Runtime executability and ownership are not proven. |
| UFW `flash.bin` end `0x9c000` to next `USR` entry | 0 B | **BLOCKED** | The next UFW payload entry starts immediately; growing `flash.bin` collides with `USR`. |

Source: `patch-set-ui/s1c2-unblock/app-extension/report.md`.

## 6. Runtime RAM and storage objects

These are data/state locations, not executable placement candidates.

| Object | Address / shape | Classification |
|---|---|---|
| S1C5 runtime object | base around `0x01c33260` | **OCCUPIED / live state** |
| Current materialized snapshot | around `0x01c34c74`, `0x9c`-byte payload | **OCCUPIED / source state** |
| SysEx staging | `0x01c37fd0` | **OCCUPIED / ingress staging** |
| Raw record store | physical storage around `0x0f8000`, 128 records × `0xa3` | **OCCUPIED / persistent stock format** |
| Bank D 1–16 logical records | raw records 96–111 | **OCCUPIED / stock records** |

The raw records preserve a seven-byte tail at `0x9c..0xa2`. Current evidence does not prove any raw record is free for private metadata. Any persistent design must preserve the raw tails and use a checked read/write/compare/commit-last lifecycle.

## 7. Stock storage helpers and their limits

| Helper | Entry | Use | Limitation |
|---|---:|---|---|
| Read wrapper | `0x02004870` | Full-length storage read | Not a validity or CRC gate by itself |
| Write wrapper | `0x02004b02` | Full-length storage write | Must require `return == len`, then read back and compare |
| memcpy | `0x02048cce` | Copying | Not a compare or CRC helper |

No exact callable v15 `memcmp` or CRC ABI has been established in the current listing evidence. A safe persistence writer therefore still needs a separately proven implementation or a newly proven helper.

## 8. Coverage boundary and remaining work

The official exhaustive listing contains 5,735 apparent gaps totaling 31,342 bytes through `0x02057000`. The four largest apparent gaps listed in Section 4 are now refuted. This does **not** mean every smaller gap has been individually analyzed or is safe.

For any future candidate, the minimum promotion checklist is:

1. Prove a real code/data boundary and positive ownership, not just a disassembler gap.
2. Check recursive decode, branch/TBH reach, call/return continuation, xrefs, and container ownership.
3. Prove an exact lifecycle hook and register/return ABI.
4. Assemble the complete body and compare its byte count with the proven range.
5. Preserve exact S1C5 selector/producer and direct/segmented/reset behavior.
6. For persistence, require valid-first/ARMED-last publication, full-length write/read checks, compare/CRC or an exact proven equivalent, and rollback.
7. Only then build app/FWSC/OTA artifacts and perform independent review and live validation.

## 9. Reproducible evidence commands

```sh
python3 baselines/v15/analysis/persistence-s2/gap-02016a88-audit/validate.py
python3 baselines/v15/analysis/persistence-s2/gap-02039be6-audit/validate.py
python3 baselines/v15/analysis/persistence-s2/gap-0202bc62-audit/validate.py
python3 baselines/v15/analysis/persistence-s2/gap-02007248-audit/validate.py
python3 baselines/v15/analysis/persistence-s2/restore-placement-audit/validate.py
python3 baselines/v15/analysis/persistence-s2/save-cave-helper/analyze_save_cave_helper.py
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/app-extension/analyze_app_extension.py
```

## 10. Explicit non-claims

- This document does not claim that any unreviewed smaller gap is free.
- It does not claim that persistence is currently safe or flashable.
- It does not authorize a new OTA or flash operation.
- It records static evidence and live-validated S1C5 boundaries separately; it does not turn offline evidence into live functional evidence.
