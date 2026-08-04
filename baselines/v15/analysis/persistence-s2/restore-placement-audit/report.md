# S2 restore placement audit: BLOCK

## Decision

**BLOCK.** No firmware candidate, FWSC, rollback bundle, exact OTA executable, or host/device writer is emitted.

The exact live S1C5 selector (`88` bytes, `900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f`) and producer (`188` bytes, `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438`) are preserved as the controlling baseline. Preserving them leaves only `2` tail bytes in the owned hot window. The audited split-call alternatives do not provide both a safe lifecycle hook and enough proven executable space for manifest/magic/CRC-gated persistent restore.

## Exact dead/cave region audit

| Region | Range | Bytes | Decision |
|---|---:|---:|---|
| current S1C5 SAVE tail dead after 0x02026da6 goto | `0x02026da8..0x02026dd4` | 44 | BLOCK for manifest/magic/CRC restore; 44 bytes cannot hold checked manifest read, CRC, 16-payload validation, RAM publication, and ABI repair |
| SAVE handler quarantined leaf after UI branch patch | `0x02026d80..0x02026dd4` | 84 | PARTIAL only; 84 bytes can host a tiny leaf, but prior lower bounds still exclude positive CRC-gated restore/write semantics |
| stock local SAVE exit retained | `0x02026dd4..0x02026dde` | 10 | NOT A CAVE; must remain stock exit if SAVE handler is quarantined |
| app-area tail / cfg_tool.bin | `0x02096a34..0x02096bb3` | 383 | BLOCK; named JLFS cfg_tool.bin occupies the whole 383-byte apparent tail, preserving JLFS leaves 0 bytes |

Summary: No exact audited dead region provides a sufficient executable body for manifest/magic/CRC-gated restore while keeping S1C5 selector/producer exact.

Exact official exhaustive-listing gap scan: `5735` gaps totaling `31342` bytes through coverage end `0x02057000`. Largest gap is `0x02016a88..0x02016ce2` (602 bytes). Decision: NOT PROMOTED; exhaustive-listing holes/gaps are not exact dead-code ownership proof and may be data, alignment, indirect targets, or resources.

## Callable stock helper audit

| Helper | Entry | Bytes | Official listing call xrefs | Decision |
|---|---:|---:|---:|---|
| read wrapper | `0x02004870` | 20 | 30 | CALLABLE but not a validity gate |
| write wrapper | `0x02004b02` | 20 | 32 | CALLABLE only with readback/compare/commit-last wrapper |
| memcpy | `0x02048cce` | - | 149 | CALLABLE for copies, not a compare or CRC helper |

Search counts in the exact official exhaustive listing for callable CRC/compare labels/text: `{'crc': 0, 'memcmp': 0, 'strcmp': 0, 'strncmp': 0, 'compare': 0}`. Result: BLOCK; no exact callable firmware CRC ABI was identified by the exhaustive-listing labels/text, and no compact in-place PI32 CRC implementation is proven. BLOCK; no exact callable memcmp/compare ABI was identified; magic compare would need hand-coded byte loads/branches and CRC still remains.

## Cross-cave reach and cold UI paths

6-byte `call32` reach to the SAVE cave is numerically possible, for example prior encodings `0x0201e190 -> 0x02026d80 = 80ffea8b0000` and `0x0201e228 -> 0x02026d80 = 80ff528b0000`. Reach is not sufficient because exact S1C5 has no hot-window call insertion budget.

| Site | Decision |
|---:|---|
| `0x02005f9c` | REJECT; disproven/revoked S1C7/R01d-style early boot behavior must not be reused |
| `0x02005fa4` | BLOCK; syntactically after stock reads/loader, but pre-USB/live safety and wrapper placement are unproven and it must preserve 0x020057e0 |
| `0x0202422e` | BLOCK; user-action UI bank/preset reload, not autonomous restore, and repurposing would break stock UI behavior |
| `0x020255a6` | BLOCK; conditional default-load/bank-block path with storage side effects, not an every-boot or side-effect-free restore hook |
| `0x02026d80` | PARTIAL; can be quarantined as an 84-byte leaf only after disabling the current UI SAVE body, but no caller/space for full manifest CRC restore exists |

Summary: Branch reach is not the blocker for 6-byte call32. The blockers are exact S1C5 call insertion, insufficient quarantined bytes, missing CRC/compare ABI, and no approved lifecycle hook.

## Split-call architecture outcome

All audited split-call architectures remain blocked:

- **exact selector/producer plus SAVE-cave restore leaf**: no exact call insertion point remains without altering selector/producer or note hook ABI; 84-byte leaf cannot validate manifest CRCs and publish 16 slots
- **post-storage boot wrapper plus SAVE-cave body**: 0x02005fa4 has no live post-USB safety proof and still needs a wrapper preserving stock 0x020057e0 plus body placement beyond 84 bytes
- **relocated cold UI reload/default-load path**: not autonomous or not side-effect-free; repurposing changes UI/default behavior and still lacks CRC/materializer placement
- **S1C7 not-ARMED helper reuse**: explicitly rejected; S1C7 trusted full-length unseeded reads and gave invalid persistent fallback priority over exact S1C5 behavior

Next discriminator: A minimal standalone PI32 manifest validator/materializer must be assembled and byte-counted against two explicit budgets: 84-byte quarantined SAVE leaf and a separately proved >=300-byte executable region. It must use 0x02004870 length checks, implement or call a proven CRC/compare routine, validate manifest first, publish RAM valid-last/ARMED-last, and leave exact S1C5 selector/producer bytes unchanged. Without that byte-level body and a safe lifecycle hook, no FWSC should be emitted.

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/restore-placement-audit/analyze_restore_placement.py --check
python3 baselines/v15/analysis/persistence-s2/restore-placement-audit/validate.py
(cd baselines/v15/analysis/persistence-s2/restore-placement-audit && shasum -a 256 -c SHA256SUMS)
```
