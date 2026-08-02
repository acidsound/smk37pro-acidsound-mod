# R03 owned-RAM copy-path design, official v15

Decision: **BLOCK**.

This report designs the smallest producer/consumer shape that would satisfy the R03 copy-path requirements, then blocks it because two mandatory proofs are missing: no owned RAM destination is proven, and no executable placement is proven that preserves stock `0x0201e13e` SAVE/SysEx behavior. No cave, patch, flash package, or device operation is chosen.

## Scope and gates

- Requirements read: `baselines/v15/analysis/r03-owned-ram/requirements.md`.
- Inputs are exact official v15 only.
- app SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- FWSC SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`.
- Quarkslab listing SHA-256: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347`.
- Kagaimiq listing SHA-256: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`.
- No v12, M08, R01d boot-hook, arbitrary SysEx fuzzing, PCM, UI, persistence, flashing, or device access was used.

## Smallest viable design contract, not patch-ready

### Producer

Patch concept if and only if a later review proves owned RAM and executable placement:

1. Replace only the one-shot complete-product call at `0x0201e468` with a call to a producer wrapper. Do not use a boot hook.
2. At entry, the stock handler has already copied `message+6` to `0x01c37030+0x0fa0 == 0x01c37fd0`, verified final `F7`, and put `r0 = 0x01c37fd0`.
3. The wrapper additionally requires `r9 == 0xa3` so only `F0 43 00 00 01 1B` + exactly `0x9c` payload bytes + `F7` publishes Ch10-owned data.
4. If `active_count != 0`, do not copy and do not publish. Still tail-call or call/return through stock `0x0201e13e` so stock product SysEx behavior is preserved.
5. If `active_count == 0`, copy exactly `0x9c` bytes from staging to owned destination, then increment `generation`, then set `valid = 1`. Publication occurs only after the copy completes.
6. Call stock `0x0201e13e` after the R03 copy decision, then return to the existing `0x0201e46c` stock reload path. This preserves stock product storage/reload semantics.
7. Leave the segmented-final product caller `0x0201e49c` and SAVE caller `0x02026dac` stock for the minimal R03 contract. Segmented/partial/unsupported packets therefore do not publish Ch10-owned data and continue stock behavior.

### Owned destination metadata required by Gate A

Minimum layout that must be proven before a Flash candidate exists:

| Offset | Size | Meaning | Publication rule |
|---:|---:|---|---|
| `+0x00` | `0x9c` | immutable Ch10 voice source | written before metadata publish |
| `+0x9c` | `1` | `valid` | `0` at reset, `1` only after full copy |
| `+0x9d` | `1` | `active_count` | increment/decrement only on accepted Ch10 Note On/Off wrapper path |
| `+0x9e` | `2` | reserved/alignment | zero or reserved |
| `+0xa0` | `4` | `generation` | increment after copy, before valid publish |

Required alignment: at least 4-byte aligned so generation can be read/written atomically under the firmware's normal aligned word conventions. Required span: `0xa4` bytes minimum. This report does not assign a start/end address because doing so from absence of xrefs would violate Gate A.

### Consumer

1. Redirect both dispatcher copy callsites, not Note On alone: Note Off `0x0201c63e`, Note On `0x0201c67c`.
2. Preserve stock ABI: wrapper receives `r0 = per-voice destination`, `r1 = stock current source`, `r2 = 0x9c`, and `r9 = MIDI channel nibble`; non-Ch10 calls `memcpy(r0, r1, 0x9c)` unchanged.
3. For Ch10 with `valid == 1`, call `memcpy(r0, owned_voice, 0x9c)`. For invalid state, fall back to stock Ch10 source or suppress deterministically. This report chooses stock fallback for smallest allocator-neutral behavior, but this remains a design choice to review before patching.
4. Use separate Note On and Note Off entrypoints or callsite identity so `active_count` can be incremented on accepted Ch10 Note On and decremented after accepted Ch10 Note Off. This prohibits producer generation changes while a Ch10 note is active.
5. Do not alter the voice allocator, claimed polyphony, or Ch1 path.

## Proven callsites and callers

| Function / callsite | Evidence | R03 implication |
|---|---|---|
| `0x0201e468` | one-shot product path calls stock packer after staging and `F7` gate | only plausible minimal producer hook |
| `0x0201e49c` | segmented-final path calls stock packer after accumulated length/F7 checks | leave stock in minimal R03 so partial/segmented does not publish |
| `0x02026dac` | UI SAVE path calls stock packer | must remain stock or SAVE is regressed |
| `0x0201e46c`, `0x0201e4a0` | post-packer stock reload calls | preserved when producer wrapper calls stock packer |
| `0x0201c63e` | Note Off `memcpy` call with `r2 = 0x9c` | redirect with same source rule as Note On |
| `0x0201c67c` | Note On `memcpy` call with `r2 = 0x9c` | redirect with same source rule as Note Off |
| `0x0201c736`, `0x0201e644` | only static callers of dispatcher in listing | caller inventory for hot consumer path |

Stock `0x0201e13e` callers from the listing:

- `0201e468` `bfea69fe` call 0x0201e13e (FUN_0201e254@0201e254)
- `0201e49c` `bfea4ffe` call 0x0201e13e (FUN_0201e254@0201e254)
- `02026dac` `bfeac7b9` call 0x0201e13e (-)

Loader `0x02005660` callers from the listing:

- `02005f9c` `bfea60fb` call 0x02005660 (-)
- `0201e46c` `bfeaf838` call 0x02005660 (FUN_0201e254@0201e254)
- `0201e4a0` `bfeade38` call 0x02005660 (FUN_0201e254@0201e254)
- `0202422e` `bfea170a` call 0x02005660 (FUN_020241e0@020241e0)
- `020255a6` `bfea5b00` call 0x02005660 (-)

Dispatcher `0x0201c5ec` callers from the listing:

- `0201c736` `bfea59ff` call 0x0201c5ec (FUN_0201c722@0201c722)
- `0201e644` `bfead2ef` call 0x0201c5ec (FUN_0201e254@0201e254)

## ABI proof

- SysEx producer wrapper entry at `0x0201e468`: official rows show `r0 = r8 = 0x01c37fd0` immediately before the stock packer call. The handler length register `r9` is still live in this basic block because it is used to compute the copied length at `0x0201e44e` and the last-byte check at `0x0201e45c..0x0201e460`. The wrapper must preserve callee-saved registers and call stock `0x0201e13e(r0=stage)` after the R03 copy decision.
- Stock packer ABI: `0x0201e13e` takes `r0 = expanded source`, packs into a stack `0x80` buffer, then calls `0x02004b02` with `r0=packed80`, `r1=selected persistent slot`, `r2=0x80`. This is why replacing it, as R02 did, regresses SAVE unless every caller is handled.
- Consumer wrapper ABI: prior live-booted R01/R02 primitive proves a compact wrapper can preserve `r0`, branch on `r9 == 9`, set `r1` to an alternate source only for Ch10, set `r2 = 0x9c`, call `0x02048cce`, and return through the original dispatcher control flow. R03 must add valid/active metadata around the same source-selection primitive.

## Instruction budget and placement

- Proven compact consumer wrapper budget from R02 manifest: `36` bytes for source selection plus `memcpy`, occupying `0x0201e13e..0x0201e162` in R02. That budget excludes R03 valid/generation/active-count checks.
- R03 producer wrapper cannot use `0x0201e13e` if stock SAVE/SysEx is to be preserved, because `0x0201e13e..0x0201e252` is the stock packer body and has three direct callers including SAVE.
- Stock packer occupied span used for placement accounting: `0x0201e13e..0x0201e252` (`0x114` bytes, end-exclusive).
- No alternate executable cave is proven by these inputs. A later candidate must provide exact start/end, original bytes, all static callers/fallthroughs, execute permissions, sector impact, and a relocation story if any stock code is displaced.
- Therefore exact R03 instruction budget cannot be closed to a placed binary. Treat the producer plus R03-augmented consumer as design-only until placement is proven independently.

## Gate decisions

| Gate | Decision | Reason |
|---|---|---|
| A owned RAM | **BLOCK** | No exact owned start/end/lifetime/reader/writer inventory is proven. Using `0x01c37fd0` is disallowed because it is transient SysEx staging. Any other address would be an unsupported cave guess. |
| B producer | **BLOCK** | The callsite and ABI are proven, but destination and placement are not. The safe repeated-packet policy is defined as no-publish while `active_count != 0`. |
| C consumer/generation | **BLOCK** | Matched Note On/Off callsites are proven and the active-count policy is defined, but metadata storage is not. |
| D offline artifact safety | **BLOCK** | No changed-address manifest, sector inventory, rollback package, deterministic build, or uploader tests were produced because no patch candidate is approved. |
| E live pass | **BLOCK** | No device access was performed or requested. |

## Malformed, partial, repeated, and unsupported behavior

- Malformed or unsupported messages: no R03 publish because the wrapper is reached only from the accepted one-shot callsite and additionally checks `r9 == 0xa3`. Stock behavior continues through stock packer/handler paths where applicable.
- Partial/segmented product packets: no R03 publish in the minimal design because `0x0201e49c` is left stock. This is intentionally conservative.
- Repeated exact one-shot product packet with no active Ch10 note: copy, increment generation, set valid, then preserve stock pack/reload.
- Repeated exact one-shot product packet while Ch10 active: do not copy, do not increment generation, do not clear valid, and still preserve stock pack/reload. Ch10 remains on the old generation until all Ch10 notes are off.

## Validation output

```text
PASS sha256-app: 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055
PASS sha256-package: f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff
PASS sha256-quark: f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347
PASS sha256-kaga: 814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013
PASS requirements-read: /Users/spectrum/Documents/SMK37ProMod/baselines/v15/analysis/r03-owned-ram/requirements.md
PASS official-v15-only: ["build/v15-official-app.bin", "build/SMK-37_Pro_015.fwsc", "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz", "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz", "baselines/v15/analysis/r03-owned-ram/requirements.md", "baselines/v15/analysis/channel-separation-reanalysis/sysex-staging/sysex_staging_trace.json", "baselines/v15/analysis/channel-separation-reanalysis/runtime-source/runtime_source_trace.json", "baselines/v15/analysis/flash-candidates/R02/app-manifest.json"]
PASS row-0x0201e3ee: lb.z r0,[r7 + 0x206]
PASS row-0x0201e3f8: lb.z r0,[r7 + 0x104]
PASS row-0x0201e448: add r8,r6,#0xfa0
PASS row-0x0201e456: call 0x02048cce
PASS row-0x0201e462: jne r0,#0xf7
PASS row-0x0201e466: mov r0,r8
PASS row-0x0201e468: call 0x0201e13e
PASS row-0x0201e46c: call 0x02005660
PASS row-0x0201e484: jne r5,#0x9e
PASS row-0x0201e494: call 0x02048cce
PASS row-0x0201e49c: call 0x0201e13e
PASS row-0x0201e4a0: call 0x02005660
PASS row-0x0201e580: add r0,r6,#0xfa0
PASS row-0x0201e58c: call 0x02048cce
PASS row-0x0201e634: sb r1,[r0 + r2]
PASS row-0x0201e644: call 0x0201c5ec
PASS row-0x0201c63a: mov r2,#0x9c
PASS row-0x0201c63e: call 0x02048cce
PASS row-0x0201c678: mov r2,#0x9c
PASS row-0x0201c67c: call 0x02048cce
PASS row-0x0201e236: call 0x02004b02
PASS row-0x02026dac: call 0x0201e13e
PASS stock-packer-callers-exact: 0x0201e468,0x0201e49c,0x02026dac
PASS loader-callers-include-stock-sysex-reloads: 0x02005f9c,0x0201e46c,0x0201e4a0,0x0202422e,0x020255a6
PASS dispatcher-callers-exact: 0x0201c736,0x0201e644
PASS r02-wrapper-length-known: {"entry": "0x0201e13e", "end": "0x0201e162", "wrapper_bytes": 36, "note_on_memcpy": "0x0201c67c", "note_off_memcpy": "0x0201c63e", "source_length": 156}
PASS stage-arithmetic: 0x01c37030+0x0fa0=0x01c37fd0
PASS gate-a-block-recorded: No exact owned RAM start/end, owner, lifetime, initialization, and complete alias exclusion are proven. 0x01c37fd0 is transient staging, not owned R03 storage.
PASS placement-block-recorded: The only live-booted compact wrapper placement reused 0x0201e13e, but preserving stock SAVE/SysEx requires retaining the stock packer body and all three callers. No alternate executable cave is proven.
PASS no-patch-output: copy-path directory contains no firmware binary/package outputs
```
