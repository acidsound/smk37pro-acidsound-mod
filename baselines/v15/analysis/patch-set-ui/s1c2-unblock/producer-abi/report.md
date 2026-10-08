# S1-C2 producer-entry ABI unblock proof

Date: 2026-08-02 UTC  
Decision: **PASS for the focused no-parser blocker**  
Scope: exact official v15, H2, S1-C1 boundary child, and Quarkslab/Kagaimiq listings only. No candidate, device, OTA, flash, or live packet action was performed.

## Result

An extended producer at `0x0201e1a2` can distinguish the exact accepted route before any H2-owned state mutation:

- Direct product call `0x0201e468`: route is `LR/rets == 0x0201e46c`; exact valid 163-byte packet is `r9 == 0x000000a3`; staging pointer is `r0 == 0x01c37fd0`.
- Segmented final call `0x0201e49c`: route is `LR/rets == 0x0201e4a0`; exact final-total gate remains live as `r5 == 0x0000009e`; staging pointer is `r0 == r6 == 0x01c37fd0`.
- The first current-producer H2-owned mutation is `0x0201e1ae testset b[r0]` on lock `0x01c465bd`, so these checks can run first and reject without changing lock, slot, or valid state.

Therefore the prior no-parser blocker is resolved at this focused ABI discriminator level. This is not a complete S1-C2 parser/state-machine proof and does not authorize a firmware candidate.

## Exact inputs

| Input | SHA-256 |
|---|---|
| `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin` | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| `build/SMK37Pro-v15-S1C1-boundary-only/app.bin` | `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e` |
| `baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json` | `dc6fba4ddb887424d6bd76b6d1477f66f97096e2d6656f203eec423680572cf3` |
| `baselines/v15/analysis/flash-candidates/S1C1-boundary-only/app-manifest.json` | `51f20f38d5c73eef34f2b45834dd428819725249395f5317786443fd9290b40b` |
| `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz` | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| `baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz` | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |

## Official/H2/S1-C1 call streams

| Site | Official v15 | H2 | S1-C1 | Meaning |
|---|---|---|---|---|
| Direct `0x0201e468` | `bfea69fe` -> `0x0201e13e` | `bfea9bfe` -> `0x0201e1a2` | `bfea9bfe` -> `0x0201e1a2` | H2/S1-C1 retarget accepted direct product packet to producer. |
| Segmented `0x0201e49c` | `bfea4ffe` -> `0x0201e13e` | `bfea81fe` -> `0x0201e1a2` | `bfea81fe` -> `0x0201e1a2` | H2/S1-C1 retarget accepted segmented final packet to producer. |

H2 and S1-C1 producer bytes are identical over `0x0201e1a2..0x0201e1ec`; S1-C1 changes only the H2 boundary and preserves product/producer code behavior.

## Instruction-level direct-route proof

```text
0201e256	0416	2	mov	mov r4,r0	FALL_THROUGH	FUN_0201e254@0201e254
0201e258	19d6	2	mov	mov r9,r1	FALL_THROUGH	FUN_0201e254@0201e254
0201e448	08e1a06f	4	add	add r8,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254
0201e44c	4986	2	add	add r1,r4,#0x6	FALL_THROUGH	FUN_0201e254@0201e254
0201e44e	36e1fa9f	4	add	add r6,r9,#-0x6	FALL_THROUGH	FUN_0201e254@0201e254
0201e452	8016	2	mov	mov r0,r8	FALL_THROUGH	FUN_0201e254@0201e254
0201e454	6216	2	mov	mov r2,r6	FALL_THROUGH	FUN_0201e254@0201e254
0201e456	80ff72a80200	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e45c	b4e04009	4	add	add r0,r4,r9	FALL_THROUGH	FUN_0201e254@0201e254
0201e460	085f	2	lb.z	lb.z r0,[r0 + -0x1]	FALL_THROUGH	FUN_0201e254@0201e254
0201e462	90f8cbee	4	jne	jne r0,#0xf7	CONDITIONAL_JUMP	FUN_0201e254@0201e254
0201e466	8016	2	mov	mov r0,r8	FALL_THROUGH	FUN_0201e254@0201e254
H2/S1-C1 0201e468  bfea9bfe      call  0x0201e1a2
```

At direct producer entry: `0x01c37fd0 (official 0x0201e466 mov r0,r8)`; `r9` is `original completed-message length from 0x0201e258 mov r9,r1; not modified by direct-path instructions or memcpy`; LR/rets is `0x0201e46c`. Exact direct acceptance is `r9 == 0xa3`.
The intervening `0x02048cce` copy helper preserves this proof: Quarkslab lists `0x02048cce push {rets,r6,r5,r4}` and `0x02048d0e pop {pc,r6,r5,r4}`, and the extracted helper body contains no `r9` reference.

## Instruction-level segmented-route proof

```text
0201e472	50ed7c09	4	lh.z	lh.z r0,[r7 + 0x9c]	FALL_THROUGH	FUN_0201e254@0201e254
0201e476	b4e04019	4	add	add r1,r4,r9	FALL_THROUGH	FUN_0201e254@0201e254
0201e47a	b4f00059	4	add	add r5,r0,r9	FALL_THROUGH	FUN_0201e254@0201e254
0201e47e	195f	2	_lb.z	_lb.z r1,[r1 + -0x1]	FALL_THROUGH	FUN_0201e254@0201e254
0201e480	91f849ee	4	jne	jne r1,#0xf7	CONDITIONAL_JUMP	FUN_0201e254@0201e254
0201e484	95f8583c	4	jne	jne r5,#0x9e	CONDITIONAL_JUMP	FUN_0201e254@0201e254
0201e488	06e1a06f	4	add	add r6,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254
0201e48c	6018	2	add	add r0,r6	FALL_THROUGH	FUN_0201e254@0201e254
0201e48e	32e1fe9f	4	add	add r2,r9,#-0x2	FALL_THROUGH	FUN_0201e254@0201e254
0201e492	4116	2	mov	mov r1,r4	FALL_THROUGH	FUN_0201e254@0201e254
0201e494	80ff34a80200	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e49a	6016	2	mov	mov r0,r6	FALL_THROUGH	FUN_0201e254@0201e254
H2/S1-C1 0201e49c  bfea81fe      call  0x0201e1a2
```

At segmented producer entry: `0x01c37fd0 (0x0201e49a mov r0,r6)`; `r5` is `0x9e, because 0x0201e47a computes previous_count + current_len and 0x0201e484 gates r5 == 0x9e before memcpy/producer`; LR/rets is `0x0201e4a0`. `r9` is only the current segment length, so the exact assembled-final discriminator is `r5 == 0x9e`, not `r9`.
The segmented append uses the same `0x02048cce` helper, so the gated `r5 == 0x9e` and staging-base `r6 == 0x01c37fd0` remain live at producer entry.

## H2 producer stream and mutation boundary

```text
0x0201e1a2  7904          push {rets,r9,r8,r7,r6,r5,r4}         ; first producer instruction; no H2-owned mutation yet
0x0201e1a4  0416          mov r4,r0                             ; save accepted staging pointer
0x0201e1a6  c0ffbd65c401  mov r0,#0x01c465bd                    ; lock address
0x0201e1ac  2000          csync                                 ; pre-testset barrier
0x0201e1ae  b000          testset b[r0]                         ; first H2-owned state mutation: lock byte
0x0201e1b0  40e81b00      ifeq 0x0201e1ea                       ; busy path returns without copy/publish
0x0201e1b4  2000          csync                                 ; post-acquire barrier
0x0201e1b6  c5ffbc65c401  mov r5,#0x01c465bc                    ; valid0 address
0x0201e1bc  5840          lb.z r0,[r5]                          ; load valid0
0x0201e1be  80f80d00      jne r0,#0,0x0201e1dc                  ; reject if already valid
0x0201e1c2  c0ff2065c401  mov r0,#0x01c46520                    ; owned destination
0x0201e1c8  4116          mov r1,r4                             ; source = accepted staging pointer
0x0201e1ca  623c          mov r2,#0x9c                          ; fixed voice copy size
0x0201e1cc  80fffcaa0200  call 0x02048cce                       ; copy 156 bytes to owned slot0
0x0201e1d2  c5ffbc65c401  mov r5,#0x01c465bc                    ; valid0 address reload
0x0201e1d8  4021          mov r0,#1                             ; valid value
0x0201e1da  d840          sb r0,[r5]                            ; publish valid0 last
0x0201e1dc  c0ffbd65c401  mov r0,#0x01c465bd                    ; lock address
0x0201e1e2  2000          csync                                 ; pre-unlock barrier
0x0201e1e4  4120          mov r1,#0                             ; unlock value
0x0201e1e6  8940          sb r1,[r0]                            ; unlock
0x0201e1e8  2000          csync                                 ; post-unlock barrier
0x0201e1ea  5904          pop {pc,r9,r8,r7,r6,r5,r4}            ; return to caller LR/rets
```

All H2 producer callers decoded from the H2 app:

| Caller | Bytes | Target | Route |
|---|---|---|---|
| `0x0201e468` | `bfea9bfe` | `0x0201e1a2` | direct |
| `0x0201e49c` | `bfea81fe` | `0x0201e1a2` | segmented |

Official v15 callers to the replaced `0x0201e13e` packer are `0x0201e468`, `0x0201e49c`, and `0x02026dac`. H2/S1-C1 retarget only the first two accepted product callsites to producer `0x0201e1a2`; the official SAVE caller at `0x02026dac` is neutralized.

## Post-return reload behavior

- Direct return: `bfeaf838` calls `0x02005660` at `0x0201e46c`, then returns at `0x0201e470`.
- Segmented return: `bfeade38` calls `0x02005660` at `0x0201e4a0`, then branches to `0x0201e538`.
- SAVE no longer calls the replaced packer/producer cave: `0x02026da6` is `04960000` and `0x02026dac` is `00000000` in H2/S1-C1.

## Minimal acceptance rule

```c
// Runs at 0x0201e1a2 before the current producer's testset/copy/publish.
void extended_h2_producer(uint8_t *stage /* r0 */) {
    uintptr_t lr = read_rets_lr();

    bool direct_exact =
        lr == 0x0201e46c &&
        stage == (uint8_t *)0x01c37fd0 &&
        r9 == 0x000000a3;      // original completed message length

    bool segmented_exact_final =
        lr == 0x0201e4a0 &&
        stage == (uint8_t *)0x01c37fd0 &&
        r6 == 0x01c37fd0 &&
        r5 == 0x0000009e;      // official segmented total gate

    if (!(direct_exact || segmented_exact_final))
        return;                // no lock, no copy, no valid-byte mutation

    // Existing H2 publication is then permitted:
    // try_lock(0x01c465bd); reject if busy or valid0 != 0;
    // memcpy(0x01c46520, stage, 0x9c);
    // *(uint8_t *)0x01c465bc = 1; unlock.
}
```

Direct packets can be exact-length gated by `r9 == 0xa3` with direct LR/rets, or safely excluded by rejecting direct LR/rets before `0x0201e1ae`. Segmented final packets are exact-gated by the official live `r5 == 0x9e` check plus segmented LR/rets.

## Final gate

| Gate | Result |
|---|---|
| Official/H2/S1-C1 identity and code equality | PASS |
| Direct route identity at producer entry | PASS |
| Direct exact length available before H2-owned mutation | PASS, `r9 == 0xa3` |
| Segmented route identity at producer entry | PASS |
| Segmented exact final length available before H2-owned mutation | PASS, `r5 == 0x9e` |
| All producer callers traced | PASS, exactly `0x0201e468` and `0x0201e49c` |
| Post-return reload behavior traced | PASS |
| Candidate/device/flash action | Not performed |

## Reproduction

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/producer-abi/analyze_producer_abi.py
```
