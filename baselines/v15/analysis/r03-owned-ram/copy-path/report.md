# R03 owned-RAM copy-path design gate

Decision: **BLOCK**.

Official-v15-only read-only analysis. No patch, flash, device access, boot hook, R01d address, v12 address, guessed RAM, or guessed executable cave is used.

## SHA gates

- app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- FWSC: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- Quarkslab listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347`
- Kagaimiq listing: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`

## Minimal semantic path, not patch-ready

The only stock-preserving producer shape is a wrapper at the two accepted product packer callsites, `0x0201e468` and `0x0201e49c`. Both are reached only after the official handler has accepted a complete product payload into `0x01c37fd0`. A valid wrapper would preserve the stage pointer, call stock `0x0201e13e(stage)`, copy exactly `0x9c` bytes from stage into a separately proven owned destination, then publish `generation++` and `valid=1` only after the copy completes. The stock reload calls at `0x0201e46c` and `0x0201e4a0` stay in place.

This remains blocked because the listings prove neither the owned destination nor the executable body placement required by that wrapper.

## Exact accepted SysEx callsites

Direct complete message: `F0 43 00 00 01 1B + 0x9c payload/checksum + F7`, total `0xa3` bytes. The direct path computes `0x01c37030 + 0x0fa0 = 0x01c37fd0`, copies `message+6`, checks final `F7`, then calls packer and loader. The segmented-final path is also accepted only after final `F7` and accumulated length `0x9e`.

### direct_complete_accept

- `0201e3ee	50ee7602	lb.z	lb.z r0,[r7 + 0x206]	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e3f2	00ff00002801	je	je r0,#0x0,0x0201e648	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e3f8	50ee7401	lb.z	lb.z r0,[r7 + 0x104]	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e3fc	c6ff3070c301	mov	mov r6,#0x1c37030	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e402	00f83604	je	je r0,0x2,0x0201e472	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e406	00f84e02	je	je r0,0x1,0x0201e4a6	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e40a	80f8fc00	jne	jne r0,#0x0,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e410	90f8f9e0	jne	jne r0,#0xf0	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e416	80f8f686	jne	jne r0,#0x43,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e432	80f8e800	jne	jne r0,#0x0,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e438	80f8e500	jne	jne r0,#0x0,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e43e	80f8e202	jne	jne r0,#0x1,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e444	80f8df36	jne	jne r0,#0x1b,0x0201e606	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e448	08e1a06f	add	add r8,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e44c	4986	add	add r1,r4,#0x6	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e44e	36e1fa9f	add	add r6,r9,#-0x6	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e452	8016	mov	mov r0,r8	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e454	6216	mov	mov r2,r6	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e456	80ff72a80200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e45c	b4e04009	add	add r0,r4,r9	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e462	90f8cbee	jne	jne r0,#0xf7	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e466	8016	mov	mov r0,r8	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e468	bfea69fe	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e46c	bfeaf838	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e470	5904	pop	pop {pc,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_0201e254@0201e254`

### segmented_final_accept

- `0201e472	50ed7c09	lh.z	lh.z r0,[r7 + 0x9c]	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e480	91f849ee	jne	jne r1,#0xf7	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e484	95f8583c	jne	jne r5,#0x9e	CONDITIONAL_JUMP	FUN_0201e254@0201e254`
- `0201e488	06e1a06f	add	add r6,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e48c	6018	add	add r0,r6	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e48e	32e1fe9f	add	add r2,r9,#-0x2	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e492	4116	mov	mov r1,r4	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e494	80ff34a80200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e49a	6016	mov	mov r0,r6	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e49c	bfea4ffe	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e4a0	bfeade38	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e4a4	2489	goto	goto 0x0201e538	UNCONDITIONAL_JUMP	FUN_0201e254@0201e254`

## Register, stack ABI, and SAVE behavior

- At `0x0201e468`, `r0 = r8 = 0x01c37fd0`. At `0x0201e49c`, `r0 = r6 = 0x01c37fd0`.
- Packer `0x0201e13e` pushes `{rets,r6,r5,r4}`, allocates `0x80` stack bytes, packs from input `r0`, calls `0x02004b02` with `r0=packed80`, selected persistent destination in `r1`, and `r2=0x80`, then restores stack and pops `{pc,r6,r5,r4}`.
- SAVE also calls `0x0201e13e` at `0x02026dac` after staging `r0 = 0x01c33260+0x1a14`. Therefore `0x0201e13e` is stock pack/SAVE code, not a cave.

### packer_sink

- `0201e13e	7604	push	push {rets,r6,r5,r4}	FALL_THROUGH	FUN_0201e13e@0201e13e`
- `0201e140	e280	add	add sp,#-0x80	FALL_THROUGH	FUN_0201e13e@0201e13e`
- `0201e216	c4ff6032c301	mov	mov r4,#0x1c33260	FALL_THROUGH	-`
- `0201e232	6220	mov	mov r2,#0x80	FALL_THROUGH	-`
- `0201e234	3016	mov	mov r0,r3	FALL_THROUGH	-`
- `0201e236	bfea6434	call	call 0x02004b02	UNCONDITIONAL_CALL	-`
- `0201e250	2280	add	add sp,#0x80	FALL_THROUGH	-`
- `0201e252	5604	pop	pop {pc,r6,r5,r4}	TERMINATOR	-`

### save_packer_caller

- `02026d9e	14e1148a	add	add r4,r8,0x1a14	FALL_THROUGH	-`
- `02026da2	6a23	mov	mov r2,#0xa3	FALL_THROUGH	-`
- `02026da4	4016	mov	mov r0,r4	FALL_THROUGH	-`
- `02026da6	beeaacee	call	call 0x02004b02	UNCONDITIONAL_CALL	-`
- `02026daa	4016	mov	mov r0,r4	FALL_THROUGH	-`
- `02026dac	bfeac7b9	call	call 0x0201e13e	UNCONDITIONAL_CALL	-`

### other_stage_overwrites

- `0201e4ce	80fffaa70200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e52c	80ff9ca70200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e580	00e1a06f	add	add r0,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
- `0201e58c	80ff3ca70200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
- `0201e592	50ed7d49	sh	sh r4,[r7 + 0x9c]	FALL_THROUGH	FUN_0201e254@0201e254`

## Instruction budgets and caller effects

- `0x0201e468`: `bfea69fe`, inline budget `4` bytes.
- `0x0201e49c`: `bfea4ffe`, inline budget `4` bytes.
- `0x0201c63e`: `80ff8ac60200`, inline budget `6` bytes.
- `0x0201c67c`: `80ff4cc60200`, inline budget `6` bytes.
- Producer logic necessarily exceeds the 4-byte SysEx callsite budget because it must preserve stage, preserve/call stock packer, perform a second `0x9c` copy, and publish metadata. No executable body is proven.
- Direct packer callers are exactly `0x0201e468`, `0x0201e49c`, and `0x02026dac`. Hooking the first two only is the stock-SAVE-preserving strategy, but it still needs unproven placement.

## Note On/Off valid and generation behavior

Stock `0x0201c5ec` has no Ch10-owned valid flag, no generation counter, and no valid-source branch. It only checks message/voice bounds, then both Note Off and Note On set `r1 = r8 = 0x01c34c74`, `r2 = 0x9c`, and copy to `engine + voice*0xa0 + 0xa2`. Event metadata follows the `0x9c` copied block. A safe R03 consumer must add metadata: `valid=0` at reset; set `valid=1` only after the producer copy completes; reject or defer generation changes while any Ch10 note is active, or otherwise prove per-active-note generation identity. No storage or code budget for that state is proven here.

### note_off_copy

- `0201c5ec	7a04	push	push {rets,r10,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5ee	1b40	lb.z	lb.z r3,[r1 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5f0	b4a4	lsr	lsr r4,r3,0x4	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5fe	79e1f030	and	and r9,r3,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c602	c8ff744cc301	mov	mov r8,#0x1c34c74	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c616	82fd7b06	jl	jl r2,#0x3,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec`
- `0201c62a	72f1f040	and	and r2,r4,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c630	e1e1a020	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c636	00e1a260	add	add r0,r6,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c63a	623c	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c63c	8116	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c63e	80ff8ac60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`
- `0201c644	00e13e61	add	add r0,r6,#0x13e	FALL_THROUGH	FUN_0201c5ec@0201c5ec`

### note_on_copy

- `0201c5ec	7a04	push	push {rets,r10,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5ee	1b40	lb.z	lb.z r3,[r1 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5f0	b4a4	lsr	lsr r4,r3,0x4	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c5fe	79e1f030	and	and r9,r3,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c602	c8ff744cc301	mov	mov r8,#0x1c34c74	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c652	82fd5d06	jl	jl r2,#0x3,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec`
- `0201c666	72f1f040	and	and r2,r4,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c66c	e1f1a020	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c674	00e1a270	add	add r0,r7,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c678	623c	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c67a	8116	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c67c	80ff4cc60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`
- `0201c682	00e13e71	add	add r0,r7,#0x13e	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
- `0201c698	5a04	pop	pop {pc,r10,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_0201c5ec@0201c5ec`

## PASS/BLOCK matrix

| Gate | Result | Reason |
|---|---|---|
| Exact accepted product callsites | PASS | `0x0201e468` and `0x0201e49c` are post-F7 acceptance packer calls |
| Producer source/length | PASS | stage is `0x01c37fd0`; required copy is first `0x9c` bytes |
| Stock packer/SAVE preservation | BLOCK | semantic strategy exists, but needs unproven wrapper body; overwriting packer affects SAVE |
| Owned RAM destination | BLOCK | no exact start/end, owner, lifetime, initialization, alias, DMA/stack/heap exclusion proof |
| Valid/generation | BLOCK | required semantics defined, but no owned metadata storage or consumer budget proven |
| Avoid boot hooks | PASS semantically | producer would run only from already-live SysEx accept path |
| No guessed cave/address | PASS by refusal | no cave or RAM address is proposed |

## Reproduce

```sh
python3 baselines/v15/analysis/r03-owned-ram/copy-path/analyze_copy_path.py
cd baselines/v15/analysis/r03-owned-ram/copy-path
shasum -a 256 -c SHA256SUMS
```
