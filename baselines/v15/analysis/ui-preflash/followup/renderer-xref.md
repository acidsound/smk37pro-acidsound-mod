# v15 UI renderer xref follow-up
## Scope
- Targeted follow-up only. Inputs are the existing official app and existing Quarkslab listings.
- No patch, flash, Ghidra run, broad research, or commit was performed.
- App SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`. Runtime base: `0x02000000`. Descriptor base: `0x02057250`.

## Result
- **Direct chain found:** no.
- **Confirmed partial chain:** `0x0202038a mov r12,#0x2057250` -> `0x02022de0 add r1,r12,0x10c4` -> `0x02022de8 call 0x0201a67c`. This computes `0x02058314`, the `Keys Channel-` descriptor/pointer-list entry.
- `FUN_02020376@02020376` has many direct `0x0201a67c` calls but no direct `0x0200f74c` or `0x0201e06c` call.
- `0x0201a67c` itself calls allocator/string helpers, not traversal/redraw.
- Direct callers of `0x0200f74c` and `0x0201e06c` are disjoint from the named `FUN_02020376` builder in the listing. Rows decoded as function `-` were not promoted to a caller chain.

## Descriptor table targets
| target | VA | base-relative | first words |
|---|---:|---:|---|
| `Firmware_descriptor_entry` | `0x02058028` | `0xdd8` | 0x0205d8f5 -> Firmware#, 0x0205d8f9 -> ware#, 0x0205d8fe -> ?, 0x0205d902 -> ? |
| `Pad_Bank_descriptor_entry` | `0x02058304` | `0x10b4` | 0x0205d9c5 -> Pad Bank-, 0x0205d9ce -> ?, 0x0205d9d7 -> tor-, 0x0205d9e0 ->  Repeat- |
| `Keys_Channel_descriptor_entry` | `0x02058314` | `0x10c4` | 0x0205d9e9 -> Keys Channel-, 0x0205d9f2 -> nel-, 0x0205d9f9 -> ds Channel-, 0x0205da03 -> - |

## Calculated/base-relative access hits
| listing | target | value | row | function | note |
|---|---|---:|---|---|---|
| exhaustive-r12-formula | `Keys_Channel_descriptor_entry` | `0x02058314` | `02022de0 add r1,r12,0x10c4` | `FUN_02020376@02020376` | descriptor target |
| recursive-r12-formula | `Keys_Channel_descriptor_entry` | `0x02058314` | `02022de0 add r1,r12,0x10c4` | `FUN_02020376@02020376` | descriptor target |

Existing Quarkslab `EVIDENCE_REF` log hits for these targets:
- line 744: `INFO  V15DecoderAnalysis.java> EVIDENCE_REF phase=recursive from=02022de0 text=add r1,r12,0x10c4 to=02058314 type=PARAM function=FUN_02020376@02020376 (GhidraScript)`
- line 2863: `INFO  V15DecoderAnalysis.java> EVIDENCE_REF phase=exhaustive from=02022de0 text=add r1,r12,0x10c4 to=02058314 type=PARAM function=FUN_02020376@02020376 (GhidraScript)`

Non-descriptor false-adjacent hit: both listings also contain `0x0201067e add r0,r6,0x10c4`, but there `r6` is derived from RAM `0x1c33260`, not descriptor base `0x02057250`, so it is not a UI pointer-table access.

## Targeted setter callsite
- `02022de8` `call 0x0201a67c` in `FUN_02020376@02020376` follows formula `02022de0 add r1,r12,0x10c4` giving `r1=0x02058314`.

### Key snippet
```text
02022dca	0063	lw	lw r0,[r0 + 0xc]	FALL_THROUGH	FUN_02020376@02020376
02022dcc	4121	mov	mov r1,#0x1	FALL_THROUGH	FUN_02020376@02020376
02022dce	4220	mov	mov r2,#0x0	FALL_THROUGH	FUN_02020376@02020376
02022dd0	532b	mov	mov r3,#0x4b	FALL_THROUGH	FUN_02020376@02020376
02022dd2	bfeabedf	call	call 0x0201ed52	UNCONDITIONAL_CALL	FUN_02020376@02020376
02022dd6	7060	lw	lw r0,[r7 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022dd8	0063	lw	lw r0,[r0 + 0xc]	FALL_THROUGH	FUN_02020376@02020376
02022dda	4122	mov	mov r1,#0x2	FALL_THROUGH	FUN_02020376@02020376
02022ddc	bfeac3df	call	call 0x0201ed66	UNCONDITIONAL_CALL	FUN_02020376@02020376
02022de0	11f1c4c0	add	add r1,r12,0x10c4	FALL_THROUGH	FUN_02020376@02020376
02022de4	7060	_lw	_lw r0,[r7 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022de6	0063	lw	lw r0,[r0 + 0xc]	FALL_THROUGH	FUN_02020376@02020376
02022de8	bfea48bc	call	call 0x0201a67c	UNCONDITIONAL_CALL	FUN_02020376@02020376
02022dec	7060	lw	lw r0,[r7 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022dee	0060	lw	lw r0,[r0 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022df0	bfea47df	call	call 0x0201ec82	UNCONDITIONAL_CALL	FUN_02020376@02020376
02022df4	7160	lw	lw r1,[r7 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022df6	9064	sw	sw r0,[r1 + 0x10]	FALL_THROUGH	FUN_02020376@02020376
02022df8	7930	mov	mov r1,#0xf0	FALL_THROUGH	FUN_02020376@02020376
02022dfa	423e	mov	mov r2,#0x1e	FALL_THROUGH	FUN_02020376@02020376
02022dfc	bfea4ddf	call	call 0x0201ec9a	UNCONDITIONAL_CALL	FUN_02020376@02020376
02022e00	41d6	mov	mov r1,r4	FALL_THROUGH	FUN_02020376@02020376
02022e02	7060	_lw	_lw r0,[r7 + 0x0]	FALL_THROUGH	FUN_02020376@02020376
02022e04	0064	lw	lw r0,[r0 + 0x10]	FALL_THROUGH	FUN_02020376@02020376
02022e06	bfea72df	call	call 0x0201ecee	UNCONDITIONAL_CALL	FUN_02020376@02020376
```

## Direct caller sets checked
- `0x02020376` direct callers: 02025488, 02027514, 02027522
- `0x0200f74c` direct callers: 0201016a, 020161a4, 0201624c, 02019c98, 02019e1c
- `0x0201e06c` direct callers: 0201e510, 0201e5ee, 020233d6, 02023430, 02023b8e, 020242a8, 020243f0, 0202451a, 02025784, 0202597c, 02025c14, 02025ca6, 02026026, 0202618a, 0202649a, 020269b4, 020270ae, 0202718a, 020271aa, 02027326, 0202960e, 0202999e, 02029d3a, 0202a514, 0202a57c, 0202a8c6, 0202a9a4, 0202aa16, 0202aa78, 0202aaa6, 0202abea, 0202ac58, 0202ad12, 0202ad4c, 0202ad9e, 0202ae08, 0202ae5a, 0202b01c, 0202b058, 0202b0ac, 0202b13c, 0202b178, 0202b1cc, 0202b274, 0202b2cc, 0202b4a8, 0202b5ba, 0202b656, 0202b690, 0202b984

## Evidence-backed blocker
No evidence-backed direct data-flow/caller chain from 0x02058028/0x02058304/0x02058314 or the targeted 0x0201a67c caller to 0x0200f74c or 0x0201e06c was recovered. 0x02020376 does not directly call either target; 0x0201a67c itself only calls allocator/string helpers; render traversal and redraw direct caller sets are disjoint from FUN_02020376 in named listing functions. Exhaustive rows with function '-' are not promoted to a chain.

## Reproduce
```sh
python3 baselines/v15/analysis/ui-preflash/followup/analyze_renderer_xref.py
```
Machine-readable output: `renderer-xref.json`.
