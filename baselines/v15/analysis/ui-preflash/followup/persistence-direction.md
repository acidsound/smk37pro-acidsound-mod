# v15 persistence direction follow-up

Scope: official v15 Quarkslab exhaustive listing only. This report focuses only on `0x02004b02 -> 0x02004a7a -> 0x02063260`. It performs no patching, flashing, firmware writes, or git commit. `cfg_tool` and `USRFLASH` strings are treated only as auxiliary hints, not proof.

## SHA gate

- listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` (PASS)

## Conclusion

- `0x02004b02` external ABI is `r0=RAM/source buffer`, `r1=storage offset/address`, `r2=length`.
- `0x02004b02` swaps arguments and calls `0x02004a7a` as `r0=source`, `r1=length`, `r2=storage`.
- `0x02004a7a` enforces `storage + length <= *(0x01c454b0+0x18)`, then calls `0x02063260` with request object `0x01c33260+0xd1c` while preserving `source/length/storage` in `r7/r10/r6`.
- Return mode is count-style: `0x02004b02` returns the requested length only when `0x02004a7a` returns that same length. Otherwise it returns `0`.
- Direction is statically `RAM -> storage` for every decoded v15 caller of `0x02004b02`. The contrasting read path is `0x02004870 -> 0x020047d8`, which later copies from an allocated/read buffer into the caller's destination with `0x02048cce`.
- Primitive-level command names inside `0x02063260` remain a decoder gap because the listing marks it `CALL_TERMINATOR` and does not decode its callee/request ABI.

## Wrapper proof

```text
02004b02	7404	2	push	push {rets,r4}	FALL_THROUGH	FUN_02004b02@02004b02
02004b04	2416	2	mov	mov r4,r2	FALL_THROUGH	FUN_02004b02@02004b02
02004b06	1216	2	mov	mov r2,r1	FALL_THROUGH	FUN_02004b02@02004b02
02004b08	4116	2	mov	mov r1,r4	FALL_THROUGH	FUN_02004b02@02004b02
02004b0a	5197	2	call	call 0x02004a7a	UNCONDITIONAL_CALL	FUN_02004b02@02004b02
02004b0c	90e80004	4	if	if (r0 != r4) {	FALL_THROUGH	FUN_02004b02@02004b02
02004b10	4420	2	mov	mov r4,#0x0	FALL_THROUGH	FUN_02004b02@02004b02
02004b12	4016	2	} 	}  mov r0, r4	FALL_THROUGH	FUN_02004b02@02004b02
02004b14	5404	2	pop	pop {pc,r4}	TERMINATOR	FUN_02004b02@02004b02
```

```text
02004a7a	7a04	2	push	push {rets,r10,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a7c	c3ffb054c401	6	mov	mov r3,#0x1c454b0	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a82	26d6	2	mov	mov r6,r2	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a84	3366	2	_lw	_lw r3,[r3 + 0x18]	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a86	1a16	2	mov	mov r10,r1	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a88	0716	2	mov	mov r7,r0	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a8a	6118	2	add	add r1,r6	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a8c	4020	2	mov	mov r0,#0x0	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a8e	03ec3710	4	ja	ja r1,r3,0x02004b00	CONDITIONAL_JUMP	FUN_02004a7a@02004a7a
02004a92	c9ff6032c301	6	mov	mov r9,#0x1c33260	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a98	08e11c9d	4	add	add r8,r9,#0xd1c	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a9c	8016	2	mov	mov r0,r8	FALL_THROUGH	FUN_02004a7a@02004a7a
02004a9e	80ffbce70500	6	call	call 0x02063260	CALL_TERMINATOR	FUN_02004a7a@02004a7a
02004b00	5a04	2	pop	pop {pc,r10,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_02004a7a@02004a7a
```

Read-wrapper comparator:

```text
020047d8	7a04	2	push	push {rets,r10,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_020047d8@020047d8
020047da	c8ffb054c401	6	mov	mov r8,#0x1c454b0	FALL_THROUGH	FUN_020047d8@020047d8
020047e0	d0ec8033	4	ldw	ldw r3,r8,#0x30	FALL_THROUGH	FUN_020047d8@020047d8
020047e4	2716	2	mov	mov r7,r2	FALL_THROUGH	FUN_020047d8@020047d8
020047e6	1416	2	mov	mov r4,r1	FALL_THROUGH	FUN_020047d8@020047d8
020047e8	0916	2	mov	mov r9,r0	FALL_THROUGH	FUN_020047d8@020047d8
020047ea	751d	2	add	add r5,r7,r4	FALL_THROUGH	FUN_020047d8@020047d8
020047ec	07ec0a30	4	ja	ja r3,r7,0x02004804	CONDITIONAL_JUMP	FUN_020047d8@020047d8
020047f0	c0ff01f0ff00	6	mov	mov r0,#0xfff001	FALL_THROUGH	FUN_020047d8@020047d8
020047f6	80e92f50	4	jb	jb r5,r0,0x02004858	CONDITIONAL_JUMP	FUN_020047d8@020047d8
020047fa	d0ec8801	4	ldw	ldw r0,r8,#0x18	FALL_THROUGH	FUN_020047d8@020047d8
020047fe	29ff80072a00	6	jbe	jbe r0,#0x1000000,0x02004858	CONDITIONAL_JUMP	FUN_020047d8@020047d8
02004804	caff6032c301	6	mov	mov r10,#0x1c33260	FALL_THROUGH	FUN_020047d8@020047d8
0200480a	06e11cad	4	add	add r6,r10,#0xd1c	FALL_THROUGH	FUN_020047d8@020047d8
0200480e	6016	2	mov	mov r0,r6	FALL_THROUGH	FUN_020047d8@020047d8
02004810	80ff4aea0500	6	call	call 0x02063260	CALL_TERMINATOR	FUN_020047d8@020047d8
02004858	7016	2	mov	mov r0,r7	FALL_THROUGH	FUN_020047d8@020047d8
0200485a	80ff14bbbfff	6	call	call 0x01c00374	UNCONDITIONAL_CALL	FUN_020047d8@020047d8
02004860	0116	2	mov	mov r1,r0	FALL_THROUGH	FUN_020047d8@020047d8
02004862	9016	2	mov	mov r0,r9	FALL_THROUGH	FUN_020047d8@020047d8
02004864	4216	2	mov	mov r2,r4	FALL_THROUGH	FUN_020047d8@020047d8
02004866	80ff62440400	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_020047d8@020047d8
0200486c	4016	2	mov	mov r0,r4	FALL_THROUGH	FUN_020047d8@020047d8
0200486e	5a04	2	pop	pop {pc,r10,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_020047d8@020047d8
02004870	7404	2	push	push {rets,r4}	FALL_THROUGH	FUN_02004870@02004870
02004872	2416	2	mov	mov r4,r2	FALL_THROUGH	FUN_02004870@02004870
02004874	1216	2	mov	mov r2,r1	FALL_THROUGH	FUN_02004870@02004870
02004876	4116	2	mov	mov r1,r4	FALL_THROUGH	FUN_02004870@02004870
02004878	518f	2	call	call 0x020047d8	UNCONDITIONAL_CALL	FUN_02004870@02004870
0200487a	90e80004	4	if	if (r0 != r4) {	FALL_THROUGH	FUN_02004870@02004870
0200487e	4420	2	mov	mov r4,#0x0	FALL_THROUGH	FUN_02004870@02004870
02004880	4016	2	} 	}  mov r0, r4	FALL_THROUGH	FUN_02004870@02004870
02004882	5404	2	pop	pop {pc,r4}	TERMINATOR	FUN_02004870@02004870
```

## All v15 callers of `0x02004b02`

| call | group | r0 source | r1 storage | r2 length | mode/default-load/save context | return/error use |
| --- | --- | --- | --- | --- | --- | --- |
| 0x02005042 | config block save | 0x01c33260+0x2a90 RAM block | *(0x01c33260+0x1d4) | 0x224 | 0x0200502e..02005032 calls 0x02004a54(mode=2, storage=*(+0x1d4)) | ignored |
| 0x02005050 | config trailer save | sp+0x24 8-byte local trailer | *(0x01c33260+0x1d4)+0x224 | 0x8 | same prepared region as 0x02005042 | ignored |
| 0x0200514a | descriptor/header save | sp+0x4 local descriptor copied from +0x494 and tagged 0x3aa3 | *(0x01c33260+0x20c) | 0x86 | none adjacent | ignored |
| 0x02005528 | current bank/preset selection save | 0x01c33260+0x3a0 selection bytes | *(0x01c33260+0x160)+0x9200 | 0x9 | none adjacent | ignored |
| 0x020064ba | default image block 0 | r6 default/source image base | *(0x01c33260)+0x0 | 0x49e3 | 0x02006440..020064ac prepares multiple sectors; mode 1 for first two, mode 2 for following sectors | ignored |
| 0x020064c8 | default image block 1 | r6+0x49e3 | *(0x01c33260)+0x5000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x020064dc | default image block 2 | r6+0x93c6 | *(0x01c33260)+0xa000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x020064f0 | default image block 3 | r6+0xdda9 | *(0x01c33260)+0xf000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x02006504 | default image block 4 | r6+0x1278c | *(0x01c33260)+0x14000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x02006518 | default image block 5 | r6+0x1716f | *(0x01c33260)+0x19000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x0200652c | default image block 6 | r6+0x1bb52 | *(0x01c33260)+0x1e000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x02006540 | default image block 7 | r6+0x20535 | *(0x01c33260)+0x23000 | 0x49e3 | sector prepare sequence at 0x02006440..020064ac | ignored |
| 0x02006552 | default image usrdata marker | sp+0x50 containing ASCII usrdata | *(0x01c33260)+0x27ff8 | 0x8 | after block-image writes | ignored |
| 0x0201dfe8 | config block save duplicate path | 0x01c33260+0x2a90 | *(0x01c33260+0x1d4) | 0x224 | 0x0201dfd2..0201dfd6 calls 0x02004a54(mode=2, storage=*(+0x1d4)) | ignored |
| 0x0201dff8 | config trailer save duplicate path | sp+0x0 local marker trimdat | *(0x01c33260+0x1d4)+0x224 | 0x8 | same prepared region as 0x0201dfe8 | ignored |
| 0x0201e236 | packed patch/current record default-load save | sp scratch buffer built by 0x0201e13e | *(0x01c33260+0x160)+bank*0x1000+preset*0x80 | 0x80 | none adjacent; after call clears +0x129c flag for bank/preset | ignored |
| 0x02023338 | descriptor/header save duplicate path | sp+0x0 local descriptor copied from 0x01c33260+0x161c and tagged 0x3aa3 | *(0x01c33260+0x20c) | 0x86 | none adjacent | ignored |
| 0x02024e5c | bank image/default bank save | 0x01c0de20 + bank*0x49e3 | *(0x01c33260+0x200)+bank*0x5000 | 0x49e3 | 0x02024e1c..02024e44 prepares five 0x1000 sectors with mode 2 | ignored |
| 0x02024e84 | bank image usrdata marker | sp+0x0 ASCII usrdata | *(0x01c33260+0x200)+0x27ff8 | 0x8 | only on bank index 7 | ignored |
| 0x0202556e | default-load selected bank block write | r10+0xfa0 RAM/default bank image | *(0x01c33260+0x160)+bank*0x1000 | 0x1000 | 0x0202555c..02025560 calls 0x02004a54(mode=2, selected-bank storage) | ignored |
| 0x0202558e | dirty/saved flag table flush after default-load | 0x01c33260+0x129c flag table just cleared | *(0x01c33260+0x160)+0x9180 | 0x80 | after 32-byte flag clear at 0x0202557a..0202557c | ignored |
| 0x02026da6 | current patch record save | 0x01c33260+0x1a14 current patch snapshot | *(0x01c33260+0x160)+0x4000+(bank*32+preset)*0xa3 | 0xa3 | none adjacent; save gate +0x1ec==0 and r6!=0xff | ignored |
| 0x02026dd0 | dirty/saved flag table flush after SAVE | 0x01c33260+0x129c flag table after selected entry is set | *(0x01c33260+0x160)+0x9180 | 0x80 | after +0x129c[bank*32+preset] = r15 | ignored |
| 0x0202b850 | thin passthrough wrapper | caller-supplied | caller-supplied | caller-supplied | none; wrapper only pushes/calls/pops | returned to caller |
| 0x0202c64c | allocator/metadata marker save | sp+0x0 local marker 0x3154 | lw [r5++=0x18] from storage metadata structure | 0x4 | 0x0202c55c may prepare storage ranges before marker write | ignored |
| 0x0202c692 | chunked copyback write | sp+0x0 temp chunk read by 0x02004870 | r6 destination storage cursor | r7 chunk length capped at 0x100 | paired with 0x02004870 read from r8 into temp, then write temp to r6 | ignored |
| 0x0202c6fc | journal magic write ddeebb77 | sp+0x0 local 0xddeebb77 | metadata pointer loaded from active bank structure | 0x4 | none adjacent | ignored |
| 0x0202c7e6 | journal/current pointer write | sp+0x0 local pointer/value | alternate active metadata pointer | 0x4 | inside journal rewrite loop | ignored |
| 0x0202c81e | journal magic write 55aaaa55 | sp+0x0 local 0x55aaaa55/value | alternate active metadata pointer | 0x4 | after toggling active slot bit | ignored |
| 0x0202cc82 | chunked copyback write duplicate | r5 temp buffer filled by 0x02004870 | r14+r11 destination cursor | r6 chunk length capped at 0x200 | paired with 0x02004870 read from old offset into r5, then 0x02004b02 writes to new offset | ignored |
| 0x0202cd1e | metadata name/header save | r4 local metadata structure | r15 caller-held destination | 0x20 | fills structure with string at 0x0205dc5a and short from 0x020028b0 | ignored |
| 0x0202cf30 | formatted object/header save | sp+0x0 local 0x50-byte object | r8 destination | 0x50 | 0x0202cf1e..0202cf22 calls 0x02004a54(mode=2, storage=r11) | ignored |

Raw xref count: `32`. The JSON stores the original context window for each xref.

## Direct v15 callers of `0x02004a7a`

| call | function | arg order | return/error use | direction |
| --- | --- | --- | --- | --- |
| 0x02004b0a | FUN_02004b02 | r0=source RAM, r1=len, r2=storage | wrapper returns original len if inner r0==len else 0 | write |
| 0x0202cd66 | FUN_0202cd42 | r0=sp+0x50 local block, r1=0x50 len, r2=storage cursor loaded earlier | ignored then function returns 0 | write by 0x02004a7a contract |
| 0x0202dd28 | unlabeled chunk writer | r0=r4 source, r1=r5 len, r2=r6 storage | requires r0==r5, then advances [r7] by r5 and returns r5; else falls through error | write |

Raw xref count: `3`.

## `0x02063260` caller comparison

Raw direct xref count in v15 listing: `41`. JSON includes all raw contexts. Only the focused path caller `0x02004a9e` is used as proof here. Many other callers use `0x02063260` as a general request/scheduler primitive, so they are not assigned storage direction unless they participate in the wrapper path.

## Bounds, default-load, save failure path

- Bounds: `0x02004a7a` loads `r3 = *(0x01c454b0+0x18)`, computes `r1 = storage + length`, preloads `r0=0`, and branches to return if `r1 > r3`.
- Default-load path: `0x0202553c` prepares selected-bank storage with `0x02004a54(mode=2)`, writes `r10+0xfa0` to `*(+0x160)+bank*0x1000` for `0x1000`, clears 32 flags at `+0x129c`, writes that flag table to `*(+0x160)+0x9180` for `0x80`, updates selected bank/preset, then calls factory loader `0x02005660`.
- Save path: `0x02026d6c` gates on `+0x1ec==0` and `r6!=0xff`, writes current snapshot `+0x1a14` to `*(+0x160)+0x4000+(bank*32+preset)*0xa3` for `0xa3`, calls `0x0201e13e`, sets the `+0x129c` entry, flushes `0x80` bytes to `*(+0x160)+0x9180`, then clears/sets `+0x1ec` and exits.
- Save failure path: both SAVE calls ignore the `0/len` return from `0x02004b02`. The wrapper can report failure, but the decoded SAVE path does not branch on it before marking saved or clearing `+0x1ec`.

## Decoder gaps

- `0x02063260-call-terminator-body`: The Quarkslab/Ghidra listing marks calls to 0x02063260 as CALL_TERMINATOR. For 0x02004a7a, control resumes at 0x02004b00 without an emitted post-call basic block. Registers r7/r10/r6 hold source/len/storage before the call, but the listing does not decode the callee or request-object ABI that consumes them. Impact: Primitive-level implementation details, device command ID, and internal errno mapping remain unproven from this listing alone.
- `0x02004896-mode-body-split`: 0x02004a54 calls 0x02004896 after table lookup at 0x02057954. The listing shows a body fragment 0x02004902..0x02004a52 after the CALL_TERMINATOR at 0x020048a8, but function ownership is '-' for many rows. That permits a mode/preparation interpretation but not a fully typed device operation decode. Impact: mode=1/2/3 preparation is visible at callsites, but exact erase/open/commit names are not assigned.

## Reproduction

```sh
python3 baselines/v15/analysis/ui-preflash/followup/analyze_persistence_direction.py
```

Outputs:

- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.md`
- `baselines/v15/analysis/ui-preflash/followup/persistence-direction.json`
