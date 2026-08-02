# v15 factory loader 0x02005660 reanalysis

Scope: loader conclusions use official v15 artifacts only. The recorded R01c manifest is comparison-only evidence for the prior static snapshot hash. This script does not read v12, generate a patch, touch flash, or modify firmware images.

## SHA gates

- app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` (PASS)
- package: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` (PASS)
- flash_slice: `f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a` (PASS)
- listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` (PASS)
- clean_dump_a: `1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b` (PASS)
- clean_dump_b: `1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b` (PASS)
- clean_dump_a_b_cmp: `identical` (PASS)

## 결론

- `0x02005660` 함수 경계는 `0x02005660..0x020057de`이다. 직전 함수는 `0x0200565e`에서 `rts`, 다음 함수는 `0x020057e0`에서 `push`로 시작한다.
- 인자는 호출자 전달값을 사용하지 않는 `void factory_loader(void)` 형태다. 함수 내부에서 전역 RAM base `0x01c33260`, selected bank `+0x3a4`, selected preset `+0x3a0+bank`를 직접 읽는다.
- destination은 `0x01c33260+0x1a14 = 0x01c34c74`이다. 이 주소는 Note On/Off dispatcher `0x0201c5ec`의 `0x9c` byte memcpy source이기도 하다.
- Bank D display 14, zero-based index 13 `Mooger #1` 경로는 index `109`, packed128 dump offset `0x000f7680`, raw163 offset `0x000fc567`, flag offset `0x000fd1ed`이다.
- `R01c` 128→156 정적 expansion은 clean Mooger #1의 첫 `0x9c` bytes와는 같다. 그러나 live source object와 동등하지는 않다. loader는 먼저 `0xa3` bytes를 복사하고, tail `0x9c..0xa2`, flag-dependent display byte swap/copy, helper side effects를 추가 수행한다.
- 따라서 clean-data 모델은 "주입된 156 bytes 자체가 달랐다"는 설명을 지지하지 않는다. 확인된 차이는 loader lifecycle/state side effect이고, 그것이 연속 pitch 하강의 정확한 원인인지는 runtime RAM/state capture 없이 미입증이다.

## Function boundary and callers

- `0x02005f9c`: post-init or state refresh path; copies +0x3a6/+0x3a7 to UI fields before loader; return consumer: loads *(r6+0x15c) into r0 and calls 0x020057e0 at 0x02005fa4
- `0x0201e46c`: SysEx/product packet path after 0x0201e13e; return consumer: immediate pop; return value ignored
- `0x0201e4a0`: alternate SysEx/product packet path after 0x0201e13e; return consumer: jumps to common continuation 0x0201e538; return value ignored
- `0x0202422e`: UI bank/preset change; invokes 0x02024070 before loader; return consumer: loads *(0x01c33260+0x15c) and calls 0x020057e0 at 0x02024236
- `0x020255a6`: default-load/bank-block path after writing bank block and clearing flag table; return consumer: falls through with r0=0x64; loader return ignored

Target census: decoded direct call count `5`. Raw official-app little-endian pointer hits are `0x02005660=[]` and `0x02005661=[]`. This rules out a simple absolute function-pointer table, but not a computed or encoded indirect target.

### Boundary evidence

```text
02005650	4021	2	mov	mov r0,#0x1	FALL_THROUGH	-
02005652	0481	2	goto	goto 0x02005656	UNCONDITIONAL_JUMP	-
02005654	4020	2	mov	mov r0,#0x0	FALL_THROUGH	FUN_0200562c@0200562c
02005656	42e08001	4	movz	movz r2,#0x180	FALL_THROUGH	FUN_0200562c@0200562c
0200565a	d8ee1102	4	sb	sb r0,[r1 + r2]	FALL_THROUGH	FUN_0200562c@0200562c
0200565e	8000	2	rts	rts	TERMINATOR	FUN_0200562c@0200562c
```

```text
02005660	7804	2	push	push {rets,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_02005660@02005660
02005662	40e0a403	4	movz	movz r0,#0x3a4	FALL_THROUGH	FUN_02005660@02005660
02005666	c4ff6032c301	6	mov	mov r4,#0x1c33260	FALL_THROUGH	FUN_02005660@02005660
0200566c	d8ee4050	4	lb.z	lb.z r5,[r4 + r0]	FALL_THROUGH	FUN_02005660@02005660
02005670	05fcb506	4	ja	ja r5,0x3,0x020057de	CONDITIONAL_JUMP	FUN_02005660@02005660
02005674	501d	2	add	add r0,r5,r4	FALL_THROUGH	FUN_02005660@02005660
02005676	41e0a003	4	movz	movz r1,#0x3a0	FALL_THROUGH	FUN_02005660@02005660
0200567a	d8ee0061	4	lb.z	lb.z r6,[r0 + r1]	FALL_THROUGH	FUN_02005660@02005660
0200567e	06fcae3e	4	ja	ja r6,0x1f,0x020057de	CONDITIONAL_JUMP	FUN_02005660@02005660
02005682	d1ec4476	4	ldw	ldw r7,r4,#0x164	FALL_THROUGH	FUN_02005660@02005660
02005686	50a5	2	lsl	lsl r0,r5,0x5	FALL_THROUGH	FUN_02005660@02005660
02005688	6018	2	add	add r0,r6	FALL_THROUGH	FUN_02005660@02005660
0200568a	e0e1a300	4	mul	mul r0,r0,#0xa3	FALL_THROUGH	FUN_02005660@02005660
0200568e	7018	2	add	add r0,r7	FALL_THROUGH	FUN_02005660@02005660
02005690	e1e0800c	4	add	add r1,r0,0x4000	FALL_THROUGH	FUN_02005660@02005660
02005694	10e1144a	4	add	add r0,r4,0x1a14	FALL_THROUGH	FUN_02005660@02005660
02005698	6a23	2	mov	mov r2,#0xa3	FALL_THROUGH	FUN_02005660@02005660
0200569a	80ff2e360400	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_02005660@02005660
020056a0	51ac	2	lsl	lsl r1,r5,0xc	FALL_THROUGH	FUN_02005660@02005660
020056a2	781c	2	add	add r0,r7,r1	FALL_THROUGH	FUN_02005660@02005660
020056a4	62a7	2	lsl	lsl r2,r6,0x7	FALL_THROUGH	FUN_02005660@02005660
020056a6	b4e00082	4	add	add r8,r0,r2	FALL_THROUGH	FUN_02005660@02005660
020056aa	2118	2	add	add r1,r2	FALL_THROUGH	FUN_02005660@02005660
020056ac	7118	2	add	add r1,r7	FALL_THROUGH	FUN_02005660@02005660
020056ae	c130	2	add	add r1,#0x10	FALL_THROUGH	FUN_02005660@02005660
020056b0	4220	2	mov	mov r2,#0x0	FALL_THROUGH	FUN_02005660@02005660
020056b2	148d	2	goto	goto 0x0200570e	UNCONDITIONAL_JUMP	FUN_02005660@02005660
020056b4	231d	2	add	add r3,r2,r4	FALL_THROUGH	FUN_02005660@02005660
020056b6	15e1143a	4	add	add r5,r3,0x1a14	FALL_THROUGH	FUN_02005660@02005660
020056ba	36e1f01f	4	add	add r6,r1,#-0x10	FALL_THROUGH	FUN_02005660@02005660
020056be	5716	2	mov	mov r7,r5	FALL_THROUGH	FUN_02005660@02005660
020056c0	108a	2	rep	rep #0x4,#0xb	FALL_THROUGH	FUN_02005660@02005660
020056c2	6007	2	lb.z	lb.z r0,[r6 ++= 1]	FALL_THROUGH	FUN_02005660@02005660
020056c4	f007	2	sb	sb r0,[r7 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660
020056c6	185b	2	lb.z	lb.z r0,[r1 + -0x5]	FALL_THROUGH	FUN_02005660@02005660
020056c8	76e1fc00	4	and	and r6,r0,#0xffffff03	FALL_THROUGH	FUN_02005660@02005660
020056cc	b0f10801	4	uextra	uextra r0,r0,0x2,0x2	FALL_THROUGH	FUN_02005660@02005660
020056d0	de4b	2	_sb	_sb r6,[r5 + 0xb]	FALL_THROUGH	FUN_02005660@02005660
020056d2	d84c	2	sb	sb r0,[r5 + 0xc]	FALL_THROUGH	FUN_02005660@02005660
020056d8	66e10700	4	and	and r6,r0,#0x7	FALL_THROUGH	-
020056dc	80a3	2	lsr	lsr r0,r0,0x3	FALL_THROUGH	-
020056de	13f1243a	4	add	add r3,r3,0x1a24	FALL_THROUGH	-
020056e2	de4d	2	_sb	_sb r6,[r5 + 0xd]	FALL_THROUGH	-
020056e4	b844	2	sb	sb r0,[r3 + 0x4]	FALL_THROUGH	-
020056ea	66e10300	4	and	and r6,r0,#0x3	FALL_THROUGH	-
020056ee	de4e	2	sb	sb r6,[r5 + 0xe]	FALL_THROUGH	-
020056f0	80a2	2	lsr	lsr r0,r0,0x2	FALL_THROUGH	-
020056f2	d84f	2	sb	sb r0,[r5 + 0xf]	FALL_THROUGH	-
020056f4	185e	2	lb.z	lb.z r0,[r1 + -0x2]	FALL_THROUGH	-
020056f6	b840	2	sb	sb r0,[r3 + 0x0]	FALL_THROUGH	-
020056fc	65e10100	4	and	and r5,r0,#0x1	FALL_THROUGH	-
02005700	bd41	2	sb	sb r5,[r3 + 0x1]	FALL_THROUGH	-
02005702	80a1	2	lsr	lsr r0,r0,0x1	FALL_THROUGH	-
02005704	b842	2	sb	sb r0,[r3 + 0x2]	FALL_THROUGH	-
02005708	1101	2	tbh	tbh r1	COMPUTED_JUMP	-
0200570a	b843	2	sb	sb r0,[r3 + 0x3]	FALL_THROUGH	-
0200570c	c235	2	add	add r2,#0x15	FALL_THROUGH	-
0200570e	82f8d1fd	4	jne	jne r2,#0x7e,0x020056b4	CONDITIONAL_JUMP	FUN_02005660@02005660
02005712	15e1904a	4	add	add r5,r4,0x1a90	FALL_THROUGH	FUN_02005660@02005660
02005716	00e16680	4	add	add r0,r8,#0x66	FALL_THROUGH	FUN_02005660@02005660
0200571a	5982	2	add	add r1,r5,#0x2	FALL_THROUGH	FUN_02005660@02005660
0200571c	0216	2	mov	mov r2,r0	FALL_THROUGH	FUN_02005660@02005660
0200571e	1087	2	rep	rep #0x4,#0x8	FALL_THROUGH	FUN_02005660@02005660
02005720	2307	2	lb.z	lb.z r3,[r2 ++= 1]	FALL_THROUGH	FUN_02005660@02005660
02005722	9307	2	sb	sb r3,[r1 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660
02005724	0948	2	lb.z	lb.z r1,[r0 + 0x8]	FALL_THROUGH	FUN_02005660@02005660
02005726	d94a	2	sb	sb r1,[r5 + 0xa]	FALL_THROUGH	FUN_02005660@02005660
02005728	54ee0910	4	lb.s	lb.s r1,[r0+#0x9]	FALL_THROUGH	FUN_02005660@02005660
0200572c	62e10710	4	and	and r2,r1,#0x7	FALL_THROUGH	FUN_02005660@02005660
02005730	da4b	2	sb	sb r2,[r5 + 0xb]	FALL_THROUGH	FUN_02005660@02005660
02005732	91a3	2	lsr	lsr r1,r1,0x3	FALL_THROUGH	FUN_02005660@02005660
02005734	d94c	2	sb	sb r1,[r5 + 0xc]	FALL_THROUGH	FUN_02005660@02005660
02005736	598d	2	add	add r1,r5,#0xd	FALL_THROUGH	FUN_02005660@02005660
02005738	0a8a	2	add	add r2,r0,#0xa	FALL_THROUGH	FUN_02005660@02005660
0200573a	1083	2	rep	rep #0x4,#0x4	FALL_THROUGH	FUN_02005660@02005660
0200573c	2307	2	lb.z	lb.z r3,[r2 ++= 1]	FALL_THROUGH	FUN_02005660@02005660
0200573e	9307	2	sb	sb r3,[r1 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660
02005740	094e	2	lb.z	lb.z r1,[r0 + 0xe]	FALL_THROUGH	FUN_02005660@02005660
02005742	72e1fe10	4	and	and r2,r1,#0xffffff01	FALL_THROUGH	FUN_02005660@02005660
02005746	13e1a04a	4	add	add r3,r4,0x1aa0	FALL_THROUGH	FUN_02005660@02005660
0200574a	b2f18c10	4	uextra	uextra r2,r1,0x1,0x3	FALL_THROUGH	FUN_02005660@02005660
0200574e	ba41	2	_sb	_sb r2,[r3 + 0x1]	FALL_THROUGH	FUN_02005660@02005660
02005750	19d7	2	sxtb	sxtb r1,r1	FALL_THROUGH	FUN_02005660@02005660
02005752	ba42	2	_sb	_sb r2,[r3 + 0x2]	FALL_THROUGH	FUN_02005660@02005660
02005754	91a4	2	lsr	lsr r1,r1,0x4	FALL_THROUGH	FUN_02005660@02005660
02005756	b943	2	sb	sb r1,[r3 + 0x3]	FALL_THROUGH	FUN_02005660@02005660
02005758	094f	2	lb.z	lb.z r1,[r0 + 0xf]	FALL_THROUGH	FUN_02005660@02005660
0200575a	b944	2	sb	sb r1,[r3 + 0x4]	FALL_THROUGH	FUN_02005660@02005660
0200575c	5995	2	add	add r1,r5,#0x15	FALL_THROUGH	FUN_02005660@02005660
0200575e	c030	2	add	add r0,#0x10	FALL_THROUGH	FUN_02005660@02005660
02005760	1089	2	rep	rep #0x4,#0xa	FALL_THROUGH	FUN_02005660@02005660
02005762	0207	2	lb.z	lb.z r2,[r0 ++= 1]	FALL_THROUGH	FUN_02005660@02005660
02005764	9207	2	sb	sb r2,[r1 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660
02005766	483f	2	mov	mov r0,#0x3f	FALL_THROUGH	FUN_02005660@02005660
02005768	16f1b04a	4	add	add r6,r4,0x1ab0	FALL_THROUGH	FUN_02005660@02005660
0200576c	b84f	2	_sb	_sb r0,[r3 + 0xf]	FALL_THROUGH	FUN_02005660@02005660
0200576e	6840	2	lb.z	lb.z r0,[r6 + 0x0]	FALL_THROUGH	FUN_02005660@02005660
02005770	bfeaddfe	4	call	call 0x0200552e	UNCONDITIONAL_CALL	FUN_02005660@02005660
02005774	6841	2	lb.z	lb.z r0,[r6 + 0x1]	FALL_THROUGH	FUN_02005660@02005660
02005776	bfea0aff	4	call	call 0x0200558e	UNCONDITIONAL_CALL	FUN_02005660@02005660
0200577a	6842	2	lb.z	lb.z r0,[r6 + 0x2]	FALL_THROUGH	FUN_02005660@02005660
0200577c	bfea3cff	4	call	call 0x020055f8	UNCONDITIONAL_CALL	FUN_02005660@02005660
02005780	6843	2	lb.z	lb.z r0,[r6 + 0x3]	FALL_THROUGH	FUN_02005660@02005660
02005782	bfea53ff	4	call	call 0x0200562c	UNCONDITIONAL_CALL	FUN_02005660@02005660
02005786	42f0a003	4	movz	movz r2,#0x3a0	FALL_THROUGH	FUN_02005660@02005660
0200578a	6846	2	_lb.z	_lb.z r0,[r6 + 0x6]	FALL_THROUGH	FUN_02005660@02005660
0200578c	d1ec4c15	4	ldw	ldw r1,r4,#0x15c	FALL_THROUGH	FUN_02005660@02005660
02005790	52ee1601	4	sb	sb r0,[r1 + 0x16]	FALL_THROUGH	FUN_02005660@02005660
02005794	40e0b901	4	movz	movz r0,#0x1b9	FALL_THROUGH	FUN_02005660@02005660
02005798	d0ec1d09	4	sw	sw r0,[r1 + 0x9c]	FALL_THROUGH	FUN_02005660@02005660
0200579c	40e0a403	4	movz	movz r0,#0x3a4	FALL_THROUGH	FUN_02005660@02005660
020057a0	d8ee4000	4	lb.z	lb.z r0,[r4 + r0]	FALL_THROUGH	FUN_02005660@02005660
020057a4	011d	2	add	add r1,r0,r4	FALL_THROUGH	FUN_02005660@02005660
020057a6	d8ee1012	4	lb.z	lb.z r1,[r1 + r2]	FALL_THROUGH	FUN_02005660@02005660
020057aa	00a5	2	lsl	lsl r0,r0,0x5	FALL_THROUGH	FUN_02005660@02005660
020057ac	1018	2	add	add r0,r1	FALL_THROUGH	FUN_02005660@02005660
020057ae	4018	2	add	add r0,r4	FALL_THROUGH	FUN_02005660@02005660
020057b0	41e09c12	4	movz	movz r1,#0x129c	FALL_THROUGH	FUN_02005660@02005660
020057b4	d8ee0001	4	lb.z	lb.z r0,[r0 + r1]	FALL_THROUGH	FUN_02005660@02005660
020057b8	00f80702	4	je	je r0,0x1,0x020057ca	CONDITIONAL_JUMP	FUN_02005660@02005660
020057bc	8050	2	jnz	jnz r0,0x020057de	CONDITIONAL_JUMP	FUN_02005660@02005660
020057be	13e19a4a	4	add	add r3,r4,0x1a9a	FALL_THROUGH	FUN_02005660@02005660
020057c2	389b	2	add	add r0,r3,#0x1b	FALL_THROUGH	FUN_02005660@02005660
020057c4	3a81	2	add	add r2,r3,#0x1	FALL_THROUGH	FUN_02005660@02005660
020057c6	399a	2	add	add r1,r3,#0x1a	FALL_THROUGH	FUN_02005660@02005660
020057c8	0486	2	goto	goto 0x020057d6	UNCONDITIONAL_JUMP	FUN_02005660@02005660
020057ca	598a	2	add	add r1,r5,#0xa	FALL_THROUGH	FUN_02005660@02005660
020057cc	588b	2	add	add r0,r5,#0xb	FALL_THROUGH	FUN_02005660@02005660
020057ce	02e12550	4	add	add r2,r5,#0x25	FALL_THROUGH	FUN_02005660@02005660
020057d2	03e12450	4	add	add r3,r5,#0x24	FALL_THROUGH	FUN_02005660@02005660
020057d6	3b40	2	lb.z	lb.z r3,[r3 + 0x0]	FALL_THROUGH	FUN_02005660@02005660
020057d8	9b40	2	sb	sb r3,[r1 + 0x0]	FALL_THROUGH	FUN_02005660@02005660
020057da	2940	2	lb.z	lb.z r1,[r2 + 0x0]	FALL_THROUGH	FUN_02005660@02005660
020057dc	8940	2	sb	sb r1,[r0 + 0x0]	FALL_THROUGH	FUN_02005660@02005660
020057de	5804	2	pop	pop {pc,r8,r7,r6,r5,r4}	TERMINATOR	FUN_02005660@02005660
```

```text
020057e0	7504	2	push	push {rets,r5,r4}	FALL_THROUGH	FUN_020057e0@020057e0
020057e2	42f09d1a	4	movz	movz r2,#0x1a9d	FALL_THROUGH	FUN_020057e0@020057e0
020057e6	0162	2	_lw	_lw r1,[r0 + 0x8]	FALL_THROUGH	FUN_020057e0@020057e0
020057e8	c3ff18608001	6	mov	mov r3,#0x1806018	FALL_THROUGH	FUN_020057e0@020057e0
020057ee	13db	2	mul	mul r3,r1	FALL_THROUGH	FUN_020057e0@020057e0
020057f0	0560	2	_lw	_lw r5,[r0 + 0x0]	FALL_THROUGH	FUN_020057e0@020057e0
```

## C-like pseudocode

```c
void factory_loader_02005660(void) {
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
}
```

## Bank D display14/index13 Mooger #1 actual path

- UI-selected fields: bank `D` = zero-based `3` read at `0x01c33260+0x3a4`; preset display `14` = zero-based `13` read at `0x01c33260+0x3a0+bank`.
- record index: `(3*32)+13 = 109`.
- packed 128-byte source: `*(0x01c33260+0x164) + bank*0x1000 + preset*0x80`; clean dump model offset `0x000f7680`; name `Mooger #1 `.
- raw 0xa3 source: `*(0x01c33260+0x164) + 0x4000 + index*0xa3`; clean dump model offset `0x000fc567`.
- dirty/SAVED flag: `0x01c33260+0x129c+index`; persisted table model offset `0x000fd1ed`; clean value `0`.
- destination/live source: `0x01c34c74`; Note event consumer copies first `0x9c` bytes.

Hashes:

- packed128: `cf44a49e6157945f70bb144e42d7add0d88ee8ef1f2658ef8ab4a657e6e6a77c`
- raw163 before loader expansion: `70721f83f029ccbbc99a13c380e7ff15e0b407aa4099824039889cf9c12b39e3`
- pure static 128→156 expansion: `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275`
- simulated live first 0x9c: `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275`
- simulated live full 0xa3 object: `693d0c9d41f72712f64f84ef15c3771b218d24f5a04bebd5e7d39a2bce6dec64`

## Static expansion vs live source differences

First `0x9c` comparison:

- clean Mooger #1 flag=0 path: first `0x9c` bytes are byte-equal to the pure 128→156 expansion.

Full live object tail not represented by a 156-byte static expansion:

- offset `0x9c` live `0x64` (raw before postprocess `0x64`), no byte exists in 156-byte static expansion
- offset `0x9d` live `0x00` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion
- offset `0x9e` live `0x00` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion
- offset `0x9f` live `0x00` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion
- offset `0xa0` live `0x0c` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion
- offset `0xa1` live `0x06` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion
- offset `0xa2` live `0x00` (raw before postprocess `0x00`), no byte exists in 156-byte static expansion

Postprocessing applied for this clean Mooger selection:

```json
[
  {
    "flag": 0,
    "operation": "cur[0xa0]=cur[0x86]; cur[0xa1]=cur[0x87]",
    "before_tail_a0_a1": [
      "0x00",
      "0x00"
    ],
    "after_tail_a0_a1": [
      "0x0c",
      "0x06"
    ]
  }
]
```

Why this matters:

- 0x02005660 first copies a full 0xa3-byte raw record to 0x01c34c74, while the R01-style static expansion materializes only the first 0x9c bytes.
- For the clean Mooger #1 flag=0 path, bytes 0x9c..0xa2 remain live-only tail state; +0xa0/+0xa1 are postprocessed from +0x86/+0x87.
- If the selected +0x129c flag is 1, the branch direction reverses and live bytes +0x86/+0x87, which are inside the 0x9c note source, are overwritten from the tail. That case is not represented by a pure 128-to-156 expansion.
- 0x02005660 also calls four update helpers with cur[0x9c..0x9f] and updates *(+0x15c)+0x16/+0x9c, so the loader has side effects that a static code-cave snapshot cannot reproduce.

## 128→156 expansion plus extra postprocessing evidence

Expansion and raw copy are inside `0x02005682..0x02005766`; helper/UI/flag postprocessing follows:

- `0x02005770` -> `0x0200552e` with source `cur[0x9c] = *(0x01c33260+0x1ab0)`
- `0x02005776` -> `0x0200558e` with source `cur[0x9d] = *(0x01c33260+0x1ab1)`
- `0x0200577c` -> `0x020055f8` with source `cur[0x9e] = *(0x01c33260+0x1ab2)`
- `0x02005782` -> `0x0200562c` with source `cur[0x9f] = *(0x01c33260+0x1ab3)`

- `0x02005786..0x02005798`: writes `cur[0xa2]` to `*(+0x15c)+0x16` and stores `0x1b9` at `*(+0x15c)+0x9c`.
- `0x0200579c..0x020057b4`: recomputes selected `bank*32+preset` and loads `+0x129c[index]`.
- `0x020057b8..0x020057dc`: flag `0` copies `cur[0x86..0x87]` to tail `cur[0xa0..0xa1]`; flag `1` copies tail `cur[0xa0..0xa1]` back into `cur[0x86..0x87]`.

### Tail-driven state initialization

For clean Mooger #1, `cur[0x9c..0x9f] = 64 00 00 00`:

- `0x0200552e(100)` clears `0x01c33260+0x16`; values `0..99` instead calculate/store a derived value at `0x01c08b10+0x10` and set the flag.
- `0x0200558e(0)` clears `0x01c33260+0x170`; nonzero values initialize the object at `*(0x01c33260+0x16c)` and set the flag.
- `0x020055f8(0)` clears `0x01c33260+0x178`; nonzero values initialize `*(0x01c33260+0x174)` and set the flag.
- `0x0200562c(0)` clears `0x01c33260+0x180`; nonzero values initialize `*(0x01c33260+0x17c)` and set the flag.

```text
0200552e	1004	2	push	push rets	FALL_THROUGH	FUN_0200552e@0200552e
02005530	00fc24c6	4	ja	ja r0,0x63,0x0200557c	CONDITIONAL_JUMP	FUN_0200552e@0200552e
02005534	80ff56470400	6	call	call 0x02049c90	UNCONDITIONAL_CALL	FUN_0200552e@0200552e
0200553a	c2ff33624481	6	mov	mov r2,#0x81446233	FALL_THROUGH	FUN_0200552e@0200552e
02005540	c3ffe6dd1140	6	mov	mov r3,#0x4011dde6	FALL_THROUGH	FUN_0200552e@0200552e
02005546	80ff8c2c0400	6	call	call 0x020481d8	UNCONDITIONAL_CALL	FUN_0200552e@0200552e
0200554c	c3ff3653f83e	6	mov	mov r3,#0x3ef85336	FALL_THROUGH	FUN_0200552e@0200552e
02005552	60e00024	4	mov	mov r2,#0x80000000	FALL_THROUGH	FUN_0200552e@0200552e
02005556	80ff70430400	6	call	call 0x020498cc	UNCONDITIONAL_CALL	FUN_0200552e@0200552e
0200555c	c3ff00005940	6	mov	mov r3,#0x40590000	FALL_THROUGH	FUN_0200552e@0200552e
02005562	4220	2	mov	mov r2,#0x0	FALL_THROUGH	FUN_0200552e@0200552e
02005564	80ff263b0400	6	call	call 0x02049090	UNCONDITIONAL_CALL	FUN_0200552e@0200552e
0200556a	80ffcc460400	6	call	call 0x02049c3c	UNCONDITIONAL_CALL	FUN_0200552e@0200552e
02005570	c1ff108bc001	6	mov	mov r1,#0x1c08b10	FALL_THROUGH	FUN_0200552e@0200552e
02005576	9064	2	sw	sw r0,[r1 + 0x10]	FALL_THROUGH	FUN_0200552e@0200552e
02005578	4121	2	mov	mov r1,#0x1	FALL_THROUGH	FUN_0200552e@0200552e
0200557a	0483	2	goto	goto 0x02005582	UNCONDITIONAL_JUMP	FUN_0200552e@0200552e
0200557c	4120	2	mov	mov r1,#0x0	FALL_THROUGH	FUN_0200552e@0200552e
0200557e	80f805c8	4	jne	jne r0,#0x64,0x0200558c	CONDITIONAL_JUMP	FUN_0200552e@0200552e
02005582	c0ff6032c301	6	mov	mov r0,#0x1c33260	FALL_THROUGH	FUN_0200552e@0200552e
02005588	52ee0611	4	sb	sb r1,[r0 + 0x16]	FALL_THROUGH	FUN_0200552e@0200552e
0200558c	0004	2	pop	pop pc	TERMINATOR	FUN_0200552e@0200552e
0200558e	7404	2	push	push {rets,r4}	FALL_THROUGH	FUN_0200558e@0200558e
02005590	c1ff6032c301	6	mov	mov r1,#0x1c33260	FALL_THROUGH	FUN_0200558e@0200558e
02005596	104a	2	jz	jz r0,0x020055ec	CONDITIONAL_JUMP	FUN_0200558e@0200558e
02005598	42e07001	4	movz	movz r2,#0x170	FALL_THROUGH	FUN_0200558e@0200558e
0200559c	4321	2	mov	mov r3,#0x1	FALL_THROUGH	FUN_0200558e@0200558e
0200559e	d8ee1132	4	sb	sb r3,[r1 + r2]	FALL_THROUGH	FUN_0200558e@0200558e
020055a6	c3ff000080bf	6	mov	mov r3,#0xbf800000	FALL_THROUGH	-
020055b0	c3ff6666e640	6	mov	mov r3,#0x40e66666	FALL_THROUGH	-
020055ba	c3ff0000c642	6	mov	mov r3,#0x42c60000	FALL_THROUGH	-
020055c4	d1ec1c46	4	ldw	ldw r4,r1,#0x16c	FALL_THROUGH	-
020055c8	c1ff98620502	6	mov	mov r1,#0x2056298	FALL_THROUGH	-
020055ce	00a3	2	lsl	lsl r0,r0,0x3	FALL_THROUGH	-
020055d0	1018	2	add	add r0,r1	FALL_THROUGH	-
020055d2	50ec0000	4	ldw	ldw r0_r1,[r0 + 0x0]	FALL_THROUGH	-
020055d6	c3ffcdcc4c3f	6	mov	mov r3,#0x3f4ccccd	FALL_THROUGH	-
020055e0	c262	2	sw	sw r2,[r4 + 0x8]	FALL_THROUGH	-
020055e2	80ffdc460400	6	call	call 0x02049cc4	UNCONDITIONAL_CALL	-
020055e8	c061	2	sw	sw r0,[r4 + 0x4]	FALL_THROUGH	-
020055ea	5404	2	pop	pop {pc,r4}	TERMINATOR	-
020055ec	40e07001	4	movz	movz r0,#0x170	FALL_THROUGH	FUN_0200558e@0200558e
020055f0	4220	2	mov	mov r2,#0x0	FALL_THROUGH	FUN_0200558e@0200558e
020055f2	d8ee1120	4	sb	sb r2,[r1 + r0]	FALL_THROUGH	FUN_0200558e@0200558e
020055f6	5404	2	pop	pop {pc,r4}	TERMINATOR	FUN_0200558e@0200558e
020055f8	c1ff6032c301	6	mov	mov r1,#0x1c33260	FALL_THROUGH	FUN_020055f8@020055f8
020055fe	0050	2	jz	jz r0,0x02005620	CONDITIONAL_JUMP	FUN_020055f8@020055f8
02005600	d1ec1427	4	ldw	ldw r2,r1,#0x174	FALL_THROUGH	FUN_020055f8@020055f8
02005608	c3ff0ad7233c	6	mov	mov r3,#0x3c23d70a	FALL_THROUGH	-
02005610	0203	2	rep	rep 0x2,r2	FALL_THROUGH	-
02005612	a061	2	sw	sw r0,[r2 + 0x4]	FALL_THROUGH	-
02005614	c0ffcdcc4c3f	6	mov	mov r0,#0x3f4ccccd	FALL_THROUGH	-
0200561a	a060	2	sw	sw r0,[r2 + 0x0]	FALL_THROUGH	-
0200561c	4021	2	mov	mov r0,#0x1	FALL_THROUGH	-
0200561e	0481	2	goto	goto 0x02005622	UNCONDITIONAL_JUMP	-
02005620	4020	2	mov	mov r0,#0x0	FALL_THROUGH	FUN_020055f8@020055f8
02005622	42e07801	4	movz	movz r2,#0x178	FALL_THROUGH	FUN_020055f8@020055f8
02005626	d8ee1102	4	sb	sb r0,[r1 + r2]	FALL_THROUGH	FUN_020055f8@020055f8
0200562a	8000	2	rts	rts	TERMINATOR	FUN_020055f8@020055f8
0200562c	c1ff6032c301	6	mov	mov r1,#0x1c33260	FALL_THROUGH	FUN_0200562c@0200562c
02005632	0050	2	jz	jz r0,0x02005654	CONDITIONAL_JUMP	FUN_0200562c@0200562c
02005634	d1ec1c27	4	ldw	ldw r2,r1,#0x17c	FALL_THROUGH	FUN_0200562c@0200562c
0200563c	c3ff0ad7233c	6	mov	mov r3,#0x3c23d70a	FALL_THROUGH	-
02005644	0203	2	rep	rep 0x2,r2	FALL_THROUGH	-
02005646	a06c	2	sw	sw r0,[r2 + 0x30]	FALL_THROUGH	-
02005648	c0ff3333b33e	6	mov	mov r0,#0x3eb33333	FALL_THROUGH	-
0200564e	a06b	2	sw	sw r0,[r2 + 0x2c]	FALL_THROUGH	-
02005650	4021	2	mov	mov r0,#0x1	FALL_THROUGH	-
02005652	0481	2	goto	goto 0x02005656	UNCONDITIONAL_JUMP	-
02005654	4020	2	mov	mov r0,#0x0	FALL_THROUGH	FUN_0200562c@0200562c
02005656	42e08001	4	movz	movz r2,#0x180	FALL_THROUGH	FUN_0200562c@0200562c
0200565a	d8ee1102	4	sb	sb r0,[r1 + r2]	FALL_THROUGH	FUN_0200562c@0200562c
0200565e	8000	2	rts	rts	TERMINATOR	FUN_0200562c@0200562c
```

### Optional caller-side initializer `0x020057e0`

Only the init/refresh caller (`0x02005fa4`) and UI bank/preset caller (`0x02024236`) invoke it immediately after the loader. The two SysEx reload sites and default-bank site do not invoke it locally. Its argument is `r0 = *(0x01c33260+0x15c)`. It consumes current-patch bytes `cur[137]`, `cur[138]`, `cur[141]`, and `cur[142]` through aliases `+0x1a9d`, `+0x1a9e`, `+0x1aa1`, and `+0x1aa2`, then writes derived fields in the pointed object at offsets including `+0x24`, `+0x28`, `+0x2a`, `+0x30`, and `+0x34`. Clean Mooger values for those four bytes are `23 00 01 00`. A static per-note `0x9c` copy does not execute this initializer.

```text
020057e0	7504	2	push	push {rets,r5,r4}	FALL_THROUGH	FUN_020057e0@020057e0
020057e2	42f09d1a	4	movz	movz r2,#0x1a9d	FALL_THROUGH	FUN_020057e0@020057e0
020057e6	0162	2	_lw	_lw r1,[r0 + 0x8]	FALL_THROUGH	FUN_020057e0@020057e0
020057e8	c3ff18608001	6	mov	mov r3,#0x1806018	FALL_THROUGH	FUN_020057e0@020057e0
020057ee	13db	2	mul	mul r3,r1	FALL_THROUGH	FUN_020057e0@020057e0
020057f0	0560	2	_lw	_lw r5,[r0 + 0x0]	FALL_THROUGH	FUN_020057e0@020057e0
020057f2	c1ff6032c301	6	mov	mov r1,#0x1c33260	FALL_THROUGH	FUN_020057e0@020057e0
020057f8	d8ee1042	4	lb.z	lb.z r4,[r1 + r2]	FALL_THROUGH	FUN_020057e0@020057e0
020057fc	f4e13125	4	div.s	div.s r2,r3,r5	FALL_THROUGH	FUN_020057e0@020057e0
02005802	8f22	2	sw	sw r15,[sp+0x8]	FALL_THROUGH	-
02005804	60e07c35	4	mov	mov r3,#0x3f000000	FALL_THROUGH	-
0200580e	5f22	2	mov	mov r7,#0x62	FALL_THROUGH	-
02005810	432b	2	mov	mov r3,#0xb	FALL_THROUGH	-
02005812	044a	2	jz	jz r4,0x02005828	CONDITIONAL_JUMP	-
02005814	e5e1a540	4	mul	mul r5,r4,#0xa5	FALL_THROUGH	-
02005818	d4a6	2	lsr	lsr r4,r5,0x6	FALL_THROUGH	-
0200581a	25e9208d	4	if	if (r5 >= #0x2800) {	FALL_THROUGH	-
0200581e	33e1604f	4	add	add r3,r4,#-0xa0	FALL_THROUGH	-
02005822	bba4	2	qasr	qasr r3,r3,0x4	FALL_THROUGH	-
02005824	c32b	2	add	add r3,#0xb	FALL_THROUGH	-
02005826	0481	2	} 	}  goto 0x0200582a	UNCONDITIONAL_JUMP	-
02005828	4421	2	mov	mov r4,#0x1	FALL_THROUGH	-
0200582a	241b	2	mul	mul r4,r2	FALL_THROUGH	-
0200582c	431b	2	mul	mul r3,r4	FALL_THROUGH	-
0200582e	43f09e1a	4	movz	movz r3,#0x1a9e	FALL_THROUGH	-
02005832	8369	2	_sw	_sw r3,[r0 + 0x24]	FALL_THROUGH	-
02005834	d8ee1033	4	lb.z	lb.z r3,[r1 + r3]	FALL_THROUGH	-
02005838	a5e06330	4	sub	sub r5,#0x63,r3	FALL_THROUGH	-
0200583c	133f	2	movs	movs r3,#-0x1	FALL_THROUGH	-
0200583e	143f	2	movs	movs r4,#-0x1	FALL_THROUGH	-
02005840	05f810c6	4	je	je r5,0x63,0x02005864	CONDITIONAL_JUMP	-
02005844	dba4	2	qasr	qasr r3,r5,0x4	FALL_THROUGH	-
02005846	c321	2	add	add r3,#0x1	FALL_THROUGH	-
02005848	64e10f50	4	and	and r4,r5,#0xf	FALL_THROUGH	-
0200584c	3424	2	bitset	bitset r4,0x4	FALL_THROUGH	-
0200584e	341a	2	lsl	lsl r4,r3	FALL_THROUGH	-
02005850	f0e14032	4	mul	mul r3,r4,r2	FALL_THROUGH	-
02005854	c5ff80ff0000	6	mov	mov r5,#0xff80	FALL_THROUGH	-
0200585a	d419	2	not	not r4,r5	FALL_THROUGH	-
0200585c	b4ec8000	4	if	if (r4 <= #0x80) {	FALL_THROUGH	-
02005860	6420	2	mov	mov r4,#0x80	FALL_THROUGH	-
02005862	241b	2	} 	}  mul r4, r2	FALL_THROUGH	-
02005864	42f0a21a	4	movz	movz r2,#0x1aa2	FALL_THROUGH	-
02005868	836c	2	_sw	_sw r3,[r0 + 0x30]	FALL_THROUGH	-
0200586a	846d	2	sw	sw r4,[r0 + 0x34]	FALL_THROUGH	-
0200586c	d8ee1022	4	lb.z	lb.z r2,[r1 + r2]	FALL_THROUGH	-
02005870	52ee0822	4	sb	sb r2,[r0 + 0x28]	FALL_THROUGH	-
02005874	42e0a11a	4	movz	movz r2,#0x1aa1	FALL_THROUGH	-
02005878	d8ee1022	4	lb.z	lb.z r2,[r1 + r2]	FALL_THROUGH	-
0200587c	4121	2	mov	mov r1,#0x1	FALL_THROUGH	-
0200587e	8241	2	jnz	jnz r2,0x02005882	CONDITIONAL_JUMP	-
02005880	2116	2	mov	mov r1,r2	FALL_THROUGH	-
02005882	52ee0a12	4	sb	sb r1,[r0 + 0x2a]	FALL_THROUGH	-
02005886	5504	2	pop	pop {pc,r5,r4}	TERMINATOR	-
```

## Static Mooger mismatch: proved facts and limit

- Proven: the recorded R01c blob hash `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` and this clean-data loader model's first `0x9c` hash `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275` compare `EQUAL`.
- Proven: the stock loader additionally owns bytes `0x9c..0xa2`, executes four tail helpers, writes through `*(+0x15c)`, and on two normal selection paths is followed by `0x020057e0`; the static Note On/Off wrapper executed none of those producers.
- Limited: the first-`0x9c` equality is a static model comparison, not a captured official-device RAM image or independent instruction-level emulation. The listing also has decoder gaps/mislabels inside the dense bitfield loop, so the model is supported by address/dataflow consistency but is not a runtime oracle.
- Not proven: which omitted state, if any, caused the reported continuously falling pitch. The experiment also changed dispatch calls and did not record the contemporaneous UI patch/global synth state. The correct conclusion is that direct snapshot injection bypassed a proven lifecycle and cannot establish Mooger #1 identity, not that one specific tail byte or helper is the demonstrated acoustic root cause.

## Return consumers and live source consumer

### `0x02005f9c` caller

```text
02005f80	40e0a603	4	movz	movz r0,#0x3a6	FALL_THROUGH	-
02005f84	d8ee6000	4	lb.z	lb.z r0,[r6 + r0]	FALL_THROUGH	-
02005f88	d1ec6c15	4	ldw	ldw r1,r6,#0x15c	FALL_THROUGH	-
02005f8c	52ee1004	4	sb	sb r0,[r1 + 0x40]	FALL_THROUGH	-
02005f90	40e0a703	4	movz	movz r0,#0x3a7	FALL_THROUGH	-
02005f94	d8ee6000	4	lb.z	lb.z r0,[r6 + r0]	FALL_THROUGH	-
02005f98	52ee1104	4	sb	sb r0,[r1 + 0x41]	FALL_THROUGH	-
02005f9c	bfea60fb	4	call	call 0x02005660	UNCONDITIONAL_CALL	-
02005fa0	d1ec6c05	4	ldw	ldw r0,r6,#0x15c	FALL_THROUGH	-
02005fa4	bfea1cfc	4	call	call 0x020057e0	UNCONDITIONAL_CALL	-
02005fa8	028b	2	add	add sp,#0x2c	FALL_THROUGH	-
02005faa	5f04	2	pop	pop {pc,r15,r14,r13,r12,r11,r10,r9,r8,r7,r6,r5,r4}	TERMINATOR	-
```

### `0x0201e46c` caller

```text
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
0201e468	bfea69fe	4	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e46c	bfeaf838	4	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e470	5904	2	pop	pop {pc,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_0201e254@0201e254
```

### `0x0201e4a0` caller

```text
0201e480	91f849ee	4	jne	jne r1,#0xf7	CONDITIONAL_JUMP	FUN_0201e254@0201e254
0201e484	95f8583c	4	jne	jne r5,#0x9e	CONDITIONAL_JUMP	FUN_0201e254@0201e254
0201e488	06e1a06f	4	add	add r6,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254
0201e48c	6018	2	add	add r0,r6	FALL_THROUGH	FUN_0201e254@0201e254
0201e48e	32e1fe9f	4	add	add r2,r9,#-0x2	FALL_THROUGH	FUN_0201e254@0201e254
0201e492	4116	2	mov	mov r1,r4	FALL_THROUGH	FUN_0201e254@0201e254
0201e494	80ff34a80200	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e49a	6016	2	mov	mov r0,r6	FALL_THROUGH	FUN_0201e254@0201e254
0201e49c	bfea4ffe	4	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e4a0	bfeade38	4	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254
0201e4a4	2489	2	goto	goto 0x0201e538	UNCONDITIONAL_JUMP	FUN_0201e254@0201e254
```

### `0x0202422e` UI bank/preset caller

```text
020241e0	7904	2	push	push {rets,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_020241e0@020241e0
020241e2	48e0a403	4	movz	movz r8,#0x3a4	FALL_THROUGH	FUN_020241e0@020241e0
020241e6	c5ff6032c301	6	mov	mov r5,#0x1c33260	FALL_THROUGH	FUN_020241e0@020241e0
020241ec	d8ee5078	4	lb.z	lb.z r7,[r5 + r8]	FALL_THROUGH	FUN_020241e0@020241e0
020241f0	7e1d	2	add	add r6,r7,r5	FALL_THROUGH	FUN_020241e0@020241e0
020241f2	49e0a003	4	movz	movz r9,#0x3a0	FALL_THROUGH	FUN_020241e0@020241e0
020241f6	d8ee6049	4	lb.z	lb.z r4,[r6 + r9]	FALL_THROUGH	FUN_020241e0@020241e0
020241fa	80e80a70	4	jne	jne r7,r0,0x02024212	CONDITIONAL_JUMP	FUN_020241e0@020241e0
020241fe	4220	2	mov	mov r2,#0x0	FALL_THROUGH	FUN_020241e0@020241e0
02024200	433f	2	mov	mov r3,#0x1f	FALL_THROUGH	FUN_020241e0@020241e0
02024202	4016	2	mov	mov r0,r4	FALL_THROUGH	FUN_020241e0@020241e0
02024204	bfea5dbc	4	call	call 0x0201bac2	CALL_TERMINATOR	FUN_020241e0@020241e0
02024208	d8ee6109	4	sb	sb r0,[r6 + r9]	FALL_THROUGH	-
0202420c	d8ee5008	4	lb.z	lb.z r0,[r5 + r8]	FALL_THROUGH	-
02024210	0482	2	goto	goto 0x02024216	UNCONDITIONAL_JUMP	-
02024212	d8ee5108	4	sb	sb r0,[r5 + r8]	FALL_THROUGH	FUN_020241e0@020241e0
02024216	0017	2	uxtb	uxtb r0,r0	FALL_THROUGH	FUN_020241e0@020241e0
02024218	80e80570	4	jne	jne r7,r0,0x02024226	CONDITIONAL_JUMP	FUN_020241e0@020241e0
0202421c	9016	2	mov	mov r0,r9	FALL_THROUGH	FUN_020241e0@020241e0
0202421e	d8ee6000	4	lb.z	lb.z r0,[r6 + r0]	FALL_THROUGH	FUN_020241e0@020241e0
02024222	00e80a40	4	je	je r4,r0,0x0202423a	CONDITIONAL_JUMP	FUN_020241e0@020241e0
02024226	d1ec5c05	4	ldw	ldw r0,r5,#0x15c	FALL_THROUGH	FUN_020241e0@020241e0
0202422a	bfea21ff	4	call	call 0x02024070	UNCONDITIONAL_CALL	FUN_020241e0@020241e0
0202422e	bfea170a	4	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_020241e0@020241e0
02024232	d1ec5c05	4	ldw	ldw r0,r5,#0x15c	FALL_THROUGH	FUN_020241e0@020241e0
02024236	bfead30a	4	call	call 0x020057e0	UNCONDITIONAL_CALL	FUN_020241e0@020241e0
0202423a	5904	2	pop	pop {pc,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_020241e0@020241e0
```

### `0x020255a6` default-load caller

```text
0202553c	60e1fc90	4	and	and r0,r9,#0xfc	FALL_THROUGH	-
02025540	00fc3706	4	ja	ja r0,0x3,0x020255b2	CONDITIONAL_JUMP	-
02025544	81f83f02	4	jne	jne r1,#0x1,0x020255c6	CONDITIONAL_JUMP	-
02025548	40e01417	4	movz	movz r0,#0x1714	FALL_THROUGH	-
0202554c	d8ee8190	4	sb	sb r9,[r8 + r0]	FALL_THROUGH	-
02025550	d1ec8006	4	ldw	ldw r0,r8,#0x160	FALL_THROUGH	-
02025554	75e17f9c	4	and	and r5,r9,#0xffff00ff	FALL_THROUGH	-
02025558	51ac	2	lsl	lsl r1,r5,0xc	FALL_THROUGH	-
0202555a	0c1c	2	add	add r4,r0,r1	FALL_THROUGH	-
0202555c	4022	2	mov	mov r0,#0x2	FALL_THROUGH	-
0202555e	4116	2	mov	mov r1,r4	FALL_THROUGH	-
02025560	beea78fa	4	call	call 0x02004a54	UNCONDITIONAL_CALL	-
02025564	00e1a0af	4	add	add r0,r10,#0xfa0	FALL_THROUGH	-
02025568	42e00010	4	movz	movz r2,#0x1000	FALL_THROUGH	-
0202556c	4116	2	mov	mov r1,r4	FALL_THROUGH	-
0202556e	beeac8fa	4	call	call 0x02004b02	UNCONDITIONAL_CALL	-
02025572	10e19c82	4	add	add r0,r8,0x129c	FALL_THROUGH	-
02025576	51a5	2	lsl	lsl r1,r5,0x5	FALL_THROUGH	-
02025578	0118	2	add	add r1,r0	FALL_THROUGH	-
0202557a	109f	2	rep	rep #0x4,#0x20	FALL_THROUGH	-
0202557c	d2ee11b0	4	sb	sb r11,[r1++=#0x1]	FALL_THROUGH	-
02025580	d1ec8016	4	ldw	ldw r1,r8,#0x160	FALL_THROUGH	-
02025584	c2ff80910000	6	mov	mov r2,#0x9180	FALL_THROUGH	-
0202558a	2118	2	add	add r1,r2	FALL_THROUGH	-
0202558c	6220	2	mov	mov r2,#0x80	FALL_THROUGH	-
0202558e	beeab8fa	4	call	call 0x02004b02	UNCONDITIONAL_CALL	-
02025592	40e0a403	4	movz	movz r0,#0x3a4	FALL_THROUGH	-
02025596	d8ee8190	4	sb	sb r9,[r8 + r0]	FALL_THROUGH	-
0202559a	b4e05008	4	add	add r0,r5,r8	FALL_THROUGH	-
0202559e	41e0a003	4	movz	movz r1,#0x3a0	FALL_THROUGH	-
020255a2	d8ee01b1	4	sb	sb r11,[r0 + r1]	FALL_THROUGH	-
020255a6	bfea5b00	4	call	call 0x02005660	UNCONDITIONAL_CALL	-
020255aa	5824	2	mov	mov r0,#0x64	FALL_THROUGH	-
```

### `0x01c34c74` Note On/Off consumer

```text
0201c5ec	7a04	2	push	push {rets,r10,r9,r8,r7,r6,r5,r4}	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c5ee	1b40	2	lb.z	lb.z r3,[r1 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c5f0	b4a4	2	lsr	lsr r4,r3,0x4	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c5f2	56e10840	4	xor	xor r6,r4,#0x8	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c5f6	07e13c00	4	add	add r7,r0,#0x3c	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c5fa	06fc4e0a	4	ja	ja r6,0x5,0x0201c69a	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c5fe	79e1f030	4	and	and r9,r3,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c602	c8ff744cc301	6	mov	mov r8,#0x1c34c74	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c608	0c8c	2	add	add r4,r0,#0xc	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c60a	0ae1a000	4	add	add r10,r0,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c60e	0601	2	tbb	tbb r6	COMPUTED_JUMP	FUN_0201c5ec@0201c5ec
0201c616	82fd7b06	4	jl	jl r2,#0x3,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c61a	50eea120	4	lb.z	lb.z r2,[r10 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c61e	50eea040	4	lb.z	lb.z r4,[r10 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c622	c21e	2	sub	sub r2,r4,r2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c624	2217	2	uxtb	uxtb r2,r2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c626	02fc731e	4	ja	ja r2,0xf,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c62a	72f1f040	4	and	and r2,r4,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c62e	1d41	2	_lb.z	_lb.z r5,[r1 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c630	e1e1a020	4	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c634	0e1c	2	add	add r6,r0,r1	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c636	00e1a260	4	add	add r0,r6,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c63a	623c	2	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c63c	8116	2	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c63e	80ff8ac60200	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec
0201c644	00e13e61	4	add	add r0,r6,#0x13e	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c648	8d40	2	sb	sb r5,[r0 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c64a	52ee0190	4	sb	sb r1,[r0 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c64e	5135	2	mov	mov r1,#0x55	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c650	049f	2	goto	goto 0x0201c690	UNCONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c652	82fd5d06	4	jl	jl r2,#0x3,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c656	50eea120	4	lb.z	lb.z r2,[r10 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c65a	50eea040	4	lb.z	lb.z r4,[r10 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c65e	c21e	2	sub	sub r2,r4,r2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c660	2217	2	uxtb	uxtb r2,r2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c662	02fc551e	4	ja	ja r2,0xf,0x0201c710	CONDITIONAL_JUMP	FUN_0201c5ec@0201c5ec
0201c666	72f1f040	4	and	and r2,r4,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c66a	1d42	2	_lb.z	_lb.z r5,[r1 + 0x2]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c66c	e1f1a020	4	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c670	1e41	2	_lb.z	_lb.z r6,[r1 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c672	0f1c	2	add	add r7,r0,r1	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c674	00e1a270	4	add	add r0,r7,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c678	623c	2	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c67a	8116	2	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c67c	80ff4cc60200	6	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec
0201c682	00e13e71	4	add	add r0,r7,#0x13e	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c686	8e40	2	sb	sb r6,[r0 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c688	52ee0190	4	sb	sb r1,[r0 + 0x1]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c68c	8d42	2	sb	sb r5,[r0 + 0x2]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c68e	5124	2	mov	mov r1,#0x44	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c690	8943	2	sb	sb r1,[r0 + 0x3]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c692	4881	2	add	add r0,r4,#0x1	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c694	52eea000	4	sb	sb r0,[r10 + 0x0]	FALL_THROUGH	FUN_0201c5ec@0201c5ec
0201c698	5a04	2	pop	pop {pc,r10,r9,r8,r7,r6,r5,r4}	TERMINATOR	FUN_0201c5ec@0201c5ec
```

## Reproduction

```sh
python3 baselines/v15/analysis/channel-separation-reanalysis/factory-loader/analyze_factory_loader.py
```

The command regenerates `factory_loader_evidence.json` and this report from official-v15 primary evidence plus the recorded R01c comparison manifest. It does not patch or flash anything.
