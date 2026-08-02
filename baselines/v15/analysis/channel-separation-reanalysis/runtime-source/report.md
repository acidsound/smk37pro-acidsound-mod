# v15 runtime source trace for 0x01c34c74

Scope: official v15 only. This pass reads `build/v15-official-app.bin` and v15 Quarkslab/Kagaimiq listings only. It performs no patching and no flashing.

## SHA gates

- app: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` (PASS)
- Quarkslab exhaustive listing: `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` (PASS)
- Kagaimiq exhaustive listing: `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013`

## 결론

- `0x01c34c74`는 독립 static DX7 blob이 아니라 `0x01c33260 + 0x1a14`인 **현재 패치 runtime snapshot**이다.
- direct absolute raw pointer는 `0x0201c604`의 immediate 하나뿐이며, 이는 `0x0201c5ec` consumer가 `r8=0x01c34c74`를 만드는 행이다. writer는 base alias `0x01c33260 + 0x1a14`로 나타난다.
- 주 writer는 `0x02005660`이다. selected bank/preset으로 backing record를 고른 뒤 `memcpy(0x01c34c74, backing+0x4000+index*0xa3, 0xa3)`를 수행하고 packed fields를 current snapshot 안에 확장한다.
- UI/current patch 변경은 `0x0201e254`가 bulk payload를 staging에 받고 `0x0201e13e`로 selected backing record에 pack한 뒤 `0x02005660`을 호출해 `0x01c34c74`를 갱신하는 경로와, 7-byte `F0 43 10 ... F7`가 `0x01c34c74+idx`에 직접 1 byte를 쓰는 경로가 있다.
- `0x0201c5ec`의 `0x9c` copy는 Note On/Off 시 현재 패치 snapshot의 tone/program 파라미터 부분을 per-voice slot `engine + voice*0xa0 + 0xa2`로 복제하는 소비 경로다. pitch bend는 별도 `E0` path에서 `engine+0x3e` 14-bit 값을 갱신하므로, Note On 중 pitch 하강은 static snapshot target-tone 가설의 근거가 아니다.
- current source 대상 memset/fill writer는 이 trace에서 발견되지 않았다. 확인된 갱신은 `memcpy`, field-wise stores, 그리고 backing-record producer 후 reload이다.

## Raw xref summary

- `current_source_buffer_0x01c34c74` `0x01c34c74`: count `1`, refs `0x0201c604`
- `ram_object_base_0x01c33260` `0x01c33260`: count `492`, refs `0x02000696`, `0x020006a8`, `0x020006ba`, `0x020006d0`, `0x020006de`, `0x020006f0`, `0x020007ea`, `0x02000816`, `0x0200083e`, `0x02000856`, `0x0200089c`, `0x02000d56`
- `current_source_end_0x01c34d10` `0x01c34d10`: count `0`, refs none
- `dispatcher_0x0201c5ec` `0x0201c5ec`: count `0`, refs none
- `factory_loader_0x02005660` `0x02005660`: count `0`, refs none
- `current_packer_0x0201e13e` `0x0201e13e`: count `0`, refs none
- `storage_transfer_0x02004b02` `0x02004b02`: count `0`, refs none
- `memcpy_0x02048cce` `0x02048cce`: count `0`, refs none

## Writers/producers/consumers

### record_loader_to_current_snapshot

- kind: `memcpy`
- destination: `0x01c33260+0x1a14 == 0x01c34c74`
- source: `*(0x01c33260+0x164)+0x4000+(bank*32+preset)*0xa3`
- length: `0xa3`
- summary: 0x02005660 computes (selected_bank*32+selected_preset)*0xa3 from *(0x01c33260+0x164), adds 0x4000, and memcpy()s 0xa3 bytes into 0x01c33260+0x1a14.
- key rows:
  - `02005682	d1ec4476	ldw	ldw r7,r4,#0x164	FALL_THROUGH	FUN_02005660@02005660`
  - `0200568a	e0e1a300	mul	mul r0,r0,#0xa3	FALL_THROUGH	FUN_02005660@02005660`
  - `02005690	e1e0800c	add	add r1,r0,0x4000	FALL_THROUGH	FUN_02005660@02005660`
  - `02005694	10e1144a	add	add r0,r4,0x1a14	FALL_THROUGH	FUN_02005660@02005660`
  - `02005698	6a23	mov	mov r2,#0xa3	FALL_THROUGH	FUN_02005660@02005660`
  - `0200569a	80ff2e360400	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_02005660@02005660`

### packed_record_normalization_inside_current_snapshot

- kind: `field_wise_expand`
- destination: `0x01c33260+0x1a14..+0x1a91 field aliases`
- source: `selected packed bank record bytes`
- summary: After the raw 0xa3 copy, 0x02005660 loops over 0x7e bytes in 0x15-byte logical operator blocks and rewrites unpacked fields into the same current snapshot area starting at +0x1a14 and +0x1a24.
- key rows:
  - `020056b4	231d	add	add r3,r2,r4	FALL_THROUGH	FUN_02005660@02005660`
  - `020056b6	15e1143a	add	add r5,r3,0x1a14	FALL_THROUGH	FUN_02005660@02005660`
  - `020056c0	108a	rep	rep #0x4,#0xb	FALL_THROUGH	FUN_02005660@02005660`
  - `020056c4	f007	sb	sb r0,[r7 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660`
  - `020056c6	185b	lb.z	lb.z r0,[r1 + -0x5]	FALL_THROUGH	FUN_02005660@02005660`
  - `020056d0	de4b	_sb	_sb r6,[r5 + 0xb]	FALL_THROUGH	FUN_02005660@02005660`
  - `020056d2	d84c	sb	sb r0,[r5 + 0xc]	FALL_THROUGH	FUN_02005660@02005660`
  - `020056de	13f1243a	add	add r3,r3,0x1a24	FALL_THROUGH	-`
  - `0200570e	82f8d1fd	jne	jne r2,#0x7e,0x020056b4	CONDITIONAL_JUMP	FUN_02005660@02005660`

### global_tail_normalization_inside_current_snapshot

- kind: `field_wise_expand`
- destination: `0x01c33260+0x1a90 and 0x01c33260+0x1aa0`
- source: `selected packed bank record tail`
- summary: 0x02005660 also expands the record tail into +0x1a90/+0x1aa0 and reads +0x1ab0 flags that drive helper updates.
- key rows:
  - `02005712	15e1904a	add	add r5,r4,0x1a90	FALL_THROUGH	FUN_02005660@02005660`
  - `02005720	2307	lb.z	lb.z r3,[r2 ++= 1]	FALL_THROUGH	FUN_02005660@02005660`
  - `02005726	d94a	sb	sb r1,[r5 + 0xa]	FALL_THROUGH	FUN_02005660@02005660`
  - `02005746	13e1a04a	add	add r3,r4,0x1aa0	FALL_THROUGH	FUN_02005660@02005660`
  - `02005764	9207	sb	sb r2,[r1 ++= 1]	CONDITIONAL_JUMP	FUN_02005660@02005660`
  - `02005768	16f1b04a	add	add r6,r4,0x1ab0	FALL_THROUGH	FUN_02005660@02005660`

### single_parameter_current_patch_write

- kind: `field_write`
- destination: `0x01c33260+0x1a14+(parameter_index & 0xff)`
- source: `UI/SysEx message byte msg[5]`
- length: `0x01`
- summary: 0x0201e254 recognizes a 7-byte F0 43 10 ... F7 message and stores msg[5] to 0x01c33260+0x1a14+((msg[3]<<7)+msg[4] & 0xff). This is a direct current-patch field writer.
- key rows:
  - `0201e622	42f0141a	movz	movz r2,#0x1a14	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e626	4843	_lb.z	_lb.z r0,[r4 + 0x3]	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e62a	00a7	lsl	lsl r0,r0,0x7	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e630	0017	uxtb	uxtb r0,r0	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e632	7018	add	add r0,r7	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e634	d8ee0112	sb	sb r1,[r0 + r2]	FALL_THROUGH	FUN_0201e254@0201e254`

### bulk_ui_patch_block_to_storage_then_current_snapshot_reload

- kind: `producer_then_reload`
- destination: `selected backing record, then 0x01c34c74 via 0x02005660`
- source: `UI/SysEx bulk patch payload staged at 0x01c37030+0xfa0`
- summary: 0x0201e254 copies incoming bulk patch data to staging at 0x01c37030+0xfa0, calls 0x0201e13e to pack that expanded patch to the selected backing record, then calls 0x02005660 so the backing record is reloaded into 0x01c34c74.
- key rows:
  - `0201e448	08e1a06f	add	add r8,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e456	80ff72a80200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e468	bfea69fe	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e46c	bfeaf838	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e488	06e1a06f	add	add r6,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e494	80ff34a80200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e49c	bfea4ffe	call	call 0x0201e13e	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e4a0	bfeade38	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e580	00e1a06f	add	add r0,r6,#0xfa0	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201e58c	80ff3ca70200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201e254@0201e254`
  - `0201e592	50ed7d49	sh	sh r4,[r7 + 0x9c]	FALL_THROUGH	FUN_0201e254@0201e254`

### bank_or_preset_selection_reload

- kind: `producer_then_reload`
- destination: `0x01c34c74 via 0x02005660`
- source: `selected bank/preset backing record`
- summary: Bank/preset UI state writes update +0x3a4/+0x3a0 and call 0x02005660. They do not write 0x01c34c74 directly, but they select which packed record becomes the current runtime source buffer.
- key rows:
  - `02024212	d8ee5108	sb	sb r0,[r5 + r8]	FALL_THROUGH	FUN_020241e0@020241e0`
  - `0202422e	bfea170a	call	call 0x02005660	UNCONDITIONAL_CALL	FUN_020241e0@020241e0`
  - `02025592	40e0a403	movz	movz r0,#0x3a4	FALL_THROUGH	-`
  - `020255a2	d8ee01b1	sb	sb r11,[r0 + r1]	FALL_THROUGH	-`
  - `020255a6	bfea5b00	call	call 0x02005660	UNCONDITIONAL_CALL	-`

### no_memset_or_clear_to_current_source_found

- kind: `negative_memset_trace`
- destination: `0x01c34c74 / 0x01c33260+0x1a14`
- summary: Quarkslab/Kagaimiq listings and raw immediate xrefs show memcpy and byte stores for 0x01c34c74/current aliases. No memset-style clear/fill call is present on the current source destination in the traced writer paths.
- key rows:
  - `02005694	10e1144a	add	add r0,r4,0x1a14	FALL_THROUGH	FUN_02005660@02005660`
  - `0200569a	80ff2e360400	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_02005660@02005660`
  - `0201e634	d8ee0112	sb	sb r1,[r0 + r2]	FALL_THROUGH	FUN_0201e254@0201e254`
  - `0201c63e	80ff8ac60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`
  - `0201c67c	80ff4cc60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`

### note_off_copy_current_to_voice_slot

- kind: `consumer_copy`
- destination: `dispatcher_r0 + voice_index*0xa0 + 0xa2`
- source: `0x01c34c74`
- length: `0x9c`
- summary: 0x0201c5ec Note Off-class path copies 0x9c bytes from 0x01c34c74 into a per-voice slot at engine+voice*0xa0+0xa2.
- key rows:
  - `0201c602	c8ff744cc301	mov	mov r8,#0x1c34c74	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c630	e1e1a020	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c636	00e1a260	add	add r0,r6,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c63a	623c	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c63c	8116	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c63e	80ff8ac60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`

### note_on_copy_current_to_voice_slot

- kind: `consumer_copy`
- destination: `dispatcher_r0 + voice_index*0xa0 + 0xa2`
- source: `0x01c34c74`
- length: `0x9c`
- summary: 0x0201c5ec Note On-class path copies the same 0x9c bytes from 0x01c34c74 into the per-voice slot, then writes note/velocity/event metadata after the copied block.
- key rows:
  - `0201c602	c8ff744cc301	mov	mov r8,#0x1c34c74	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c666	72f1f040	and	and r2,r4,#0xffffff0f	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c66c	e1f1a020	mul	mul r1,r2,#0xa0	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c674	00e1a270	add	add r0,r7,#0xa2	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c678	623c	mov	mov r2,#0x9c	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c67a	8116	mov	mov r1,r8	FALL_THROUGH	FUN_0201c5ec@0201c5ec`
  - `0201c67c	80ff4cc60200	call	call 0x02048cce	UNCONDITIONAL_CALL	FUN_0201c5ec@0201c5ec`

## 0x0201c5ec의 정확한 0x9c 구조 의미

`0x0201c5ec`는 MIDI-like channel message dispatcher다. `msg[0] >> 4`로 status class를 분기하고, `msg[0] & 0x0f`를 channel nibble로 만든다. Note Off 및 Note On class에서 공통으로 `r8=0x01c34c74`, `r2=0x9c`, `r0=engine + voice*0xa0 + 0xa2`, `r1=r8`를 세팅한 뒤 `0x02048cce`를 호출한다. 따라서 복사되는 `0x9c`는 current patch snapshot 중 per-note voice가 필요한 tone/program parameter block이고, 뒤의 `slot+0x13e..0x141` bytes는 note, velocity, event marker 같은 runtime metadata이다. `0xa0` voice stride = `0x9c` copied tone bytes + 4 metadata bytes로 해석된다.

## Address-level C pseudocode

### `0x02005660`

```c
void load_selected_patch_to_current(void) {
    obj = (uint8_t *)0x01c33260;
    bank = obj[0x3a4]; if (bank > 3) return;
    preset = obj[0x3a0 + bank]; if (preset > 31) return;
    record = *(uint8_t **)(obj + 0x164) + 0x4000 + ((bank * 32 + preset) * 0xa3);
    memcpy(obj + 0x1a14, record, 0xa3);
    // expand/normalize packed operator blocks and tail fields in-place
    expand_6_operator_blocks_and_global_tail(record, obj + 0x1a14, obj + 0x1a90, obj + 0x1aa0);
    apply_current_patch_helper_flags(obj + 0x1ab0);
    update_save_saved_display_from_flag(obj[0x129c + bank * 32 + preset]);
}
```

### `0x0201e254:bulk-current-patch-paths`

```c
void ui_sysex_bulk_patch_path(uint8_t *msg, uint32_t len) {
    obj = (uint8_t *)0x01c33260;
    stage = (uint8_t *)0x01c37030 + 0xfa0;
    if (matches_bulk_patch_header_and_f7(msg, len)) {
        memcpy(stage + current_stream_offset, msg + payload_offset, payload_len);
        pack_expanded_current_patch_to_selected_record(stage); // 0x0201e13e
        load_selected_patch_to_current();                    // 0x02005660
    }
}
```

### `0x0201e254:single-byte-current-patch-writer`

```c
void ui_sysex_single_parameter_writer(uint8_t *msg, uint32_t len) {
    obj = (uint8_t *)0x01c33260;
    if (len == 7 && msg[0] == 0xf0 && msg[1] == 0x43 && msg[2] == 0x10 && msg[6] == 0xf7) {
        uint8_t idx = ((msg[3] << 7) + msg[4]) & 0xff;
        obj[0x1a14 + idx] = msg[5];
        return;
    }
}
```

### `0x0201e13e`

```c
void pack_expanded_current_patch_to_selected_record(uint8_t *expanded) {
    uint8_t packed80[0x80];
    for (int off = 0; off != 0x7e; off += 0x15) {
        // Six 0x15-byte expanded operator blocks become compact packed bytes.
        pack_one_operator_block(expanded + off, packed80 + operator_packed_offset(off));
    }
    pack_global_tail(expanded + 0x7e, packed80 + 0x66);
    obj = (uint8_t *)0x01c33260;
    bank = obj[0x3a4]; preset = obj[0x3a0 + bank];
    dst = *(uint8_t **)(obj + 0x160) + bank * 0x1000 + preset * 0x80;
    storage_transfer(packed80, dst, 0x80); // 0x02004b02
    obj[0x129c + bank * 32 + preset] = 0;
}
```

### `0x02026d6c`

```c
void save_current_patch_candidate(void) {
    obj = (uint8_t *)0x01c33260;
    if (obj[0x1ec] != 0 || state == 0xff) goto out;
    bank = obj[0x3a4]; preset = obj[0x3a0 + bank];
    storage_dst = *(uint8_t **)(obj + 0x160) + 0x4000 + (bank * 32 + preset) * 0xa3;
    storage_transfer(obj + 0x1a14, storage_dst, 0xa3);
    pack_expanded_current_patch_to_selected_record(obj + 0x1a14);
    obj[0x129c + bank * 32 + preset] = 0xff;
    storage_transfer(/*save flags*/, *(uint8_t **)(obj + 0x160) + 0x9180, 0x80);
out:
    obj[0x1ec] = 0xff;
}
```

### `0x0201c5ec`

```c
void dispatch_midi_like_event(void *engine, uint8_t *msg, uint32_t len) {
    status = msg[0]; status_hi = status >> 4; channel = status & 0x0f;
    if (status_hi == 0x8 || status_hi == 0x9) {
        voice = allocate_or_select_voice_index(engine);
        slot = (uint8_t *)engine + voice * 0xa0;
        memcpy(slot + 0xa2, (void *)0x01c34c74, 0x9c);
        // bytes at slot+0x13e..0x141 are event metadata, outside the 0x9c tone copy.
        write_note_velocity_and_marker(slot, msg);
        return;
    }
    if ((status & 0xf0) == 0xe0 && len >= 3) {
        *(uint16_t *)((uint8_t *)engine + 0x3e) = msg[1] | (msg[2] << 7);
        return;
    }
    handle_cc_program_or_pressure_like_messages(engine, msg, len);
}
```

## Reproduce

```sh
python3 baselines/v15/analysis/channel-separation-reanalysis/runtime-source/trace_runtime_source.py
```
