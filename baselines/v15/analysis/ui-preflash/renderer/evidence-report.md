# v15 UI renderer/LCD static evidence report

## Scope

- App: `build/v15-official-app.bin`
- SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Runtime base: `0x02000000`
- Listings: `baselines/v15/analysis/quarkslab/results/quarkslab-recursive-listing.tsv.gz`, `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz`
- Static only. No patching, flashing, or commit was performed by this analysis.
- Exhaustive listing data false-positives are treated as a known hazard.

## Classification summary

### 확정
- Input app is build/v15-official-app.bin, size 617012, SHA-256 36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055.
- UI text/color bytes exist in the official app at the recorded offsets; Firmware/Pad Bank-/Keys Channel- occur once.
- Firmware, Pad Bank-, and Keys Channel- have raw little-endian pointer-table entries at 0x02058028, 0x02058304, and 0x02058314 respectively.
- FUN_0201a67c manipulates an object at r0/r4, a string pointer at r1/r5, stores/replaces [r4+0x24], and calls zero-terminated length/copy helpers at 0x02048eca/0x02048e5c. This supports an object string setter role, not a full renderer name.
- FUN_02030e50 is a real recursive-listing function and directly loads 0x02058b50, treating it as a halfword table. This is independent contradictory evidence against blindly naming the overlapping ST-like bytes an LCD init table.

### 후보
- FUN_0200ea9a is a text extent or markup parser candidate: r0 is checked as a byte-string pointer; the function iterates bytes, handles NUL/CR/LF, calls helper 0x0200e936, and returns r0 as an accumulated length/count. The exact renderer ABI remains candidate.
- FUN_0200f74c is an object traversal/render dispatch candidate: r0-r3 are saved, fields from r1 are read, computed callbacks are invoked, and 0x0200f412/0x0200f734 are callees. Its direct UI role is not independently proven.
- The 0x02058aec..0x02058be8 byte run matches a ST7789V-like command list including 0x11, 0x36, 0x3a/0x05, 0xb2, 0xb7, 0xbb, 0xc2, 0xe0, 0xe1, 0x21. It is only a byte-pattern candidate because no LCD write caller was recovered and a recursive function references the overlapping region as a halfword table.

### 미확정
- No defensible LCD command/data write function, bus mode, panel resolution routine, or framebuffer owner was recovered from the current listings.
- No direct caller/callee chain from the UI string pointer entries to a final pixel/LCD write routine was recovered.
- No function receives a stable name unless at least two independent evidence classes support it; therefore this report keeps candidate roles instead of names for renderer/LCD functions.

## Seed strings and colors

| Seed | hits | offsets / VAs |
|---|---:|---|
| `Firmware` | 1 | `0x05d8f5` / `0x0205d8f5` |
| `Pad Bank-` | 1 | `0x05d9c5` / `0x0205d9c5` |
| `Keys Channel-` | 1 | `0x05d9e9` / `0x0205d9e9` |
| `Pads Channel-` | 1 | `0x05d9f7` / `0x0205d9f7` |
| `SAVE` | 3 | `0x057298` / `0x02057298`<br>`0x05d982` / `0x0205d982`<br>`0x05d990` / `0x0205d990` |
| `SAVED` | 1 | `0x05d990` / `0x0205d990` |
| `#D9D9D9` | 6 | `0x057730` / `0x02057730`<br>`0x057d5c` / `0x02057d5c`<br>`0x057d85` / `0x02057d85`<br>`0x057d92` / `0x02057d92`<br>`0x057dbb` / `0x02057dbb`<br>`0x05d97a` / `0x0205d97a` |
| `#F5BC27` | 5 | `0x057ce4` / `0x02057ce4`<br>`0x057d6a` / `0x02057d6a`<br>`0x057d77` / `0x02057d77`<br>`0x05d8ed` / `0x0205d8ed`<br>`0x05da05` / `0x0205da05` |
| `#f5bc27` | 1 | `0x05d988` / `0x0205d988` |

Key pointer-table evidence:
- `Firmware_text` at `0x0205d8f5` has raw pointer refs: [{"file_offset": "0x058028", "runtime_va": "0x02058028"}]
- `Pad_Bank_text` at `0x0205d9c5` has raw pointer refs: [{"file_offset": "0x058304", "runtime_va": "0x02058304"}]
- `Keys_Channel_text` at `0x0205d9e9` has raw pointer refs: [{"file_offset": "0x058314", "runtime_va": "0x02058314"}]

## ST7789-like byte sequence

The sequence is retained as a byte-pattern candidate, not a confirmed LCD path.

| Label | VA | command | len | payload | payload match |
|---|---:|---:|---:|---|---|
| sleep_out_or_table_prefix | `0x02058aec` | `0x11` | `0` | `` | `True` |
| MADCTL | `0x02058b10` | `0x36` | `1` | `00` | `True` |
| COLMOD_RGB565 | `0x02058b22` | `0x3a` | `1` | `05` | `True` |
| PORCTRL | `0x02058b34` | `0xb2` | `5` | `0c 0c 00 33 33` | `True` |
| GCTRL | `0x02058b46` | `0xb7` | `1` | `35` | `True` |
| VCOMS | `0x02058b58` | `0xbb` | `1` | `32` | `True` |
| VDVVRHEN | `0x02058b6a` | `0xc2` | `1` | `01` | `True` |
| VRHS | `0x02058b7c` | `0xc3` | `1` | `15` | `True` |
| VDVS | `0x02058b8e` | `0xc4` | `1` | `20` | `True` |
| FRCTRL2 | `0x02058ba0` | `0xc6` | `1` | `0f` | `True` |
| PWCTRL1 | `0x02058bb2` | `0xd0` | `2` | `a4 a1` | `True` |
| PVGAMCTRL | `0x02058bc4` | `0xe0` | `14` | `d0 08 0e 09 09 05 31 33 48 17 14 15 31 34` | `True` |
| NVGAMCTRL | `0x02058bd6` | `0xe1` | `14` | `d0 08 0e 09 09 05 31 33 48 17 14 15 31 34` | `True` |
| INVON | `0x02058be8` | `0x21` | `0` | `` | `True` |

Contradiction: `FUN_02030e50` is present in the recursive listing and loads `0x02058b50`, then reads it with `lh.s/lh.z` as a halfword table. That overlaps the ST-like run, so the LCD identity cannot be promoted without another independent xref to an LCD write routine.

## Candidate function evidence

### `0x0201a67c` `FUN_0201a67c_object_string_setter_candidate`

- ABI note: r0/r4 object pointer; r1/r5 source C string; returns via r0 from allocation/copy path; clobbers r4-r7 saved by prologue.
- Field accesses: `[r4+0x24] string/backing pointer`, `[r4+0x48] flags byte`
- Callees: `0x0200a7b2`, `0x02048eca`, `0x0200a28c`, `0x02009f98`, `0x02009f70`, `0x02048e5c`, `0x0201a1bc`
- Direct callers recovered: `0201a770`, `0201f22c`, `0201f530`, `0201f5c6`, `0201f65c`, `0201f6ac`, `0201f702`, `0201f758`, `0201f8ca`, `0201f97c`, `0201f9ca`, `0201fa22`, `02020456`, `020204a4`, `020205b0`, `020205fe`, `02020732`, `020207b8`, `020208ec`, `02020974`, `020209ba`, `02020a08`, `02020a4a`, `02020a8c`, `02020ace`, `02020bde`, `02020c76`, `02020ccc`, `02020dc8`, `02020e60`, `02020eb6`, `02020fb2`, `02021014`, `0202105c`, `020210ac`, `020210ee`, `02021130`, `02021188`, `02021292`, `020212f6`, `02021336`, `02021380`, `020213d6`, `0202142e`, `02021470`, `02021570`, `020215ba`, `020216ea`, `02021908`, `020219ee`, `02021a4a`, `02021b7c`, `02021c62`, `02021d18`, `02021dd8`, `02021ef2`, `02021f4a`, `02021f96`, `020220f6`, `02022140`, `02022186`, `020221f6`, `0202235a`, `020223ac`, `020223ee`, `0202243a`, `020224ba`, `020225fa`, `0202265c`, `020226ba`, `020226e4`, `0202276c`, `020227fc`, `02022858`, `02022952`, `02022a02`, `02022a66`, `02022bca`, `02022d2c`, `02022d76`, `02022de8`, `02022e34`, `020232f8`, `0202499a`, `02024ab6`, `02024ac4`, `02024ada`, `02024ae6`, `02024b4a`, `02024b60`, `02024b6e`, `02024bc6`, `02024cd6`, `02024d1a`, `02024d6e`, `02024d7a`, `02024d92`, `02024d9e`, `02024daa`, `02024dc2`, `02024dce`, `02024dda`, `02024de4`, `020252c2`, `02025350`, `020253cc`, `02025448`, `020277e8`, `02027830`, `02027842`, `020278d8`, `020278f0`, `0202794c`, `02027960`, `02027a6e`, `02027a84`, `02027b18`, `02027cb0`, `02027d28`, `02027d46`, `02027e9e`, `02027eb2`, `02027f48`, `02027fce`, `0202800c`, `0202812e`, `020281d6`, `020281e4`, `02028206`, `02028212`, `0202824c`, `0202838e`, `02028424`, `0202849e`, `02028572`, `02028742`, `020287ea`, `020288b0`, `020288c8`, `0202897a`, `0202899e`, `020289ba`, `02029228`, `0202923e`, `02029270`, `0202928a`
- Listing excerpt:
```text
0201a67c 7704 push {rets,r7,r6,r5,r4} FALL_THROUGH FUN_0201a67c@0201a67c
0201a67e 0415 mov r4_r5,r0_r1 FALL_THROUGH FUN_0201a67c@0201a67c
0201a680 bfea9780 call 0x0200a7b2 UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a684 07f14840 add r7,r4,#0x48 FALL_THROUGH FUN_0201a67c@0201a67c
0201a688 4669 _lw r6,[r4 + 0x24] FALL_THROUGH FUN_0201a67c@0201a67c
0201a68a 6016 mov r0,r6 FALL_THROUGH FUN_0201a67c@0201a67c
0201a68c 0543 jz r5,0x0201a694 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a68e 5016 mov r0,r5 FALL_THROUGH FUN_0201a67c@0201a67c
0201a690 85e80f60 jne r6,r5,0x0201a6b2 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a694 05d6 mov r5,r0 FALL_THROUGH FUN_0201a67c@0201a67c
0201a696 7940 _lb.z r1,[r7 + 0x0] FALL_THROUGH FUN_0201a67c@0201a67c
0201a698 51e80b1a jmnz r1,#0xd,0x0201a6b2 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a69c 6016 mov r0,r6 FALL_THROUGH FUN_0201a67c@0201a67c
0201a69e 80ff26e80200 call 0x02048eca UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6a4 0981 add r1,r0,#0x1 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6a6 6016 mov r0,r6 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6a8 bfeaf07d call 0x0200a28c UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6ac c069 sw r0,[r4 + 0x24] FALL_THROUGH FUN_0201a67c@0201a67c
0201a6ae 805a jnz r0,0x0201a6e4 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a6b0 5704 pop {pc,r7,r6,r5,r4} TERMINATOR FUN_0201a67c@0201a67c
0201a6b2 0648 jz r6,0x0201a6c4 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a6b4 7840 lb.z r0,[r7 + 0x0] FALL_THROUGH FUN_0201a67c@0201a67c
0201a6b6 50e8051a jmnz r0,#0xd,0x0201a6c4 CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a6ba 6016 mov r0,r6 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6bc bfea6c7c call 0x02009f98 UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6c0 49ea0040 sw 0x0,[r4 + 0x24] FALL_THROUGH FUN_0201a67c@0201a67c
0201a6c4 5016 mov r0,r5 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6c6 80fffee70200 call 0x02048eca UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6cc c021 add r0,#0x1 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6ce bfea4f7c call 0x02009f70 UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6d2 c069 sw r0,[r4 + 0x24] FALL_THROUGH FUN_0201a67c@0201a67c
0201a6d4 004a jz r0,0x0201a6ea CONDITIONAL_JUMP FUN_0201a67c@0201a67c
0201a6d6 5116 mov r1,r5 FALL_THROUGH FUN_0201a67c@0201a67c
0201a6d8 80ff7ee70200 call 0x02048e5c UNCONDITIONAL_CALL FUN_0201a67c@0201a67c
0201a6de 7840 lb.z r0,[r7 + 0x0] FALL_THROUGH FUN_0201a67c@0201a67c
0201a6e0 b823 bitclr r0,0x3 FALL_THROUGH FUN_0201a67c@0201a67c
... 51 more rows in evidence.json
```

### `0x0200ea9a` `FUN_0200ea9a_text_extent_or_markup_candidate`

- ABI note: r0/r10 input byte string; r1 must be nonzero but exact role unresolved; r2 contributes flags via stack extra arg [sp+0x58]; returns r0/r12 count or advance.
- Direct callers recovered: `0200ed36`, `0200ef22`, `0200ef52`, `0200f380`, `0201a0b0`
- Listing excerpt:
```text
0200ea9a 7f04 push {rets,r15,r14,r13,r12,r11,r10,r9,r8,r7,r6,r5,r4} FALL_THROUGH FUN_0200ea9a@0200ea9a
0200ea9c e297 add sp,#-0x24 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200ea9e 0ad6 mov r10,r0 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaa0 8224 _sw r2,[sp+0x10] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaa2 c414 clr r12 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaa4 00f8d700 je r0,0x0,0x0200ec56 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eaa8 01f8d500 je r1,0x0,0x0200ec56 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eaac 0840 lb.z r0,[r0 + 0x0] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaae 00f8d200 je r0,0x0,0x0200ec56 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eab2 0236 lw r2,[sp+0x58] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eab4 60ff06201500 jmz r2,#0x6,0x0200eae4 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eaba 02e101a0 add r2,r10,#0x1 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eabe 4120 mov r1,#0x0 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eac0 43e00124 movz r3,#0x2401 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eac4 0483 goto 0x0200eacc UNCONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eac6 d8ee2001 lb.z r0,[r2 + r1] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaca c121 add r1,#0x1 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eacc 00fcfb1b ja r0,0xd,0x0200eac6 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200ead0 94e13240 bit.and r4,r3,r0 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200ead4 7458 jz r4,0x0200eac6 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200ead6 4221 mov r2,#0x1 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200ead8 20eaff00 if ((r0 & #0xff) != 0) { FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eadc 4220 mov r2,#0x0 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eade b4e020c1 }  add r12, r2, r1 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eae2 5499 goto 0x0200ec56 UNCONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eae4 71f1fd20 and r1,r2,#0xffffff02 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eae8 8120 _sw r1,[sp] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaea 77f1fe20 and r7,r2,#0xffffff01 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaee 8121 _sw r1,[sp+0x4] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaf0 dee91bc0 sb r12,[sp+0x1b] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaf4 d4e915c0 sw r12,[sp+0x4] FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eaf8 ceffe8d80502 mov r14,#0x205d8e8 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eafe b9e14130 sextra r9,r3,0x0,0x10 FALL_THROUGH FUN_0200ea9a@0200ea9a
0200eb02 89fda002 jl r9,#0x1,0x0200ec46 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eb06 00f89e00 je r0,0x0,0x0200ec46 CONDITIONAL_JUMP FUN_0200ea9a@0200ea9a
0200eb0a b4e0a06c add r6,r10,r12 FALL_THROUGH FUN_0200ea9a@0200ea9a
... 114 more rows in evidence.json
```

### `0x0200f74c` `FUN_0200f74c_object_render_traversal_candidate`

- ABI note: r0/r13 context or object; r1/r14 descriptor/object; r2/r12 and r3/r6 rectangle or render args candidate; exact ABI unresolved.
- Field accesses: `[r1+0x08]`, `[r1+0x09]`, `[r1+0x0b]`, `[r1+0x10]`, `[r13+0x18] computed callback`
- Callees: `0x0200afe8`, `0x0200a1f2`, `computed callbacks`, `0x0200f412`, `0x0200f734`
- Direct callers recovered: `0201016a`, `020161a4`, `0201624c`, `02019c98`, `02019e1c`
- RAM/global immediates:
  - `0200f784` `mov r15,#0x1c33260`
- Listing excerpt:
```text
0200f74c 7f04 push {rets,r15,r14,r13,r12,r11,r10,r9,r8,r7,r6,r5,r4} FALL_THROUGH FUN_0200f74c@0200f74c
0200f74e e28f add sp,#-0x44 FALL_THROUGH FUN_0200f74c@0200f74c
0200f750 3616 mov r6,r3 FALL_THROUGH FUN_0200f74c@0200f74c
0200f752 2c16 mov r12,r2 FALL_THROUGH FUN_0200f74c@0200f74c
0200f754 1e16 mov r14,r1 FALL_THROUGH FUN_0200f74c@0200f74c
0200f756 0d16 mov r13,r0 FALL_THROUGH FUN_0200f74c@0200f74c
0200f758 c8ffdcd80502 mov r8,#0x205d8dc FALL_THROUGH FUN_0200f74c@0200f74c
0200f75e 06f8bf00 je r6,0x0,0x0200f8e0 CONDITIONAL_JUMP FUN_0200f74c@0200f74c
0200f762 184b lb.z r0,[r1 + 0xb] FALL_THROUGH FUN_0200f74c@0200f74c
0200f764 80f9c106 jb r0,0x3,0x0200f8ea CONDITIONAL_JUMP FUN_0200f74c@0200f74c
0200f768 d0ecd841 ldw r4,r13,#0x18 FALL_THROUGH FUN_0200f74c@0200f74c
0200f76c 0445 jz r4,0x0200f778 CONDITIONAL_JUMP FUN_0200f74c@0200f74c
0200f76e d016 mov r0,r13 FALL_THROUGH FUN_0200f74c@0200f74c
0200f770 c400 call r4 COMPUTED_CALL FUN_0200f74c@0200f74c
0200f772 80f8ba00 jne r0,#0x0,0x0200f8ea CONDITIONAL_JUMP FUN_0200f74c@0200f74c
0200f776 5494 goto 0x0200f8e0 UNCONDITIONAL_JUMP FUN_0200f74c@0200f74c
0200f778 1464 lw r4,[r1 + 0x10] FALL_THROUGH FUN_0200f74c@0200f74c
0200f77a 1f49 lb.z r7,[r1 + 0x9] FALL_THROUGH FUN_0200f74c@0200f74c
0200f77c 1d48 lb.z r5,[r1 + 0x8] FALL_THROUGH FUN_0200f74c@0200f74c
0200f77e bfea33dc call 0x0200afe8 UNCONDITIONAL_CALL FUN_0200f74c@0200f74c
0200f782 0916 mov r9,r0 FALL_THROUGH FUN_0200f74c@0200f74c
0200f784 cfff6032c301 mov r15,#0x1c33260 FALL_THROUGH FUN_0200f74c@0200f74c
0200f78a 0ae188f8 add r10,r15,#0x888 FALL_THROUGH FUN_0200f74c@0200f74c
0200f78e 4928 mov r1,#0x28 FALL_THROUGH FUN_0200f74c@0200f74c
0200f790 a016 mov r0,r10 FALL_THROUGH FUN_0200f74c@0200f74c
0200f792 bfea2ed5 call 0x0200a1f2 CALL_TERMINATOR FUN_0200f74c@0200f74c
0200f7f8 4360 lw r3,[r4 + 0x0] FALL_THROUGH -
0200f7fa 035e jz r3,0x0200f838 CONDITIONAL_JUMP -
0200f7fc 4061 lw r0,[r4 + 0x4] FALL_THROUGH -
0200f7fe 005c jz r0,0x0200f838 CONDITIONAL_JUMP -
0200f800 07e19cf8 add r7,r15,#0x89c FALL_THROUGH -
0200f804 4016 mov r0,r4 FALL_THROUGH -
0200f806 6116 mov r1,r6 FALL_THROUGH -
0200f808 7216 mov r2,r7 FALL_THROUGH -
0200f80a c300 call r3 COMPUTED_CALL -
0200f80c 0516 mov r5,r0 FALL_THROUGH -
... 66 more rows in evidence.json
```

### `0x02030e50` `FUN_02030e50_halfword_table_decoder_confirmed`

- ABI note: r0/r4 destination buffer; r1/r11 input halfword stream; returns after writing [r4+0x24] through 0x0202ec42.
- Data accesses: `r8=0x02058b50`, `r9=r8+0x1ee`, `lh.s/lh.z table reads`, `writes bytes under r4 and halfword via 0x0202ec42`
- Direct callers recovered: `020310ae`
- Listing excerpt:
```text
02030e50 7b04 push {rets,r11,r10,r9,r8,r7,r6,r5,r4} FALL_THROUGH FUN_02030e50@02030e50
02030e52 1b16 mov r11,r1 FALL_THROUGH FUN_02030e50@02030e50
02030e54 0416 mov r4,r0 FALL_THROUGH FUN_02030e50@02030e50
02030e56 4881 add r0,r4,#0x1 FALL_THROUGH FUN_02030e50@02030e50
02030e58 4120 mov r1,#0x0 FALL_THROUGH FUN_02030e50@02030e50
02030e5a 4a3f mov r2,#0x3f FALL_THROUGH FUN_02030e50@02030e50
02030e5c c014 clr r8 FALL_THROUGH FUN_02030e50@02030e50
02030e5e 80ff328d0100 call 0x02049b96 UNCONDITIONAL_CALL FUN_02030e50@02030e50
02030e64 6025 mov r0,#0x85 FALL_THROUGH FUN_02030e50@02030e50
02030e66 49f0c100 movz r9,#0xc1 FALL_THROUGH FUN_02030e50@02030e50
02030e6a c840 _sb r0,[r4 + 0x0] FALL_THROUGH FUN_02030e50@02030e50
02030e6c 7020 mov r0,#0xc0 FALL_THROUGH FUN_02030e50@02030e50
02030e6e 52ee4002 sb r0,[r4 + 0x20] FALL_THROUGH FUN_02030e50@02030e50
02030e72 4221 mov r2,#0x1 FALL_THROUGH FUN_02030e50@02030e50
02030e74 5320 mov r3,#0x40 FALL_THROUGH FUN_02030e50@02030e50
02030e76 4020 mov r0,#0x0 FALL_THROUGH FUN_02030e50@02030e50
02030e78 4620 mov r6,#0x0 FALL_THROUGH FUN_02030e50@02030e50
02030e7a 0716 mov r7,r0 FALL_THROUGH FUN_02030e50@02030e50
02030e7c c81c add r0,r4,r3 FALL_THROUGH FUN_02030e50@02030e50
02030e7e 52ee0090 sb r1,[r0 + 0x0] FALL_THROUGH FUN_02030e50@02030e50
02030e82 52ee0180 sb r0,[r0 + 0x1] FALL_THROUGH FUN_02030e50@02030e50
02030e86 c322 add r3,#0x2 FALL_THROUGH FUN_02030e50@02030e50
02030e88 0248 jz r2,0x02030e9a CONDITIONAL_JUMP FUN_02030e50@02030e50
02030e8a 6017 uxtb r0,r6 FALL_THROUGH FUN_02030e50@02030e50
02030e8c d8edb820 lh.z r2,[r11 + r0] FALL_THROUGH FUN_02030e50@02030e50
02030e90 4021 mov r0,#0x1 FALL_THROUGH FUN_02030e50@02030e50
02030e92 8241 jnz r2,0x02030e96 CONDITIONAL_JUMP FUN_02030e50@02030e50
02030e94 2016 mov r0,r2 FALL_THROUGH FUN_02030e50@02030e50
02030e96 0618 add r6,r0 FALL_THROUGH FUN_02030e50@02030e50
02030e98 0481 goto 0x02030e9c UNCONDITIONAL_JUMP FUN_02030e50@02030e50
02030e9a 4220 mov r2,#0x0 FALL_THROUGH FUN_02030e50@02030e50
02030e9c c81c add r0,r4,r3 FALL_THROUGH FUN_02030e50@02030e50
02030e9e 2116 mov r1,r2 FALL_THROUGH FUN_02030e50@02030e50
02030ea0 bfeacfee call 0x0202ec42 UNCONDITIONAL_CALL FUN_02030e50@02030e50
02030ea4 c322 add r3,#0x2 FALL_THROUGH FUN_02030e50@02030e50
02030ea6 61ff1f30eeff jmnz r3,#0x1f,0x02030e88 CONDITIONAL_JUMP FUN_02030e50@02030e50
... 69 more rows in evidence.json
```

## Reproduction

```bash
python3 baselines/v15/analysis/ui-preflash/renderer/analyze_renderer.py
python3 -m json.tool baselines/v15/analysis/ui-preflash/renderer/evidence.json >/dev/null
```

