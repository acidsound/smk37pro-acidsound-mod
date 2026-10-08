# S1-C2 stock-helper unblock investigation

Date: 2026-08-02 UTC  
Decision: **BLOCK**  
Scope: exact official v15, the existing S1-C1/H2 analysis lineage, SDK-signature evidence, and the two exact official decoder listings. No candidate, device access, OTA, flash, reset, live MIDI, or persistence action was performed.

## Executive result

The requested tiny-trampoline plus stock-helper route does **not** unblock S1-C2.

Reusable, ABI-proven helper coverage is too small:

- **PASS:** completed-message hook ABI at `0x0202d202` supplies `r0=assembled_message`, `r1=accumulated_length`.
- **PASS:** `memcpy`/memmove-style helper at `0x02048cce` has the stock scalar ABI `r0=dst`, `r1=src`, `r2=len`.
- **PASS:** non-private traffic can be delegated unchanged by tail-calling the preserved product SysEx handler `0x0201e254` with original `r0/r1`.
- **BLOCK:** no verified callable stock helper implements exact private length gates, private prefix framing, arbitrary 7-bit LEN/CRC decode, CRC-16 packet/set checks, two bounded distinct note checks, or two-slot `LOADING -> ARMED` publication.
- **BLOCK:** the existing H2 producer is one-slot only. It copies one accepted product payload to `0x01c46520`, sets `valid0` last, and returns. It has no slot1, no note metadata, no transaction ID, and no ARMED state.

Therefore a safe S1-C2 producer still needs new parser/state-machine code rather than a tiny trampoline. The prior `fb2095e` BLOCK remains valid for implementation, although this pass narrows the reason: stock helpers can cover copy and delegation only, not the safety-critical parser/checksum/publication contract.

## Evidence inputs

`validate.py` SHA-gates these exact inputs:

| Input | SHA-256 |
|---|---|
| `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| `build/SMK-37_Pro_015.fwsc` | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| Quarkslab exhaustive listing | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| Kagaimiq exhaustive listing | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |
| SDK signatures `report.json` | `e9f02dfe9ba1987353df14c82b18b321f960960fcd66d987db183fe71b0f75fe` |
| SDK signatures `evidence.md` | `ba0a18e389f84a294f56a1b84f8a045b9b6a7d59b58a237d42e17e84fcb873ac` |
| runtime-source trace | `bc619891389c9f1183b36686b706a67136a8852a0de3e8b0fdd6c21d75022d4c` |
| factory-loader evidence | `efdda52181e3736221354acfe36633a1fd55cc3f7b83918a03e073bab3ebcd09` |
| SysEx staging trace | `9cb78c3149b78c5c56569a6e17ef4f36b6c73f25a2bed018bbc2c0d1c0f6b655` |
| S1-C1 ingress evidence | `3b30cdb6904fd81156f4be1b919eda9b44259873055f9e1aad2b029c156bcf34` |
| S1-C1 code evidence | `44b2cb1d7d758c8b85ae19461a05aaa78f9a7579b90f1fddf4575b09079b672c` |
| `fb2095e` S1-C2 BLOCK evidence, current file | `b0e60b37e05ffa8075aaa9b39acf0149f1cd5b822579d2e3535e6f217da1af60` |

The SDK-signature evidence is deliberately negative for MIDI synth helper reuse: it proves strong AC79 SDK lineage and USB/file-system positives, but records zero defensible exact or relocation-aware public MIDI synth matches in v15. It therefore cannot supply missing S1-C2 parser, CRC, note, or state helper ABIs.

## Helper ABI matrix

| Requirement | Verdict | Exact evidence | Why this does or does not help S1-C2 |
|---|---|---|---|
| Complete-message length/pointer ingress | **PASS as ABI only** | `0x0202d200 mov r0,r6`; `0x0202d202 call 0x0201e254`; handler entry `0x0201e256 mov r4,r0`, `0x0201e258 mov r9,r1` | A trampoline at the completed-message callsite can see pointer and length before the product handler. This is not a helper for private parsing. |
| Upstream nonsegmented size threshold | **PASS fact, not helper** | `0x0202d182 jb r1,0xfe,0x0202d20a`; otherwise `0x0202d186 add r0,r7,0x1f80`, `0x0202d202 call 0x0201e254` | Supports the S1-C1 two-message design under `0xfe`, but does not validate private exact lengths `173` and `176`. |
| Stock product framing | **BLOCK for reuse** | Product handler checks `F0 43`: `0x0201e410 jne r0,#0xf0`, `0x0201e416 jne r0,#0x43`; direct path final `F7` at `0x0201e462` | The checks are inline and product-specific. They do not recognize private `F0 7D 53 4D 4B 0F 01`. |
| Exact direct single-voice length | **BLOCK** | Direct path `0x0201e44e r6=r9-6`, `0x0201e456 memcpy(stage,msg+6,r9-6)`, then `0x0201e462` final `F7` | It copies before the final delimiter check and does not prove `r9 == 0xa3`. S1-C2 still needs exact private length gates before indexing or mutation. |
| Segmented single-voice final length | **PASS for stock only** | `0x0201e484 jne r5,#0x9e`; `0x0201e494 memcpy`; `0x0201e49c packer`; `0x0201e4a0 factory_loader` | This protects one stock segmented product path only. It is not a generic two-message private assembler or parser. |
| Stock single-parameter 7-bit index | **BLOCK for reuse** | `0x0201e626 lb.z msg[3]`; `0x0201e62a lsl 7`; `0x0201e630 uxtb`; `0x0201e634 sb msg[5],[base+0x1a14+idx]` | This is inline, truncates to 8 bits, and writes current snapshot global state. It is not a callable decoder for private LEN or CRC fields. |
| Factory packed-record expansion | **BLOCK for reuse** | Function `0x02005660` uses globals; bounds `0x02005670 ja bank,3`, `0x0200567e ja preset,0x1f`; copy `0x02005694 cur`, `0x02005698 len 0xa3`, `0x0200569a memcpy` | It is `void factory_loader(void)`, selected-bank/preset driven, and mutates current global snapshot and side-effect helpers. It cannot decode arbitrary host payload into S1-C2 slots. |
| Bulk copy | **PASS** | `0x02048cce push`; many callers set `r0/r1/r2`; body handles overlap and byte/word copies | This can copy slot payloads if caller provides already-validated addresses and length. It does not validate anything. |
| CRC-16/checksum | **BLOCK** | Deterministic scan found no `0x1021`, `0x8408`, or `0xa001` constants in either exact listing; S1-C1 ingress proves live payload did not satisfy the assumed Yamaha sum-to-zero | No callable CRC/checksum ABI, caller set, or side-effect profile is proven. S1-C2 packet and set CRCs still require new code or a separately proven helper. |
| Bounded note validation | **BLOCK** | Only stock bounds found here are bank/preset gates and the single-parameter `uxtb` truncation | No helper checks `NOTE0 <= 127`, `NOTE1 <= 127`, and `NOTE0 != NOTE1` before mutation. |
| Atomic publication | **BLOCK for two slots** | H2 producer at `0x0201e1a2` uses `csync; testset b[0x01c465bd]`; copies one payload to `0x01c46520`; sets `0x01c465bc=1`; unlocks | The side effect is exactly one-slot `valid0` publication. It cannot hide partial slot0 while slot1 is pending, cannot write note/state/TX, and cannot set `ARMED` last. |
| Delegation to product SysEx | **PASS** | Original completed-message call bytes at `0x0202d202` are `bfea2788`, `call 0x0201e254`; handler ABI preserves `r0/r1` at entry | A trampoline must tail-call `0x0201e254` unchanged for every non-private message. This is feasible but insufficient alone. |

## Exact instruction evidence

### Completed-message ABI and stock delegation

```text
0202d1bc  6840      lb.z  r0,[r6 + 0x0]
0202d1be  81f81f0e  jne   r1,#0x7,0x0202d200
0202d200  6016      mov   r0,r6
0202d202  bfea2788  call  0x0201e254
0201e254  7904      push  {rets,r9,r8,r7,r6,r5,r4}
0201e256  0416      mov   r4,r0       ; message pointer
0201e258  19d6      mov   r9,r1       ; message length
```

ABI proof: the caller materializes the assembled-message pointer in `r0` immediately before the call, and the callee saves `r0` to `r4` and `r1` to `r9` without reinterpretation. A trampoline at `0x0202d202` can therefore dispatch on the completed message and can delegate by restoring the original `r0/r1` and tail-calling `0x0201e254`.

### Stock direct product path is not an exact private length checker

```text
0201e410  90f8f9e0      jne   r0,#0xf0
0201e416  80f8f686      jne   r0,#0x43,0x0201e606
0201e448  08e1a06f      add   r8,r6,#0xfa0       ; stage = 0x01c37030 + 0x0fa0
0201e44e  36e1fa9f      add   r6,r9,#-0x6        ; copy length = len - 6
0201e456  80ff72a80200  call  0x02048cce         ; memcpy(stage,msg+6,len-6)
0201e462  90f8cbee      jne   r0,#0xf7           ; final delimiter checked after copy
0201e468  bfea69fe      call  0x0201e13e         ; stock packer in official v15
0201e46c  bfeaf838      call  0x02005660         ; reload selected current snapshot
```

This is useful only as a stock traffic path. It does not prove a direct `r9 == 0xa3` gate and cannot be reused for S1-C2 private messages without accepting mutation before validation.

### Stock segmented final path is product-specific

```text
0201e484  95f8583c      jne   r5,#0x9e
0201e494  80ff34a80200  call  0x02048cce
0201e49c  bfea4ffe      call  0x0201e13e
0201e4a0  bfeade38      call  0x02005660
```

This is an official single-voice/product path and proves why non-private traffic must delegate unchanged. It is not a private two-message S1-C2 parser.

### Single-parameter 7-bit index is inline and mutating

```text
0201e622  42f0141a  movz  r2,#0x1a14
0201e626  4843      lb.z  r0,[r4 + 0x3]
0201e62a  00a7      lsl   r0,r0,0x7
0201e630  0017      uxtb  r0,r0
0201e634  d8ee0112  sb    r1,[r0 + r2]
```

This reconstructs a product parameter address and stores into the current snapshot object. It is not callable, and its destination side effect is incompatible with private S1-C2 validation.

### Factory loader bounds are real but global and not callable for S1-C2

```text
02005660  7804            push  {rets,r8,r7,r6,r5,r4}
02005670  05fcb506        ja    r5,0x3,0x020057de     ; bank <= 3
0200567e  06fcae3e        ja    r6,0x1f,0x020057de    ; preset <= 31
02005694  10e1144a        add   r0,r4,0x1a14          ; current snapshot
02005698  6a23            mov   r2,#0xa3
0200569a  80ff2e360400    call  0x02048cce
020057de  5804            pop   {pc,r8,r7,r6,r5,r4}
```

`0x02005660` has exact callers `0x02005f9c`, `0x0201e46c`, `0x0201e4a0`, `0x0202422e`, and `0x020255a6` in the factory-loader and runtime-source reports. The ABI is `void factory_loader(void)`: it reads global selected bank/preset and writes global current state. It cannot take S1-C2 slot pointers or host-supplied note metadata.

### `memcpy` helper ABI is proven but insufficient

```text
02048cce  7604            push  {rets,r6,r5,r4}
02048cd0  00ec0310        ja    r1,r0,0x02048cda
02048cd4  931c            add   r3,r1,r2
02048cd6  00ec2930        ja    r3,r0,0x02048d2c
02048cda  0316            mov   r3,r0
...
02048d0e  5604            pop   {pc,r6,r5,r4}
```

Callsite examples establish the ABI:

```text
0201c63a  623c            mov   r2,#0x9c
0201c63c  8116            mov   r1,r8
0201c63e  80ff8ac60200    call  0x02048cce
0201c678  623c            mov   r2,#0x9c
0201c67a  8116            mov   r1,r8
0201c67c  80ff4cc60200    call  0x02048cce
```

This helper can copy `0x9c` bytes once a safe parser has selected a source and destination. It does not provide length, framing, 7-bit, CRC, bounds, lock, or state semantics.

### H2 one-slot atomic producer cannot publish an S1-C2 set

Exact H2 manifest bytes at `0x0201e1a2` decode to this side-effect shape:

```text
0201e1a2  push saved registers
0201e1a4  r4 = r0                         ; accepted staging pointer
0201e1a6  r0 = 0x01c465bd                 ; H2 lock byte
0201e1ac  csync; testset b[r0]
0201e1b0  ifeq return/busy
0201e1b4  csync
0201e1b6  r5 = 0x01c465bc                 ; valid0
0201e1bc  if valid0 != 0 return/reject
0201e1c0  r0 = 0x01c46520                 ; slot0 destination
0201e1c6  r1 = r4; r2 = 0x9c; call 0x02048cce
0201e1d2  valid0 = 1
0201e1d8  r0 = 0x01c465bd; csync; lock = 0; csync
0201e1ea  pop pc
```

This is an H2 helper, not stock official v15. Even if kept as an existing parent helper, its complete side effect is one-slot load-once publication. S1-C2 requires all of the following before `ARMED`: `state=LOADING`, `TX`, `NOTE0`, slot0 copy, `valid0`, `NOTE1`, slot1 copy, `valid1`, set CRC, and finally `state=ARMED`. The H2 helper has no ABI or internal state for that contract.

## Code-size budget

From current S1-C1 code evidence:

| Region | Range | Bytes | S1-C2 implication |
|---|---:|---:|---|
| S1-C1 selector | `0x0201e13e..0x0201e19e` | 96 | Occupied by consumer selector. |
| Internal gap | `0x0201e19e..0x0201e1a2` | 4 | Not useful for parser. |
| Unchanged H2 producer | `0x0201e1a2..0x0201e1ec` | 74 | Must be preserved if stock/H2 accepted product packet behavior remains delegated. |
| Remaining audited tail before handler entry | `0x0201e1ec..0x0201e254` | 104 | Not enough for private parser unless stock helpers cover the hard checks. |
| Total non-selector budget preserving H2 producer | 108 | Still lacks exact helper coverage for CRC/state/bounds. |

A minimal trampoline at `0x0202d202` would replace the original four-byte `call 0x0201e254`, but its body still needs somewhere to live. Because stock helpers cover only copy and non-private delegation, the body must still implement the full private protocol. That includes seven-byte prefix compare, exact length/body length checks for two commands, all data-byte `<0x80` checks, packet CRC-16, set CRC-16, TX/state validation, duplicate-note rejection, lock acquire/release with all reject paths, two `0x9c` copies, valid-last stores, ARMED-last store, and delegation. No evidence-backed 108-byte implementation exists.

## Pseudocode for the only admissible trampoline shape

This is a safety requirement, not an implementation candidate:

```c
void s1c2_completed_message_trampoline(uint8_t *msg, unsigned len) {
    if (len >= 7 &&
        msg[0] == 0xf0 && msg[1] == 0x7d && msg[2] == 0x53 &&
        msg[3] == 0x4d && msg[4] == 0x4b && msg[5] == 0x0f && msg[6] == 0x01) {
        /* BLOCK: no verified stock helper implements this parser. */
        s1c2_private_parser_required_but_not_available(msg, len);
        return;
    }

    /* Required stock preservation: original r0/r1, unchanged product handler. */
    tail_call_0x0201e254(msg, len);
}
```

The missing parser would need this all-or-none publication shape:

```c
reject unless exact command length, terminal F7, all data bytes < 0x80;
reject unless TX in 1..127, FLAGS == 0, decoded LEN is exact;
reject unless packet_crc16_ccitt_false(msg[2..body_end]) matches;

LOAD0:
    reject unless state == EMPTY && valid0 == 0 && valid1 == 0 && NOTE0 <= 127;
    if (!try_lock(0x01c465bd)) reject_busy_no_mutation;
    recheck state/valid;
    state = LOADING;
    tx = TX;
    note0 = NOTE0;
    memcpy(slot0, VOICE0, 0x9c);
    valid0 = 1;          // last visible slot0 byte
    unlock;

LOAD1_COMMIT:
    reject unless state == LOADING && TX == stored_tx && valid0 == 1 && valid1 == 0;
    reject unless NOTE1 <= 127 && NOTE1 != note0;
    reject unless set_crc16(01 || TX || NOTE0 || VOICE0 || NOTE1 || VOICE1) matches;
    if (!try_lock(0x01c465bd)) reject_busy_no_mutation;
    recheck state/tx/valid/note;
    note1 = NOTE1;
    memcpy(slot1, VOICE1, 0x9c);
    valid1 = 1;
    state = ARMED;       // final publication byte
    unlock;
```

Only `memcpy` and the conceptual `tail_call_0x0201e254` are backed by stock helper evidence. Everything else still requires new code.

## Final PASS/BLOCK gates

| Gate | Result |
|---|---|
| Official v15 artifact identity | PASS |
| `fb2095e` BLOCK read and re-evaluated | PASS |
| S1-C1 ingress/code, runtime-source, factory-loader, SysEx staging, SDK-signatures, and exact listings considered | PASS |
| Complete-message ABI | PASS as hook ABI |
| Copy helper ABI | PASS |
| Stock product SysEx delegation | PASS |
| Exact private length/framing helper | BLOCK |
| Seven-bit LEN/CRC decode helper | BLOCK |
| CRC-16 packet/set helper | BLOCK |
| S1-C2 bounded distinct note helper | BLOCK |
| Two-slot atomic publication helper | BLOCK |
| Tiny trampoline plus stock helpers | **BLOCK** |
| Firmware candidate/device/flash authorization | **BLOCK, not requested and not performed** |

## Validation

Run:

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/stock-helpers/validate.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c2-unblock/stock-helpers/SHA256SUMS
```

The validator is read-only. It rejects candidate-looking artifacts in this directory and rechecks the exact rows/negative scans that support this BLOCK.
