# SMK37ProMod v15 S1-C4 segmented-final Playback Note ABI

Status: **PASS static ABI proof, current S1-C4 v2 split-send publication BLOCKED**.

Scope: offline only. This pass read official v15, S1-C3 r3 reload, S1-C4 v2 failclosed, and existing playback-note ABI/protocol evidence. It did not access a device, open MIDI/USB, flash, OTA, reset, or build a new firmware package.

Reproduce:

```sh
python3 baselines/v15/analysis/playback-note/segmented-abi/validate_segmented_abi.py --write
```

## Decision

The official v15 segmented-final product ABI is exact enough to fix the Chrome/CoreMIDI split failure safely:

1. The final accepted segmented path reconstructs exactly `0x9c` product payload bytes at `0x01c37fd0`.
2. Immediately before the product call, it sets `r0 = 0x01c37fd0` and then calls the product callsite at `0x0201e49c`.
3. At that call, `r9` is the **final chunk length**, not the direct-message length `0xa3` and not the accumulated length.
4. Therefore a segmented-safe S1-C4 producer must publish Playback Note from the assembled staging byte `stage[0x9b]`, not from `r4`, `r9`, or a direct-wire offset.
5. S1-C4 v2's producer is already compatible with that requirement because it uses `r0` as staging pointer, saves it in `r4`, loads `stage+0x9b`, stores it to `0x01c46f20+slot`, restores `stage[0x9b]` to `0x3f`, copies `0x9c`, restores slot byte `0x9b`, then publishes valid/count/ARMED in order.
6. The current S1-C4 v2 package is still fail-closed for split sends because `0x0201e49c` targets the no-mutation stub at `0x0201e224`.

Safe publication path for a future package: retarget only the S1-C4 segmented product callsite `0x0201e49c` from `bfeac2fe -> 0x0201e224` to `bfeac4fe -> 0x0201e228` so final segmented packets enter the same reset wrapper used by direct product packets. The reset wrapper preserves reset lifecycle and calls the main producer at `0x0201e196`. This report does **not** apply that patch.

## Pinned artifact basis

| Artifact | SHA-256 |
|---|---|
| official v15 app `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| S1-C3 r3 reload app | `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b` |
| S1-C4 v2 failclosed app | `66ac465cc058682ee015e0f1b980da6593b09ac345f4f7d5abd6396077b46b25` |
| S1-C4 combined code | `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` |
| S1-C4 selector | `900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f` |
| S1-C4 producer | `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438` |

## Official segmented-final ABI

### Handler entry registers

At official handler entry `0x0201e254`:

| Address | Bytes | Instruction | Meaning |
|---:|---|---|---|
| `0x0201e254` | `7904` | `push {rets,r9,r8,r7,r6,r5,r4}` | save frame |
| `0x0201e256` | `0416` | `mov r4,r0` | `r4 = incoming chunk pointer` |
| `0x0201e258` | `19d6` | `mov r9,r1` | `r9 = incoming chunk length` |
| `0x0201e25c` | `c7ff6032c301` | `mov r7,#0x1c33260` | object/control base |

At product dispatch setup:

| Address | Bytes | Instruction | Meaning |
|---:|---|---|---|
| `0x0201e3f8` | `50ee7401` | `lb.z r0,[r7 + 0x104]` | load segmented state selector |
| `0x0201e3fc` | `c6ff3070c301` | `mov r6,#0x1c37030` | staging root |
| `0x0201e402` | `00f83604` | `je r0,0x2,0x0201e472` | state `2` selects final segmented single-voice path |

The staging base is `0x01c37030 + 0x0fa0 = 0x01c37fd0`.

### Initial segmented path

The initial path is selected by `F0 43 00 09 20 00` and reaches `0x0201e57a`. It does not call the product producer.

| Address | Bytes | Instruction | Meaning |
|---:|---|---|---|
| `0x0201e57a` | `4021` | `mov r0,#0x1` | mark segmented state/loading |
| `0x0201e580` | `00e1a06f` | `add r0,r6,#0xfa0` | `r0 = stage = 0x01c37fd0` |
| `0x0201e584` | `4986` | `add r1,r4,#0x6` | source skips six-byte segmented header |
| `0x0201e586` | `34e1fa9f` | `add r4,r9,#-0x6` | initial copied byte count |
| `0x0201e58a` | `4216` | `mov r2,r4` | memcpy length |
| `0x0201e58c` | `80ff3ca70200` | `call 0x02048cce` | copy initial payload bytes to stage |
| `0x0201e592` | `50ed7d49` | `sh r4,[r7 + 0x9c]` | publish previous staged length |

Initial ABI summary: `memcpy(0x01c37fd0, chunk+6, r9-6)`, then store `previous_len = r9-6` at `[r7+0x9c]`.

### Final segmented path

| Address | Bytes | Instruction | Meaning |
|---:|---|---|---|
| `0x0201e472` | `50ed7c09` | `lh.z r0,[r7 + 0x9c]` | `r0 = previous_len` |
| `0x0201e476` | `b4e04019` | `add r1,r4,r9` | `r1 = chunk_end` |
| `0x0201e47a` | `b4f00059` | `add r5,r0,r9` | `r5 = previous_len + final_len` |
| `0x0201e47e` | `195f` | `_lb.z r1,[r1 + -0x1]` | load final byte |
| `0x0201e480` | `91f849ee` | `jne r1,#0xf7` | require terminal `F7` |
| `0x0201e484` | `95f8583c` | `jne r5,#0x9e` | require `previous_len + r9 == 0x9e` |
| `0x0201e488` | `06e1a06f` | `add r6,r6,#0xfa0` | `r6 = 0x01c37fd0` |
| `0x0201e48c` | `6018` | `add r0,r6` | `r0 = stage + previous_len` |
| `0x0201e48e` | `32e1fe9f` | `add r2,r9,#-0x2` | final copy length |
| `0x0201e492` | `4116` | `mov r1,r4` | source is final chunk pointer |
| `0x0201e494` | `80ff34a80200` | `call 0x02048cce` | copy final payload bytes |
| `0x0201e49a` | `6016` | `mov r0,r6` | product-call argument is stage base |
| `0x0201e49c` | `bfea4ffe` official | `call 0x0201e13e` | official product callsite |
| `0x0201e4a0` | `bfeade38` | `call 0x02005660` | reload after product call |
| `0x0201e4a4` | `2489` | `goto 0x0201e538` | cleanup |
| `0x0201e538` | `4020` | `mov r0,#0x0` | clear segmented state |
| `0x0201e53a` | `52ee7401` | `sb r0,[r7 + 0x14]` | state clear row as decoded |

Final ABI summary:

```text
previous_len = *(uint16_t *)(r7 + 0x9c)
require *(r4 + r9 - 1) == 0xf7
require previous_len + r9 == 0x9e
stage = 0x01c37fd0
memcpy(stage + previous_len, r4, r9 - 2)
r0 = stage
call product_callsite_0x0201e49c
call reload_0x02005660
clear segmented state
```

The assembled stage length is `previous_len + (r9 - 2) = 0x9c`. Unlike the direct path, the segmented-final path does not need `F7` at `stage+0x9c`. It has already checked final chunk `F7` before the product call.

## Callsite comparison

| Basis | Direct product callsite | Segmented-final product callsite |
|---|---|---|
| official v15 | `0x0201e468 bfea69fe -> 0x0201e13e` | `0x0201e49c bfea4ffe -> 0x0201e13e` |
| S1-C3 r3 reload | `0x0201e468 bfeaddfe -> 0x0201e226` | `0x0201e49c bfeac1fe -> 0x0201e222` |
| S1-C4 v2 failclosed current | `0x0201e468 bfeadefe -> 0x0201e228` | `0x0201e49c bfeac2fe -> 0x0201e224` |
| Future safe split-send retarget | unchanged | `0x0201e49c bfeac4fe -> 0x0201e228` |

Current blocker is exact: S1-C4 v2 segmented callsite reaches `0x0201e224`, whose body is only:

| Address | Bytes | Name | Meaning |
|---:|---|---|---|
| `0x0201e224` | `7904` | `producer.segmented_stub_push` | save frame |
| `0x0201e226` | `5904` | `producer.segmented_stub_return` | return without mutation |

## Safe Playback Note publication from segmented final

S1-C4's direct product packets encode Playback Note at wire byte `161`, which is payload byte `0x9b` after the six-byte Yamaha header:

```text
F0 43 00 00 01 1B + payload[0x00..0x9b] + F7
                         ^ payload[0x9b] == wire byte 161
```

For segmented final, the exact equivalent location is not a final-chunk wire offset. It is the reconstructed `stage[0x9b]` byte after the final copy. The verifier models valid split points including cases where `stage[0x9b]` arrives in the first chunk and cases where it arrives in the final chunk. In every accepted model:

```text
previous_len + final_chunk_len == 0x9e
final_copy_len == final_chunk_len - 2
assembled_stage_len == 0x9c
stage[0x9b] == original direct wire byte 161
```

S1-C4 v2 producer rows already implement the safe stage read and publication order:

| Address | Bytes | Name | Meaning |
|---:|---|---|---|
| `0x0201e1e8` | `01e19b40` | `producer.staging_last_pointer` | `r1 = stage + 0x9b` |
| `0x0201e1ec` | `1a40` | `producer.playback_load` | load Playback Note from assembled stage byte |
| `0x0201e1ee` | `8a40` | `producer.playback_store` | store to `0x01c46f20 + slot` |
| `0x0201e1f0` | `4a3f` | `producer.restore_value` | `r2 = 0x3f` |
| `0x0201e1f2` | `9a40` | `producer.restore_staging_last` | restore `stage[0x9b]` before copy/reload |
| `0x0201e1f4` | `7016` | `producer.copy_destination` | destination slot |
| `0x0201e1f6` | `4116` | `producer.copy_source` | source is restored stage |
| `0x0201e1f8` | `623c` | `producer.copy_size` | `0x9c` bytes |
| `0x0201e1fa` | `80ffceaa0200` | `producer.memcpy_call` | copy product payload |
| `0x0201e202` | `e85f` | `producer.restore_slot_last` | restore slot byte `0x9b` before valid |
| `0x0201e204` | `2000` | `producer.copy_csync` | order restore before valid |
| `0x0201e208` | `e840` | `producer.valid_store` | publish slot valid last for slot |
| `0x0201e20a` | `5b41` | `producer.post_memcpy_count_reload` | reload count after memcpy |
| `0x0201e20e` | `db41` | `producer.count_store` | count after valid |
| `0x0201e214` | `2000` | `producer.armed_csync` | barrier before ARMED |
| `0x0201e218` | `d842` | `producer.armed_store` | state ARMED last publishes map |

The producer has `r9_length_gate_removed: true` in `candidate-v2-failclosed/evidence.json`, which is required for segmented final because `r9` is only the final chunk length.

## Exact safe retarget

The segmented-final callsite can safely use the same reset wrapper as direct packets:

| Item | Value |
|---|---|
| callsite | `0x0201e49c` |
| current bytes | `bfeac2fe` |
| current target | `0x0201e224` no-mutation stub |
| proposed bytes | `bfeac4fe` |
| proposed target | `0x0201e228` reset wrapper |
| reset wrapper action | optional signature reset, restore `r0=stage`, call producer `0x0201e196` |
| direct callsite | remains `0x0201e468 bfeadefe -> 0x0201e228` |
| reload | remains `0x0201e4a0 bfeade38 -> 0x02005660` |

Retargeting to reset wrapper is preferable to retargeting directly to `0x0201e196` because it keeps direct and segmented lifecycle behavior symmetric. It also preserves the reset signature handling that clears lock/count/state before calling the producer.

## Blockers and follow-ups

1. Current S1-C4 v2 failclosed does not publish split-send Playback Note because segmented final enters the no-mutation stub.
2. A future flashable S1-C4 package should retarget `0x0201e49c` to `0x0201e228`, rebuild deterministically, regenerate rollback/OTA evidence, and receive independent review before any device action.
3. This report proves the static firmware ABI once the official segmented-final path is entered. It does not live-prove Chrome/CoreMIDI chunk scheduling or the runtime device state that selects the segmented path.
4. No device, flash, OTA, reset, or MIDI transport was used here.

## Generated files

- `validate_segmented_abi.py`: static verifier and split model.
- `evidence.json`: machine-readable ABI evidence.
- `validation.txt`: concise validation summary.
- `SHA256SUMS`: local inventory for this directory.
