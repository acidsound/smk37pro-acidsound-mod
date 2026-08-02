# S1-C1 official-v15/H2 note-register and executable-code audit

Date: 2026-08-02 UTC
Scope: exact official v15 app and decoder rows plus the exact live-proven H2 app. Static analysis only.

## Decision

- Note Off `r5 = msg[1]`: PASS
- Note On `r6 = msg[1]`: PASS
- Hook ABI and corrected fallback design: PASS
- PI32 encoding, placement, and branch reach: PASS
- Cross-artifact metadata integration: BLOCK until the separate RAM layout is reconciled with the H2-compatible ingress state machine
- Firmware candidate: BLOCK

The note identities are closed at the exact existing H2 hook callsites. A minimal H2-compatible two-entry selector can replace only H2's two consumer wrappers, end 8 bytes before the unchanged H2 producer, and require no executable-range expansion.

No firmware candidate was produced. No app or FWSC image was written, no uploader was invoked, no device was accessed, no flash operation was performed, and no v12 address, artifact, ABI, or behavior was used.

## Exact inputs

| Input | SHA-256 |
| --- | --- |
| official v15 app, `build/v15-official-app.bin` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| live-parent H2 app | `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59` |
| Quarkslab exhaustive official listing | `f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347` |
| independent Kagaimiq exhaustive official listing | `814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013` |
| H2 app manifest | `dc6fba4ddb887424d6bd76b6d1477f66f97096e2d6656f203eec423680572cf3` |
| H2 live record | `b2aca5903390cffe573f42c89aa6407a52c28f967124a07b407887959d1c8fd7` |

`analyze.py` SHA-gates every input above before accepting any conclusion.

## 1. Exact Note Off identity at `0x0201c63e`

The official dispatcher rows are:

```text
0201c62e  1d41          lb.z  r5,[r1 + 0x1]
0201c630  e1e1a020      mul   r1,r2,#0xa0
0201c634  0e1c          add   r6,r0,r1
0201c636  00e1a260      add   r0,r6,#0xa2
0201c63a  623c          mov   r2,#0x9c
0201c63c  8116          mov   r1,r8
0201c63e  80ff8ac60200  call  0x02048cce
0201c644  00e13e61      add   r0,r6,#0x13e
0201c648  8d40          sb    r5,[r0 + 0x0]
```

Proof:

1. `0x0201c62e` loads byte `msg[1]` into `r5`.
2. No instruction between that load and `0x0201c63e` writes `r5`.
3. The callsite ABI is complete immediately before the call:
   - `r0 = r6 + 0xa2`, the per-voice destination
   - `r1 = r8`, the stock source, statically `0x01c34c74`
   - `r2 = 0x9c`, the exact copy count
   - `r9 = status & 0x0f`, established at `0x0201c5fe`
4. After the call, `0x0201c648` stores `r5` as the event metadata note.
5. Both official decoders independently identify the load as `r5,[r1 + 0x1]` and the post-call store as `r5,[r0 + 0x0]`.

The H2 byte window `0x0201c62e..0x0201c64a` is byte-identical to official v15 except that the six-byte call at `0x0201c63e` targets `0x0201e13e`. Therefore `r5` has the same note identity at the H2 hook.

H2 begins that wrapper with `7904`, push of original `rets,r9..r4`, and every owned/fallback return uses `5904`, pop to `pc,r9..r4`. H2 temporarily reuses `r5` for destination but restores the original note before `0x0201c648`. This is additionally consistent with H2's recorded normal Ch10 Note Off.

## 2. Exact Note On identity at `0x0201c67c`

The official dispatcher rows are:

```text
0201c66a  1d42          lb.z  r5,[r1 + 0x2]
0201c66c  e1f1a020      mul   r1,r2,#0xa0
0201c670  1e41          lb.z  r6,[r1 + 0x1]
0201c672  0f1c          add   r7,r0,r1
0201c674  00e1a270      add   r0,r7,#0xa2
0201c678  623c          mov   r2,#0x9c
0201c67a  8116          mov   r1,r8
0201c67c  80ff4cc60200  call  0x02048cce
0201c682  00e13e71      add   r0,r7,#0x13e
0201c686  8e40          sb    r6,[r0 + 0x0]
0201c688  52ee0190      sb    r1,[r0 + 0x1]
0201c68c  8d42          sb    r5,[r0 + 0x2]
```

Proof:

1. `0x0201c66a` loads `msg[2]`, velocity, into `r5`.
2. `0x0201c670` independently loads `msg[1]`, note, into `r6`.
3. No instruction between the note load and `0x0201c67c` writes `r6`.
4. The same destination/source/count/channel ABI is formed immediately before the call.
5. `0x0201c686` stores `r6` as the event metadata note, while `0x0201c68c` stores `r5` as velocity. This separates the two identities exactly.
6. Both official decoders independently identify the `r6 = msg[1]` load and the `r6` post-call metadata store.

The H2 byte window `0x0201c66a..0x0201c68e` is byte-identical to official v15 except that the six-byte call at `0x0201c67c` targets `0x0201e170`. H2's matching push/pop restores both `r6` note and `r5` velocity before those metadata stores.

## 3. Minimal separate native-register adapters

The two callsites cannot use one identical entry instruction because their native note registers differ. The smallest admitted design uses two separate adapters and one shared lookup core:

```text
0x0201e13e  mov r3,r5             ; Note Off adapter, normalize proven r5 note
0x0201e140  goto 0x0201e144       ; compact official-v15-derived forward goto

0x0201e142  mov r3,r6             ; Note On adapter, normalize proven r6 note
                                     fall through

0x0201e144  push {rets,r9..r4}
0x0201e146  mov r4,r0             ; save exact original destination
0x0201e148  mov r5,r9             ; temporary channel copy
0x0201e14a  jne r5,9,copy         ; non-Ch10 fallback
0x0201e14e  mov32 r5,0x01c465bc   ; exact H2 valid0 / slot0 metadata base
0x0201e154  lb.z r0,[r5 + 3]      ; state at 0x01c465bf
0x0201e156  jne r0,0,not_empty
0x0201e15a  lb.z r0,[r5]          ; EMPTY compatibility: exact H2 valid0
0x0201e15c  jne r0,1,copy         ; EMPTY and invalid falls back
0x0201e160  mov32 r1,0x01c46520   ; exact H2 slot0 source
0x0201e166  goto copy
0x0201e168  jne r0,2,copy         ; LOADING/invalid state falls back; ARMED == 2
0x0201e16c  lb.z r0,[r5 + 2]      ; immutable slot-0 note at 0x01c465be
0x0201e16e  xor r0,r3             ; compare with normalized event note
0x0201e170  jne r0,0,note1
0x0201e174  mov32 r1,0x01c46520   ; private slot 0 source
0x0201e17a  goto copy
0x0201e17c  mov32 r5,0x01c4665c   ; slot1 valid/transaction/note metadata base
0x0201e182  lb.z r0,[r5 + 2]      ; immutable slot-1 note at 0x01c4665e
0x0201e184  xor r0,r3             ; compare with normalized event note
0x0201e186  jne r0,0,copy         ; every other note falls back
0x0201e18a  mov32 r1,0x01c465c0   ; private slot 1 source
0x0201e190  mov r0,r4             ; corrected H2 destination restore
0x0201e192  call 0x02048cce       ; original r2 remains exactly 0x9c
0x0201e198  pop {pc,r9..r4}
```

Exact selector hex:

```text
53160481631679040416951685f82112c5ffbc65c401584380f80700584080f81802c1ff2065c401049480f812045842381980f80400c1ff2065c401048ac5ff5c66c4015842381980f80300c1ffc065c401401680ff36ab02005904
```

The two adapters are separate at the hook boundary, but share every instruction that can be identical after note normalization. The Note On adapter is placed immediately before the core and falls through, eliminating a second goto.

### Why the two-byte goto is admitted

No v12 encoding is used. Official v15 has:

```text
0x0201c650  049f  goto 0x0201c690
```

The target is 31 halfwords forward from `PC + 2`, validating the compact form `0x8004 | (halfwords << 8)`. The local encoder first reproduces official bytes `049f`, then emits only range-checked aligned forward targets.

The dynamic note comparisons likewise use an exact official-v15 instruction independently decoded by both listings:

```text
0x02003624  3819  xor r0,r3
```

The core loads each immutable note byte into `r0`, XORs it with the normalized event note in `r3`, and uses the existing range-checked `jne r0,#0` form. Equality is therefore represented by a zero result without introducing an unproved register-compare encoding.

### Smallest-design boundary

This is the smallest construction found under the exact instruction forms validated by official/H2 bytes and the current v15 PI32 helper set:

- Note Off native adapter: `4` bytes
- Note On native adapter: `2` bytes
- shared H2-compatible state/lookup/copy core: `86` bytes
- Selector code: `92` bytes

It uses one state load, one exact-H2 `valid0` compatibility load, two note-byte loads, the official-v15 `xor r0,r3` equality idiom, two private `mov32` source literals, one common corrected copy tail, and no duplicate memcpy or pop sequence.

This is not a claim of globally optimal PI32 machine code under unproved instruction forms. Any smaller replacement must demonstrate exact official/H2 decoder evidence and preserve every invariant in this report.

## 4. ABI and fallback preservation

### Entry ABI

| Register | Exact callsite meaning | Selector action |
| --- | --- | --- |
| `r0` | destination | saved to `r4` before any RAM probe, restored at `0x0201e190` |
| `r1` | stock source | untouched on all fallback paths, changed only for exact H2 EMPTY/valid0 compatibility or an ARMED allowlist match |
| `r2` | `0x9c` count | never written by the selector |
| `r9` | channel nibble | read only, then restored by pop |
| `r5` | Note Off note or Note On velocity | native value remains until shared push, restored by pop |
| `r6` | Note On note | native value remains unchanged, restored by pop |

### Corrected H2 fallback

All fallback paths branch to the single copy tail at `0x0201e190`:

- channel is not 9
- state is EMPTY and exact H2 `valid0` is not 1
- state is LOADING or any value other than EMPTY/ARMED
- state is ARMED and the normalized note matches neither immutable note byte at `0x01c465be` and `0x01c4665e`

Before those branches, no instruction writes `r1` or `r2`. The common tail performs `mov r0,r4` immediately before `memcpy`. Therefore fallback calls stock memcpy with the original destination, original stock source, original `0x9c` count, and unchanged channel state. This preserves the exact H2 correction that eliminated the invalid-path destination clobber.

The selector preserves H2's existing load-once behavior before a private transaction: when state is EMPTY and `valid0 == 1`, all Ch10 events select exact H2 slot 0. During LOADING, every consumer uses stock. When state is ARMED (`2`), the two immutable note bytes select private slot 0 or slot 1. State publication is allowed only after both valid bytes and both note/payload pairs are complete, so ARMED subsumes per-read valid checks in the minimal hot path.

### H2-compatible state contract

The code consumes the guarded-ingress metadata contract:

- `0x01c465bc`: exact H2 `valid0`
- `0x01c465be`: private `note0`
- `0x01c465bf`: state, `0 = EMPTY`, `1 = LOADING`, `2 = ARMED`
- `0x01c4665c`: `valid1`
- `0x01c4665e`: private `note1`

ARMED must be written last after both complete `0x9c` payloads, both bounded distinct note bytes, and both valid bytes. After ARMED, all mutation remains rejected until reboot. If this publication order changes, the minimal omission of per-slot valid reads is no longer admitted.

The separate RAM analysis currently assigns different meanings to `0x01c465bc` and `0x01c465bf`. That cross-artifact mismatch is an explicit integration BLOCK. The metadata contract must be reconciled before any candidate construction; the code bytes in this report follow the H2-compatible guarded-ingress contract because it alone preserves H2's existing `valid0 == 1` producer behavior.

The two allowlisted note values are immutable metadata written before ARMED. Initial S1-C1 test values may be 36 and 45, but no note value or contiguous physical-Pad sequence is hardcoded by the selector.

## 5. Executable placement and exact byte budget

The H2 live-parent layout is:

| Region | Range | Bytes |
| --- | --- | ---: |
| current H2 Note Off + Note On wrappers | `0x0201e13e..0x0201e1a2` | 100 |
| unchanged H2 producer | `0x0201e1a2..0x0201e1ec` | 74 |
| H2 occupied extent | `0x0201e13e..0x0201e1ec` | 174 |
| audited replaced stock packer body | `0x0201e13e..0x0201e254` | 278 |

The proposed static layout is:

| Region | Range | Bytes |
| --- | --- | ---: |
| two adapters + shared selector core | `0x0201e13e..0x0201e19a` | 92 |
| internal unused gap | `0x0201e19a..0x0201e1a2` | 8 |
| unchanged H2 producer | `0x0201e1a2..0x0201e1ec` | 74 |
| unchanged audited tail | `0x0201e1ec..0x0201e254` | 104 |

Budget:

- Selector code: `92` bytes
- unchanged H2 producer: `74` bytes
- active code total: `166` bytes
- total audited replacement body: `278` bytes
- Total unoccupied budget: `112` bytes
- H2 occupied-extent expansion: `0` bytes

The design does not use the blocked app-area tail, does not extend `app.bin`, does not enter `cfg_tool.bin`, and does not add a boot or post-init hook.

## 6. Branch and call reach

All encodings are regenerated and decoded by `analyze.py`:

| Source | Target | Encoding | Result |
| --- | --- | --- | --- |
| Note Off hook `0x0201c63e` | adapter `0x0201e13e` | `80fffa1a0000` | PASS, byte-identical to H2 |
| Note On hook `0x0201c67c` | adapter `0x0201e142` | `80ffc01a0000` | PASS |
| Note Off adapter goto `0x0201e140` | core `0x0201e144` | `0481` | PASS |
| non-Ch10 `jne` `0x0201e14a` | copy `0x0201e190` | `85f82112` | PASS, 33 halfwords |
| state-nonempty `jne` `0x0201e156` | discriminator `0x0201e168` | `80f80700` | PASS, 7 halfwords |
| H2-invalid `jne` `0x0201e15c` | copy `0x0201e190` | `80f81802` | PASS, 24 halfwords |
| H2-slot0 goto `0x0201e166` | copy `0x0201e190` | `0494` | PASS |
| state-not-ARMED `jne` `0x0201e168` | copy `0x0201e190` | `80f81204` | PASS, 18 halfwords |
| slot-0 compare `jne` `0x0201e170` | slot-1 lookup `0x0201e17c` | `80f80400` | PASS, 4 halfwords |
| private slot-0 goto `0x0201e17a` | copy `0x0201e190` | `048a` | PASS |
| slot-1 compare `jne` `0x0201e186` | copy `0x0201e190` | `80f80300` | PASS, 3 halfwords |
| shared memcpy call `0x0201e192` | `0x02048cce` | `80ff36ab0200` | PASS |

The producer remains at exact H2 address `0x0201e1a2`, byte-for-byte identical. Therefore its internal PC-relative encodings and the two accepted-packet short calls remain unchanged:

- `0x0201e468`: `bfea9bfe`
- `0x0201e49c`: `bfea81fe`

## 7. Exact PASS conditions

The code analysis is PASS only while all of these remain true:

1. Parent app SHA-256 is exact H2 `d71f...7f59`.
2. Official and H2 hook windows match the bytes SHA-gated by `analyze.py`.
3. Note Off enters with `r5 = msg[1]`; Note On enters with `r6 = msg[1]` and `r5 = msg[2]`.
4. `r0/r1/r2/r9` retain the documented destination/source/count/channel meanings.
5. The selector bytes and every decoded branch/call match generated evidence.
6. H2 producer `0x0201e1a2..0x0201e1ec` remains byte-for-byte unchanged.
7. State becomes ARMED (`2`) only after both slot payloads, both note bytes, and both valid bytes are complete and immutable.
8. The paired BSS/HEAP boundary through `0x01c46660` is applied only after the independent allocator-headroom gate passes and the RAM metadata layout is reconciled with this state contract.
9. SAVE remains blocked because the stock packer body is still replaced.
10. The two note bytes are explicit S1-C1 host allowlist values and are never inferred from a contiguous physical-Pad sequence.

## 8. Exact BLOCK conditions

Firmware construction or installation remains BLOCKED if any of these occurs:

1. Parent hash or any hook/cave byte differs.
2. A wrapper overwrites native `r5/r6` before saving or fails to restore them before post-call metadata stores.
3. Any fallback path writes `r1` or `r2`, or reaches memcpy without `r0` restored from the saved destination.
4. The static RAM placement or paired BSS/HEAP arithmetic through `0x01c46660` changes, the additional-`0xa0` allocator-headroom gate remains unresolved, or the separate RAM metadata assignment is not reconciled with valid0/state/note1 addresses in this report.
5. The ingress proof does not guarantee state=ARMED last after both immutable payloads, both distinct bounded note bytes, and both valid bytes, or does not reject every later mutation until reboot.
6. The H2 producer must move, accepted-packet short calls change, or executable code grows beyond the exact H2 occupied extent without a new independent audit.
7. SAVE or an original `0x0201e13e` packer caller can reach overwritten selector bytes.
8. Any v12 evidence, guessed physical-Pad sequence, firmware candidate, device access, or flash step is introduced into this evidence package.

## Reproduction

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c1/code/analyze.py --write-output
python3 baselines/v15/analysis/patch-set-ui/s1c1/code/analyze.py
shasum -a 256 -c baselines/v15/analysis/patch-set-ui/s1c1/code/SHA256SUMS
```

The first command regenerates only analysis JSON/text/hex evidence. The second performs a read-only deterministic recheck. Neither command creates or modifies firmware.
