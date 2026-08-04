# S1-C3/S1-C4 Playback Note live reanalysis

Status: **PASS, offline analysis only**. No firmware, flash, OTA, USB, MIDI, or reset action was performed.

Output scope: this directory only, `baselines/v15/analysis/playback-note/live-reanalysis/producer/`.

## Executive result

The live result `Original=PASS` and `all C4 repeated60=FAIL` is explained by a real current-code condition:

- S1-C4 source selection still uses only the Trigger Note: `slot = trigger_note - 36`.
- S1-C4 byte `161` is stored as a per-slot Playback Note map byte and later written to the local synth metadata note byte at `dest + 0x9c`.
- There is no separate trigger identity field in the current C4 consumer path and no duplicate-note reject.
- Therefore `Original` writes map bytes `24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33`, preserving 16 distinct synth identities.
- `all C4` writes `3c` sixteen times, collapsing all 16 trigger slots to one synth metadata identity, note 60. That is the repeated-note or cross-release failure condition documented by the code.

The current C4 condition for reliable multi-slot playback is thus: **effective playback metadata notes must remain one-to-one for trigger slots that may overlap**, unless a future hook proves and uses a separate trigger identity or voice cookie.

## Exact artifacts

| Artifact | Bytes | SHA-256 |
|---|---:|---|
| S1-C3 r3 selector | 96 | `ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915` |
| S1-C3 r3 producer | 174 | `48abedfe48368aed6528900725404a4c8f41c0957f25196cc91b246a9b7a8607` |
| S1-C4 v1 selector | 88 | `2670e3d2e9a9c47e8a48170ed13a2539b5ccd6229876f3b1689b69a73c8df7a7` |
| S1-C4 v1 producer | 188 | `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438` |
| S1-C4 v1 combined | 278 | `f877aa68476b88644e81df1fe2c7670591c3883f9a443b2d303007d677a48364` |
| S1-C4 v2 selector | 88 | `900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f` |
| S1-C4 v2 producer | 188 | `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438` |
| S1-C4 v2 combined | 278 | `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` |
| S1-C4 v3 selector | 88 | `900e8f05c8157737e89a22338b9a4575aa3ff124bd70ff132de0226654fce29f` |
| S1-C4 v3 producer | 188 | `a7627984549f62592384189a707ef04512921ad693b18409eb483dcccb53c438` |
| S1-C4 v3 combined | 278 | `4293474041bd40b697be88dcdc936eb92a2b6ce6d20fb95dc2e9dcbe9205cae1` |

Exact byte block diffs are in `exact-diff.tsv`. Full v1 to v2 and v2 to v3 builder diffs are in `builder-diff.md`.

## PI32 decode deltas that matter

### S1-C3 r3 selector

S1-C3 has no Playback Note map. It normalizes Note Off `r5` or Note On `r6` into `r3`, gates Ch10/range/ARMED/valid, sets `r1 = 0x01c46520 + (trigger_note - 36) * 0xa0`, calls `memcpy`, and returns. It restores `r5/r6`, so stock metadata stores use the Trigger Note.

Key rows:

| Address | Bytes | Instruction | Meaning |
|---|---|---|---|
| `0x0201e148` | `9516` | `mov r5,r9` | channel temp, no playback default |
| `0x0201e168` | `e3e1a030` | `mul r3,r3,#0xa0` | source offset from trigger slot |
| `0x0201e17a` | `5116` | `mov r1,r5` | source is trigger-selected slot |
| `0x0201e17e` | `80ff4aab0200` | `call 0x02048cce` | copy 0x9c bytes |
| `0x0201e184` | `5904` | `pop {pc,r9..r4}` | restores native note registers |

### S1-C4 v1 selector

V1 adds local metadata substitution. It loads Playback Note after the ARMED gate but before the selected-slot valid gate.

| Address | Bytes | Instruction | Meaning |
|---|---|---|---|
| `0x0201e148` | `3516` | `mov r5,r3` | default metadata note is Trigger Note |
| `0x0201e16a` | `07e1008a` | `add r7,r8,#0xa00` | map base `0x01c46f20` |
| `0x0201e170` | `7d40` | `lb.z r5,[r7]` | load Playback Note metadata |
| `0x0201e184` | `6116` | `mov r1,r6` | source remains trigger-selected slot |
| `0x0201e192` | `8d40` | `sb [r0],r5` | store metadata note at destination + `0x9c` |

### S1-C4 v2/v3 selector

V2 and v3 PI32 selector bytes are identical. The v2/v3 fix is fail-closed ordering: ARMED and selected-slot valid gates precede the Playback Note map load.

| Address | Bytes | Instruction | Meaning |
|---|---|---|---|
| `0x0201e16a` | `3616` | `mov r6,r3` | preserve trigger slot index for map |
| `0x0201e16c` | `e6e1a060` | `mul r6,r6,#0xa0` | source offset from trigger slot |
| `0x0201e178` | `80f80502` | `jne r0,#1,copy` | invalid source falls back before map read |
| `0x0201e17c` | `07e1008a` | `add r7,r8,#0xa00` | map base `0x01c46f20` |
| `0x0201e182` | `7d40` | `lb.z r5,[r7]` | load Playback Note only after valid |
| `0x0201e192` | `8d40` | `sb [r0],r5` | store metadata note at destination + `0x9c` |

### S1-C4 v1/v2/v3 producer

All C4 producers are byte-identical. Compared with S1-C3 r3, C4 removes the explicit `r9 == 0xa3` length gate, inserts the Playback Note map write, restores the staged and resident slot byte `0x9b` to `0x3f`, and moves the reset wrapper call target because the producer is rebased to `0x0201e196`.

| Address | Bytes | Instruction | Meaning |
|---|---|---|---|
| `0x0201e1c4` | `5b41` | `lb.z r3,[r5+1]` | load accepted packet count |
| `0x0201e1c6` | `03fd2820` | `jge r3,#16,unlock` | reject packet 17+ |
| `0x0201e1ca` | `3616` | `mov r6,r3` | current count is slot/order |
| `0x0201e1e0` | `c0ff206fc401` | `mov r0,#0x01c46f20` | Playback Note map base |
| `0x0201e1e6` | `3018` | `add r0,r3` | map pointer = map base + slot/count |
| `0x0201e1e8` | `01e19b40` | `add r1,r4,#0x9b` | payload byte `0x9b`, wire byte `161` |
| `0x0201e1ec` | `1a40` | `lb.z r2,[r1]` | load Playback Note from byte 161 |
| `0x0201e1ee` | `8a40` | `sb [r0],r2` | store to `playback_note[count]` |
| `0x0201e1f0` | `4a3f` | `mov r2,#0x3f` | restore proven payload byte |
| `0x0201e1f2` | `9a40` | `sb [r1],r2` | restore staging byte `0x9b` before copy |
| `0x0201e202` | `e85f` | `sb [r6-1],r0` | restore resident slot byte `0x9b` before valid |
| `0x0201e218` | `d842` | `sb [r5+2],r0` | state `ARMED` publishes after slot15 |

## Where byte 161 is used

| Area | Address | Instructions | Conclusion |
|---|---|---|---|
| Slot/order | `0x0201e1c4/0x0201e1c6/0x0201e1ca` | `lb.z r3,[r5+1]; jge r3,#16; mov r6,r3` | slot is accepted packet count, not byte161 |
| Slot/order | `0x0201e1e0/0x0201e1e6/0x0201e1ee` | `mov r0,#0x1c46f20; add r0,r3; sb [r0],r2` | byte161 is written to `playback_note[count]` |
| Uniqueness | `0x0201e1ec..0x0201e1ee` | `lb.z r2,[r1]; sb [r0],r2` | no compare, scan, range, or duplicate reject exists |
| Publication | `0x0201e204..0x0201e218` | `csync; valid=1; count++; if count==16 csync; state=2` | map is published only by ARMED last after the 16th valid slot |
| Selector consumption | `0x0201e164..0x0201e182/0x0201e192` | `state==2; selected valid==1; lb.z r5,[map+trigger_slot]; sb [dest+0x9c],r5` | byte161 becomes the local synth metadata note |

## Live condition, decoded

For each trigger slot `i`, the current C4 producer stores:

```text
RAM[0x01c46f20 + i] = packet_i[161]
```

The current C4 selector later stores:

```text
dest[0x9c] = RAM[0x01c46f20 + (trigger_note - 36)]
```

So:

| Test map | byte161 sequence | RAM map | Expected current C4 result |
|---|---|---|---|
| Original | `36..51` | `2425262728292a2b2c2d2e2f30313233` | PASS because metadata identities stay unique |
| all C4 | `60 x 16` | `3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c` | FAIL because all trigger identities collapse to note 60 |

This is not a slot selection failure. Source selection remains trigger-based. It is a metadata identity collapse after copy.

## Builder conclusions

- S1-C3 r3 producer builder emits the explicit `r9 == 0xa3` gate at `0x0201e1a6..0x0201e1ac`, then copies exactly `0x9c` bytes to `0x01c46520 + count*0xa0`, sets valid, reloads count after `memcpy`, and publishes ARMED last.
- S1-C4 v1/v2/v3 producer builders emit the same 188-byte producer. The new builder code adds `map_pointer`, `map_slot`, `staging_last_pointer`, `playback_load`, `playback_store`, and both `0x3f` restorations. They intentionally represent `0..127` with duplicates.
- S1-C4 v1 selector builder reads the Playback Note map after ARMED but before valid.
- S1-C4 v2 selector builder moves source/valid validation before map read and marks fail-closed fallback.
- S1-C4 v3 builder keeps v2 PI32 code unchanged, but changes the segmented-final callsite to target the reset wrapper rather than the no-mutation segmented stub. Thus v2 and v3 code evidence is identical, while package callsite semantics differ.

## Possible metadata layout to split Trigger identity and Playback Note

This is a layout proposal only, not a firmware patch. The current code writes only one consumer-visible metadata note byte at `dest + 0x9c`, so the layout alone is not patch-ready.

Keep current control bytes:

| Address | Byte | Purpose |
|---|---:|---|
| `0x01c465bd` | 1 | producer lock |
| `0x01c465be` | 1 | loaded count |
| `0x01c465bf` | 1 | publication state |

Use owned header/map space `0x01c46f20..0x01c46fb0`:

| Range | Bytes | Purpose |
|---|---:|---|
| `0x01c46f20..0x01c46f2f` | 16 | `playback_note_by_slot[16]`, current C4 use |
| `0x01c46f30..0x01c46f3f` | 16 | `trigger_note_by_slot[16]`, default `36..51` |
| `0x01c46f40..0x01c46f4f` | 16 | `identity_note_by_slot[16]`, distinct stock identity if pitch can be split |
| `0x01c46f50..0x01c46f5f` | 16 | `slot_flags[16]`, Original/custom/duplicate group bits |
| `0x01c46f60..0x01c46f6f` | 16 | `active_playback_by_trigger_slot[16]`, matched Note Off aid |
| `0x01c46f70..0x01c46f7f` | 16 | `active_cookie_by_trigger_slot[16]`, generation or voice token if exposed |
| `0x01c46f80..0x01c46f8f` | 16 | `duplicate_group_or_refcount[16]`, many-to-one release guard |
| `0x01c46f90..0x01c46faf` | 32 | header, magic/version/layout state/original mask/CRC/reserved |

Patch-readiness requirement: a future selector or voice hook must prove a real consumer path for **identity** separate from **pitch**. Without that, repeated C4 remains unsafe because the stock visible identity is still one byte.

## Validation

Run:

```sh
python3 baselines/v15/analysis/playback-note/live-reanalysis/producer/validate.py
(cd baselines/v15/analysis/playback-note/live-reanalysis/producer && shasum -a 256 -c SHA256SUMS)
```
