# Independent final review: commits `9f9b7d7` and `fe33500`

Date: 2026-08-03 UTC  
Reviewer: Jcode  
Scope: offline-only review of exact commits in `/Users/spectrum/Documents/SMK37ProMod`

## Verdict

**PASS** for the committed offline artifacts in:

- `9f9b7d75358b8efcabfef25b1ed07af6cfec15ac` (`Add S1-C3 compact producer proof`)
- `fe3350063c56a0cff7ab855735b0c7e8a04c957e` (`Add v15 Bank D 1-16 diagnostic packet set`)

**BLOCK** for live/device use. This review does not authorize device access, firmware/FWSC build, flash/reset, MIDI transport open, or live send.

## Commands and independent checks performed

```sh
git show --stat --oneline --decorate --name-status 9f9b7d7 fe33500
git rev-parse 9f9b7d7 fe33500 2a23cf5 HEAD
python3 baselines/v15/analysis/patch-set-ui/s1c3/compact-producer/validate.py
python3 baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16/validate.py
python3 tools/build_v15_patch_set.py build \
  baselines/v15/device-dumps/v15-clean-baseline-a.bin \
  baselines/v15/analysis/patch-set-ui/s1c3/packet-set-bank-d-1-16/config.json \
  /Users/spectrum/.jcode/scratch/s1c3-final-review-20260803T0116Z/rebuilt-bank-d
```

I also ran an independent Python check over committed bytes and manifests. It verified producer length/hash/placement, full independent PI32 decode coverage, mutation ordering, scratch rebuilt Bank D artifacts, exact stream order, runtime-object equivalence, physical Pad permutation, and sender manifest live-send blocking.

Scratch check result:

```text
independent review checks PASS
producer sha 4e738a54dda52abd2ab816201ece7d1851215cba90268c14c535503b4ceb2460
packet stream sha 5454832b5b97cd8773efe23aa0ba343ae14639d7a38584c43fb2f74d4c9e6939
runtime-slots sha fdf7ebdf911041de64ebd80c3d807959b29034ef4e2fed35245b2dfe7b032270
patch set PASS: BANK D 01-16 DIAGNOSTIC -> /Users/spectrum/.jcode/scratch/s1c3-final-review-20260803T0116Z/rebuilt-bank-d
runtime image: fdf7ebdf911041de64ebd80c3d807959b29034ef4e2fed35245b2dfe7b032270
packet stream: 5454832b5b97cd8773efe23aa0ba343ae14639d7a38584c43fb2f74d4c9e6939
```

## `9f9b7d7`: compact producer review

### Full PI32 decode

**PASS.** `producer.bin` is exactly 130 bytes with SHA-256:

```text
4e738a54dda52abd2ab816201ece7d1851215cba90268c14c535503b4ceb2460
```

`independent-decode.tsv` contains 49 decoded instructions. The sum of decoded instruction sizes is 130 bytes, exactly covering the producer/stub byte stream with no undecoded tail or overlap.

### 178-byte placement

**PASS.** Placement arithmetic is closed:

- start: `0x0201e1a2`
- end exclusive: `0x0201e224`
- owned limit exclusive: `0x0201e254`
- owned window: `178` bytes
- used: `130` bytes
- spare: `48` bytes
- overrun: `0` bytes

### Pre-mutation gates

**PASS.** The direct entry copies `r9` to `r0`, subtracts `0x80` and `0x23`, then branches on nonzero:

```text
0x0201e1a6 9016       mov r0,r9
0x0201e1a8 e020       add r0,#-0x80
0x0201e1aa f03d       add r0,#-0x23
0x0201e1ac 80f83700   jne r0,#0,0x0201e21e
```

The first mutating/testset operation is only later at `0x0201e1b6` (`2000b000`). Therefore wrong-length packets return at `0x0201e21e` before lock/testset/state/count/slot mutation.

### Testset polarity contract

**PASS.** The try-lock sequence is:

```text
0x0201e1b6 2000b000   csync; testset b[r0]
0x0201e1ba 40e83000   ifeq 0x0201e21e
```

This matches the established repository polarity contract: `testset` zero means acquisition failure, so `ifeq` returns without clearing another owner; nonzero falls through as the acquired path.

### Slot pointer bounds

**PASS.** The producer rejects `loaded_count >= 16` before slot pointer arithmetic:

```text
0x0201e1dc 03fd1b20   jge r3,#16,0x0201e216
0x0201e1e2 e6e1a060   r6 = r6 * 0xa0
0x0201e1e6 c7ff2065c401 r7 = 0x01c46520
0x0201e1ee 06e19c70   r6 = r7 + 0x9c
```

For accepted counts `0..15`, the maximum valid byte is:

```text
0x01c46520 + 15 * 0xa0 + 0x9c = 0x01c46f1c
```

This is inside the 16-slot area ending at `0x01c46f20`.

### Valid/count/ARMED ordering

**PASS.** Publication is ordered as required:

1. clear selected `valid` at `0x0201e1f4`
2. copy exactly `0x9c` bytes via `memcpy` at `0x0201e1fc`
3. `csync` at `0x0201e202`
4. set selected `valid = 1` at `0x0201e206`
5. increment and store `loaded_count = i + 1` at `0x0201e208..0x0201e20a`
6. only if count is 16, `csync`, then write `state = ARMED` at `0x0201e214`

Thus valid is last for each slot payload, count is after valid, and ARMED is last for slot 15.

### Segmented stub

**PASS.** Segmented entry `0x0201e220` is only:

```text
0x0201e220 7904 push {rets,r9..r4}
0x0201e222 5904 pop {pc,r9..r4}
```

It has no store, testset, call, state/count mutation, or slot mutation path.

### Compact producer blocking scope

**BLOCK.** `9f9b7d7` proves offline producer bytes and callsite routing only. It does not produce or approve a firmware image, FWSC package, flash/reset operation, MIDI/USB access, or live send.

## `fe33500`: Bank D packet set review

### Official-v15 derivation

**PASS.** The packet builder SHA-gates the full flash dump before reading factory voices. The source dump SHA-256 is:

```text
1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b
```

I rebuilt from `baselines/v15/device-dumps/v15-clean-baseline-a.bin` and the committed config into scratch. The rebuilt `manifest.json`, `note-map.bin`, `runtime-slots.bin`, and `sequential-product-packets.syx` matched the committed files byte-for-byte.

### 16 exact 156-byte runtime objects

**PASS.** There are exactly 16 committed runtime-object files. Each is exactly 156 bytes. Each equals the payload bytes of its corresponding direct Yamaha product SysEx packet, and each hash matches `SHA256SUMS`, `manifest.json`, `packet-set-manifest.json`, and `sender-manifest.json`.

### Exact order: notes 36..51, Bank D patches 1..16

**PASS.** The committed config and manifests are exactly:

```text
slot 00 note 36 Bank D patch 01 BUZZ BASS
slot 01 note 37 Bank D patch 02 Bang ?????
slot 02 note 38 Bank D patch 03 BASSE BIEN
slot 03 note 39 Bank D patch 04 BASS-THING
slot 04 note 40 Bank D patch 05 BASS SLAP
slot 05 note 41 Bank D patch 06 BEAMER 2
slot 06 note 42 Bank D patch 07 Onglon
slot 07 note 43 Bank D patch 08 SOFTSTEEL
slot 08 note 44 Bank D patch 09 BASS-ROADS
slot 09 note 45 Bank D patch 10 E.ORGAN 1
slot 10 note 46 Bank D patch 11 YEAAAHH
slot 11 note 47 Bank D patch 12 HAND DRUM
slot 12 note 48 Bank D patch 13 HAND CLAP1
slot 13 note 49 Bank D patch 14 Mooger #1
slot 14 note 50 Bank D patch 15 Moog Solo2
slot 15 note 51 Bank D patch 16 Mooger Low
```

The sequential stream is exactly 16 packets * 163 bytes = 2608 bytes, concatenated in this order. Its SHA-256 is:

```text
5454832b5b97cd8773efe23aa0ba343ae14639d7a38584c43fb2f74d4c9e6939
```

### SysEx and runtime layout

**PASS.** Each packet has direct Yamaha product framing:

```text
F0 43 00 00 01 1B + 156-byte runtime object + F7
```

`runtime-slots.bin` is `16 * 0xa0 = 0x0a00` bytes. For each slot, bytes `0..0x9b` match the 156-byte runtime object and bytes `0x9c..0x9f` are `01 01 00 00`.

### Physical Pad permutation from `2a23cf5`

**PASS.** `physical-pad-permutation.json` pins `source_commit: 2a23cf5` and matches commit `2a23cf5017eff520f775e511f8d3d80e15163e7d`, which corrected the current profile to official 2x8 Pad numbering.

The exact physical Pad 1..16 to note-ordered slot sequence is:

```text
4,5,6,7,12,13,14,15,0,1,2,3,8,9,10,11
```

The corresponding Pad 1..16 MIDI-note sequence is:

```text
40,41,42,43,48,49,50,51,36,37,38,39,44,45,46,47
```

### Hashes and sender manifest

**PASS.** The committed `SHA256SUMS` recursively matches all packet-set artifacts. `sender-manifest.json` pins each packet path, order, size, runtime hash, packet hash, and USB-MIDI packetization facts. It explicitly blocks live sending:

- `send_enabled: false`
- `device_accessed: false`
- `midi_transport_opened: false`
- `firmware_built: false`
- `fwsc_built: false`
- `flash_performed: false`
- `reset_performed: false`
- verdict `device_access_or_live_send: BLOCK`
- verdict `firmware_or_flash: BLOCK`

### Packet set blocking scope

**BLOCK.** `fe33500` is an offline diagnostic packet set only. It does not authorize device access, transport open, firmware/FWSC generation, flash/reset, or live send.

## Final decision

**PASS:** exact offline compact producer proof and exact offline Bank D 1..16 packet-set artifacts satisfy the requested invariants.

**BLOCK:** any live/device-facing action remains outside this artifact and is not authorized by this review.
