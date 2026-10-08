# v15 FM subsystem feasibility

Date: 2026-08-02 UTC

## Scope and safety boundary

This note analyzes the official v15 application/full-flash/R01 evidence, the
`smk-37-pro-docs` public documentation and local derived documents, the pinned
Jieli AC79 SDK evidence, and public DX7/SynprezFM source references for FM
subsystem feasibility.

No patch, OTA, flash, reset, or device write operation was performed for the
original analysis pass. Validation was limited to local file reads, hash checks,
pack/unpack self-tests, and documentation review.

## 2026-08-02 R02 live update

A later controlled R02 checkpoint resolved the named-timbre uncertainty for a
transient RAM source. The exact 156-byte Bank D display 14 Mooger #1 runtime
voice was sent through the official product SysEx framing into `0x01c37fd0`.
Pad Ch10 matched the keyboard reference, Note Off worked without a stuck note,
and changing the Ch1 UI patch did not change Ch10. See
[`../flash-candidates/R02/live-validation-20260802.md`](../flash-candidates/R02/live-validation-20260802.md).

This proves the runtime representation and independent Channel-10 source path,
but not a production storage design. The successful address is shared transient
SysEx RAM. Durable Ch10 ownership, per-note patch sets, reboot/SAVE lifecycle,
and concurrent SysEx protection remain open. The R01b/R01c app/text snapshot
failures below remain valid negative evidence for that specific source-location
design.

Evidence classes used below:

- **Direct evidence**: exact official-v15 bytes, clean full-flash bytes, R01
  manifests/build validation, or directly fetched public documentation.
- **Derived evidence**: prior project documents, v12/Mxx live results, public
  reverse-engineering tool output, or source-code comparisons. Useful for
  hypotheses, but not a standalone proof for v15 runtime behavior.
- **Inference**: a conclusion that follows from direct and/or derived evidence
  but still needs a live or deeper static experiment.

Probability grades:

| Grade | Meaning |
|---|---|
| Very high | Direct byte/source evidence, only small interpretation risk remains. |
| High | Multiple direct facts agree, but one key runtime behavior is unobserved. |
| Medium | Plausible and useful, but depends on derived evidence or incomplete decoding. |
| Low | Possible only as an exploration path; current evidence is weak or negative. |

## Executive verdict

| Topic | Current v15 feasibility | Probability | Short reason |
|---|---|---:|---|
| FM engine exists and consumes DX7-like voices | **Live-proven on v15, internal renderer still unnamed** | Very high, ~0.95 | Physical Pad and raw MIDI tests produced stock and modified FM sounds. R01 live-proved the `0x0201c5ec` Note path, while later comparisons disproved intentional named-voice selection from an app-resident snapshot. |
| DX7-style packed voice format | **Established for factory banks** | Very high, ~0.95 | Four 4096-byte full-flash banks at `0x000f4000..0x000f7fff` contain 32 x 128-byte voice records with DX7 name fields; R01 extracts `HAND DRUM ` at `0x000f7580`. |
| 156-byte runtime voice | **Established as the per-note copy shape, not sufficient proof of a valid source location** | Very high, ~0.95 for size; low for app-resident injection | Official Note On/Off both copy `0x9c` bytes from RAM `0x01c34c74`. R01b/R01c showed that app/text-resident bytes with the same calculated content do not reproduce named factory voices. |
| Operator/envelope mapping | **Packed-to-runtime byte map is known; audible semantics are not fully verified** | Medium-high, ~0.70 | The byte split is deterministic and round-trips through `tools/dx7_vmem.py`; individual runtime byte meanings/ranges still need parameter-sweep audio tests. |
| Polyphony and voice allocation | **Open for v15** | Medium, ~0.45 | Public docs claim 12 notes and v12 M05/M06/M08 proved stock allocator can sound multiple FM timbres in modified builds, but v15 R01 has no live stress result and no allocator function identity. |
| Real-time parameter editing | **Possible for future notes; currently-sounding voice editing is unproven** | Medium-low, ~0.35 | Note-time snapshot replacement is feasible statically. Safe live mutation of current voices, UI/CC binding, per-part state, and persistence are not established. |

## Primary inputs, revisions, hashes, and URLs

### Official v15 and R01 artifacts

| Item | Value |
|---|---|
| Official v15 package | `build/SMK-37_Pro_015.fwsc` |
| Official package SHA-256 | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` |
| Official extracted app | `build/v15-official-app.bin` |
| Official app size | 617,012 bytes |
| Official app SHA-256 | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` |
| Runtime base used in v15 analysis | `0x02000000` |
| Clean full-flash dump | `baselines/v15/device-dumps/v15-clean-baseline-a.bin` and `...-b.bin` |
| Clean full-flash SHA-256 | `1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b` |
| R01 app SHA-256 | `e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7` |
| R01 package SHA-256 | `292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462` |
| R01 manifests | `baselines/v15/analysis/flash-candidates/R01/app-manifest.json`, `package-manifest.json` |
| R01 validation command run | `python3 tools/validate_v15_mod_capabilities.py` returned PASS |
| R01 live/device validation | Done 2026-08-02. Channel branch passed; original R01 Note Off failed; R01b/R01c Note Off passed; HAND DRUM/BUZZ BASS/Mooger #1 intended identity failed; official v15 restored. |

Relevant R01 addresses:

| Address | Meaning | Evidence |
|---:|---|---|
| `0x0201c5ec` | MIDI dispatcher candidate used by R01 | R01 manifest and capability validator |
| `0x0201c67c` | Note On memcpy source replacement point | R01 manifest |
| `0x0201c63e` | Note Off memcpy left unchanged | R01 manifest |
| `0x02005660` | v15 factory voice loader/expansion reference used by R01 | R01 manifest and builder |
| `0x02048cce` | memcpy callee used by R01 wrapper | R01 manifest |
| `0x0201e13e` | R01 wrapper entry/code cave | R01 manifest |
| `0x0201e162` | Embedded 156-byte `HAND DRUM ` runtime snapshot | R01 manifest |
| `0x0201e468`, `0x0201e49c` | Existing direct callers neutralized because the replaced code cave covered SysEx routine bytes | R01 manifest |

R01 full-flash voice source:

| Field | Value |
|---|---|
| Factory bank/preset | bank 3, preset 11 |
| Voice name | `HAND DRUM ` |
| Packed flash offset | `0x000f7580` |
| Packed voice size | 128 bytes |
| Packed SHA-256 | `a64fc8623c877b16ecc8eb0259f14eb2b58e46e92fcd073849bbddf16b060452` |
| Runtime snapshot size | 156 bytes |
| Runtime SHA-256 | `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf` |

### Public and derived sources

| Source | Revision / URL | Role and caution |
|---|---|---|
| `jonathaslacerda/smk-37-pro-docs` | inspected in local notes at commit `8f1bf1115cc8fe874bbac326d4f1f1513d743844`; current URL <https://github.com/jonathaslacerda/smk-37-pro-docs> | Community documentation. Claims SMK-37 Pro has a Yamaha-DX7-compatible FM engine, six operators, 32 algorithms, mono/poly, and 12-note polyphony. Not a binary proof. |
| `smk-37-pro-docs` README fetched 2026-08-02 | <https://raw.githubusercontent.com/jonathaslacerda/smk-37-pro-docs/main/README.md> | Confirms current README still states the FM/DX7/polyphony claims. |
| `smk-37-pro-docs` SYSEX page fetched 2026-08-02 | <https://raw.githubusercontent.com/jonathaslacerda/smk-37-pro-docs/main/sysex/SYSEX.md> | Lists four stock FM banks. |
| `smk-37-pro-docs` firmware page fetched 2026-08-02 | <https://raw.githubusercontent.com/jonathaslacerda/smk-37-pro-docs/main/firmware/FIRMWARE.md> | Lists v15 firmware package and release notes. |
| Jieli AC79 SDK | <https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK>, branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` | Strong platform/code-lineage source, but its public MIDI synth did not match v15 synth code. |
| `lib_midi_dec.a` | SHA-256 `3f4a38dbec69eb2f85c56838eaa461252c8ee0e419211d06aebf46ce9bc62f03` | Public Jieli sample/wavetable MIDI library evidence, not v15 FM proof. |
| `audio_server.a` | SHA-256 `16de11ce1f363f37cdc9c1e84cb169ebdc3bfc802d6f932172bcb40f07d2f6ae` | Public Jieli audio/MIDI wrapper evidence. No defensible synth match in v15. |
| `sdk.elf` | SHA-256 `250b0534fee9f57208b42e38c97c36982875fac901db1d9979e781f0d26e0cf3` | Positive controls matched USB/filesystem code, but not public MIDI synth. |
| Quarkslab `ghidra-jieli` | <https://github.com/quarkslab/ghidra-jieli/tree/e1bd0707874b77b759401555d24839ad43af1267> | Better pi32v2 decode coverage, still incomplete. |
| Kagaimiq `ghidra-jieli` | <https://github.com/kagaimiq/ghidra-jieli/tree/b5e60122b6cd3e6b615387035994b8bed0ea1a26> | Older processor/ABI model. Used with local decoder supplement in earlier analysis. |
| Kagaimiq `jielie` | `1657d25e6e51df6b2c18cd55cfc576c4a6370c63` | Community chip/core notes. |
| Dexed | <https://github.com/asb2m10/dexed>, inspected commit `2e182b3db85c09083ab13c8b9b00565ce7d9ff85` | Independent DX7 VMEM format reference and source of bundled SynprezFM cartridges used only in revoked M09 forensic templates. |
| Public USB MIDI spec | <https://www.usb.org/sites/default/files/midi10.pdf> | Descriptor/endpoint transport standard. |

## Direct evidence from v15 full flash and R01

### 1. v15 contains 128-byte DX7-style factory voice records

Direct check on `baselines/v15/device-dumps/v15-clean-baseline-a.bin`:

```text
flash sha256 1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b
0xf4000 body_sha256 39bb3267ffbf3bf2f728142874655fbd288fb98979574ca7eab0ab331450abae first4 WATER GDN, E.ORGAN 1, XMAS BELLS, PI-3.14R0D preset11 *Kurzweil2
0xf5000 body_sha256 9ae842be852be6fff01302ed19ed40bbdb3d03dba7d19772ad09703dc1dbcbb1 first4 AN.STRG 1A, BRASS   2, BRASS   3, FLUTE   1 preset11 SYN-LEAD 3
0xf6000 body_sha256 ca09ba4b9299ab29a9a577e7a38631f2664f113129d0f65305a366da3877dce1 first4 ANALG STR2, ANALG SYN2, ANALGSYN15, ANALG SYN9 preset11 WineGlass2
0xf7000 body_sha256 9dee037becaa21589fd45481bed5d32e0d184aa2654cdd286208f767adec2953 first4 BUZZ BASS, Bang ?????, BASSE BIEN, BASS-THING preset11 HAND DRUM
```

Each 4096-byte body is exactly 32 x 128-byte records. The ten-byte names at
record offset `118..127` match the DX7 VMEM naming convention and the R01
`HAND DRUM ` extraction. Raw flash stores the 4096-byte bodies, not complete
4104-byte Yamaha SysEx wrappers.

**Direct conclusion:** v15 full flash stores factory/user voice data in a
DX7-style 32 x 128-byte packed-bank layout. This is stronger than a public-docs
claim because the bytes are in the clean v15 full-flash dump.

**Limit:** this alone does not name the live oscillator engine function or prove
that every packed field has the same audible semantics as a Yamaha DX7.

### 2. R01 expansion bytes are reproducible, but app-resident source injection was live-disproven

Direct validation performed for this note:

```text
python3 tools/dx7_vmem.py
python3 tools/validate_v15_mod_capabilities.py
```

The local verifier reproduced the R01 `HAND DRUM ` extraction from clean full
flash and confirmed:

```text
verified hand drum packed/runtime a64fc8623c877b16ecc8eb0259f14eb2b58e46e92fcd073849bbddf16b060452 98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf
v15 mod capability matrix: PASS
```

R01's `app-manifest.json` embeds the 156-byte runtime snapshot at `0x0201e162`
and replaces the Note On memcpy call at `0x0201c67c` with a wrapper that copies
that snapshot for human MIDI channel 10 (`r9 == 9`). Non-Ch10 follows the stock
memcpy path. Note Off memcpy at `0x0201c63e` is intentionally unchanged.

The later official-v15 loader reanalysis proved that `0x02005660` creates the
live source at RAM `0x01c34c74`, and that clean Mooger #1 produces the same first
`0x9c` calculated bytes as the static converter. Nevertheless, R01b/R01c did
not sound like the selected factory voices. Therefore content equality alone
does not prove that an address in the app text region is a valid runtime voice
source.

**Direct conclusion:** `0x9c` is the correct per-note copy size and the expansion
map is reproducible. The specific design that embeds those bytes at
`0x0201e162` and uses that program address as the memcpy source is revoked.

**Next proof:** have the official loader materialize the target voice, clone its
first `0x9c` bytes into a provenance-checked RAM buffer, and use the same RAM
source for Ch10 Note On and Note Off.

### 3. The R01 change set is small and app-only

R01 package manifest reports:

- `app_byte_count`: 202;
- `flash_byte_count_including_crc_fields`: 210;
- `fwsc_byte_count`: 216;
- `safety_gate`: `PASS`;
- protected hashes before and after are identical for boot/layout,
  `uboot.boot`, `isd_config.ini`, and post-app resources/reserved.

**Direct conclusion:** the R01 evidence supports app-only experiment packaging,
not a boot/config/resource rewrite.

**Limit:** app-only and hash-gated does not imply safe-to-flash or live-correct.
M09/M10 history shows that statically plausible app data changes can still
produce boot failure on earlier v12-derived builds.

## Packed DX7 voice to 156-byte runtime map

The deterministic mapping used by `tools/dx7_vmem.py` and
`tools/build_v15_r01_hand_drum.py` is:

### Per-operator map

There are six operators. Packed operator `op` begins at `17 * op`; runtime
operator `op` begins at `21 * op`.

| Runtime relative offset | Source packed offset | Meaning from DX7 VMEM model | Directness |
|---:|---:|---|---|
| `+0..+3` | `+0..+3` | Operator EG rates 1..4 | Direct byte map, DX7 semantic inferred from VMEM docs |
| `+4..+7` | `+4..+7` | Operator EG levels 1..4 | Direct byte map, DX7 semantic inferred |
| `+8` | `+8` | Keyboard level scaling breakpoint | Direct byte map, DX7 semantic inferred |
| `+9` | `+9` | Left depth | Direct byte map, DX7 semantic inferred |
| `+10` | `+10` | Right depth | Direct byte map, DX7 semantic inferred |
| `+11` | `packed[+11] & 0x03` | Left curve | Direct byte split, DX7 semantic inferred |
| `+12` | `(packed[+11] >> 2) & 0x03` | Right curve | Direct byte split, DX7 semantic inferred |
| `+13` | `packed[+12] & 0x07` | Lower 3-bit field, normally rate scaling | Direct byte split, semantic inferred |
| `+20` | `(packed[+12] >> 3) & 0x0f` | Upper 4-bit field, normally detune | Direct byte split, semantic inferred |
| `+14` | `packed[+13] & 0x03` | Amplitude modulation sensitivity | Direct byte split, semantic inferred |
| `+15` | `(packed[+13] >> 2) & 0x07` | Key velocity sensitivity | Direct byte split, semantic inferred |
| `+16` | `packed[+14]` | Output level | Direct byte map, semantic inferred |
| `+17` | `packed[+15] & 0x01` | Oscillator mode | Direct byte split, semantic inferred |
| `+18` | `(packed[+15] >> 1) & 0x1f` | Frequency coarse | Direct byte split, semantic inferred |
| `+19` | `packed[+16]` | Frequency fine | Direct byte map, semantic inferred |

### Common voice map

| Runtime offset | Source packed offset | Meaning from DX7 VMEM model | Directness |
|---:|---:|---|---|
| `126..129` | `102..105` | Pitch EG rates 1..4 | Direct byte map, semantic inferred |
| `130..133` | `106..109` | Pitch EG levels 1..4 | Direct byte map, semantic inferred |
| `134` | `110` | Algorithm, 0..31 in DX7 terms | Direct byte map, semantic inferred |
| `135` | `packed[111] & 0x07` | Feedback | Direct byte split, semantic inferred |
| `136` | `(packed[111] >> 3) & 0x01` | Oscillator key sync | Direct byte split, semantic inferred |
| `137..140` | `112..115` | LFO speed, delay, pitch-mod depth, amp-mod depth | Direct byte map, semantic inferred |
| `141` | `packed[116] & 0x01` | LFO sync | Direct byte split, semantic inferred |
| `142` | `(packed[116] >> 1) & 0x07` | LFO waveform | Direct byte split, semantic inferred |
| `143` | `(packed[116] >> 4) & 0x07` | Pitch modulation sensitivity | Direct byte split, semantic inferred |
| `144` | `117` | Transpose | Direct byte map, semantic inferred |
| `145..154` | `118..127` | Ten-byte voice name | Direct byte map |
| `155` | constant `0x3f` in R01 | Six-operator enable mask | Direct byte map; runtime use inferred |

**Inference:** because the map is exactly a DX7 VMEM unpacking pattern and R01
uses it to create the Note On timbre snapshot, runtime bytes `0..155` are best
modeled as a DX7 VCED-like six-operator voice plus an operator mask.

**Remaining uncertainty:** the byte layout is known, but the SMK runtime may
clamp, reinterpret, ignore, or post-process some fields. Audible per-field
semantics need controlled edits.

## Jieli SDK and public synth evidence

### Direct/derived findings

The pinned SDK evidence says:

- SDK: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch
  `release/AC79NN_SDK_V1.2.0`, commit
  `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`.
- The SDK is a strong platform/code-lineage match for v15 for USB and calibration
  positives.
- The public MIDI synth implementation does **not** produce a defensible byte,
  relocation-aware, table, string, or operation-table match in v15.
- The public AC79 MIDI synth evidence points to sample/wavetable synthesis:
  `midi_synth.o`, tone-file readers, sample maps, loop points, ADPCM decoding,
  envelopes, filtering, pan, and PCM generation.
- AC79 public documentation uses “FM” for external FM radio receiver modules in
  many contexts, not necessarily frequency-modulation synthesis.

**Conclusion:** the public Jieli SDK should not be used as proof of the SMK FM
engine ABI, allocator, or 156-byte voice layout. It is useful for platform ABI,
USB lineage, and negative controls, but the SMK synth appears product-specific
or built from sources/libraries absent from the public SDK.

## Public SMK docs and derived project evidence

### `smk-37-pro-docs`

The current public README states:

- SMK-37 Pro has “a FM engine sound source compatible with Yamaha DX7 tone
  generator.”
- Internal synthesis engine: six FM operators, Yamaha DX7 MK1 compatibility,
  feedback, 32 algorithms, mono/poly, FX, and polyphony 12 notes.
- The SYSEX page lists four stock FM banks.

**Directness:** direct web documentation, but community-maintained. It supports
product-level expectations and aligns with v15 full-flash packed-bank bytes, but
it is not a substitute for binary/runtime proof.

### Derived v12/Mxx documents

Relevant derived findings from `docs/research-notes.md`,
`docs/fm-drum-plan.md`, `docs/firmware-versioning.md`, and
`docs/m09-brick-incident.md`:

- Prior project work identified DX7 VMEM/SysEx bank structure and a 156-byte
  runtime snapshot model.
- M05 on v12/display 1.05 verified simultaneous channel 1 patch N and channel 2
  patch N+1 FM playback.
- M06 verified local keyboard/current patch N and local pads/Ch10 patch N+1 FM
  playback.
- M08 verified Ch1/current patch and Ch10 fixed Bank 0 presets 0..15 isolation,
  but maximum-polyphony stress was still pending.
- M09 stored eight app-resident 156-byte DX7 percussion templates and failed to
  boot after OTA. M10 then populated the candidate data range only and also
  failed. These failures strongly warn against treating zero-filled app ranges
  as safe persistent data caves.

**Directness:** these are not v15 direct evidence. They are strong design clues
and risk evidence for future work.

## Feasibility by requested subsystem question

### FM engine

**Direct evidence:**

- v15 clean full flash stores four 4096-byte banks of 32 x 128-byte DX7-style
  packed voices at `0x000f4000`, `0x000f5000`, `0x000f6000`, and `0x000f7000`.
- R01 uses a v15 factory loader model at `0x02005660` and a Note On snapshot
  copy point at `0x0201c67c` to inject a 156-byte runtime voice.
- `smk-37-pro-docs` claims a DX7-compatible FM source with 12-note polyphony.

**Inference:** v15 almost certainly contains an FM voice engine or a close
DX7-compatible product-specific synth path that consumes these voices.

**Unresolved:** the actual v15 oscillator/render engine function, allocator,
per-voice record layout after the 156-byte snapshot, and audio callback chain are
not named by current static analysis. The public Jieli MIDI synth does not match
v15 and appears sample/wavetable-oriented.

**Possibility grade:** High, ~0.75.

**Needed experiments:**

1. Test a loader-produced RAM clone checkpoint against the same stock UI Patch.
2. Static search for references to the copied 156-byte snapshot destination and
   downstream allocator/render structures using a more complete pi32v2 decoder.
3. Compare v15 factory-bank edits or SysEx loads against live patch changes if a
   non-destructive editor path is available.

### DX7-style packed voice

**Direct evidence:**

- Factory packed voice `HAND DRUM ` is exactly 128 bytes at full-flash offset
  `0x000f7580`, SHA-256
  `a64fc8623c877b16ecc8eb0259f14eb2b58e46e92fcd073849bbddf16b060452`.
- The name field is at packed offsets `118..127`, matching DX7 VMEM.
- `tools/dx7_vmem.py` parses 4104-byte Yamaha 32-voice SysEx and round-trips
  128-byte VMEM packing/unpacking.
- `smk-37-pro-docs` SYSEX page lists four stock FM banks.

**Inference:** the v15 factory/user bank sectors are DX7 VMEM bodies without
SysEx wrapper/checksum bytes.

**Possibility grade:** Very high, ~0.95.

**Needed experiments:**

1. Hash and archive all four v15 bank bodies plus a table of all 128 voice names.
2. If public `smk-37-pro-docs` bank files are used, pin their exact commit and
   compare the 4096-byte SysEx bodies to v15 flash sectors.
3. Verify whether v15 writes user edits back into these sectors or shadows them
   elsewhere.

### 156-byte runtime voice

**Direct evidence:**

- R01 runtime snapshot size is 156 bytes and SHA-256
  `98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf`.
- `tools/build_v15_r01_hand_drum.py` expands a 128-byte packed voice into 156
  bytes with `out[155] = 0x3f`.
- R01 copies `0x9c` bytes at the special branch. `0x9c == 156`.
- `tools/validate_v15_mod_capabilities.py` now records channel/source-path
  separation as live-proven and `VOICE-03` app-resident factory-voice injection
  as live-disproven.

**Inference:** v15 Note On has a per-event or per-voice timbre snapshot point
whose expected size is 156 bytes.

**Possibility grade:** High, ~0.85.

**Needed experiments:**

1. Replace the disproven app/text-resident source with an official-loader-produced RAM clone.
2. Determine whether the destination at `r0` is a voice object, a transient event
   object, or a staging buffer copied again by the allocator.
3. Confirm whether bytes `156..162` mentioned in older v12 records are truly
   excluded from v15 per-event snapshots.

### Operator/envelope mapping

**Direct evidence:**

- The packed-to-runtime byte map is implemented twice in project tooling:
  `tools/dx7_vmem.py` and `tools/build_v15_r01_hand_drum.py`.
- `tools/dx7_vmem.py` self-test passes a pack/unpack round trip.
- The map exactly expands six 17-byte operators into six 21-byte runtime operator
  blocks plus common voice data.

**Inference:** runtime offsets match DX7/VCED-style operator and common fields.

**Possibility grade:** Medium-high, ~0.70.

**Needed experiments:**

1. Generate controlled one-parameter voice variants, preferably changing only one
   byte among EG rate, EG level, output level, coarse, fine, algorithm, feedback,
   and operator mask.
2. Use a safe same-size R01-like snapshot replacement, not a new app-tail data
   cave, after a recovery strategy is available.
3. Record audio and compare expected changes: mute one operator via output level
   or mask, change algorithm, change carrier coarse frequency, change envelope
   decay/release.
4. Verify value bounds. DX7 fields are mostly 0..99 or small bitfields, but SMK
   runtime might assume tighter ranges or table indices.

### Polyphony and voice allocation

**Direct evidence for v15:**

- Original R01 changed only Note On and produced a Ch10 stuck note. R01b/R01c
  changed both Note On `0x0201c67c` and Note Off `0x0201c63e` to the same source,
  which restored Note Off.
- Product docs claim 12-note polyphony.
- Live v15 channel routing and release observations now exist, but full
  overlapping polyphony/voice-stealing stress is still incomplete.

**Derived evidence:**

- v12 M05/M06/M08 owner tests proved simultaneous FM parts are possible in those
  modified v12-derived builds.
- M08 still needed maximum-polyphony/voice-stealing stress.

**Inference:** the stock engine probably has a voice pool and can play multiple
notes, but v15 R01 does not yet prove channel-isolated allocation, stealing,
release ordering, or pool limits.

**Possibility grade:** Medium, ~0.45 for confidently modifying allocation on
v15 today; higher for ordinary stock polyphony existing.

**Needed experiments:**

1. On live v15/R01, play overlapping Ch1 and Ch10 note streams and vary release
   order. Check stuck notes, cross-timbre contamination, and all-notes-off.
2. Stress up to and past 12 simultaneous notes if the device is safe to test.
3. Use USB/MIDI logs plus human audio observation. USB success alone is not an
   audio proof.
4. Static trace from Note On snapshot copy to allocator structures and active
   voice records.

### Real-time parameter editing

**Direct evidence:**

- R01 can statically select a different source path for future Ch10 events, but
  app/text-resident snapshot identity was live-disproven.
- The v15 capability matrix marks `FM-01` as only partially confirmed: internal
  FM parameter semantic editing is not fully verified.
- R01 deliberately replaces the code cave that formerly contained Yamaha
  single-voice SysEx pack/save-related bytes, so that feature is not preserved in
  R01.

**Inference:** editing a loader-produced RAM snapshot before a future Note On is
feasible in principle. Treating arbitrary app/text bytes as the snapshot is not.
Editing a currently sounding voice in real time is not established.
The UI, CC, SysEx, save/load, and per-part mutable-state paths are still separate
reverse-engineering tasks.

**Possibility grade:** Medium-low, ~0.35.

**Needed experiments:**

1. First prove parameter edits at note-on time with fixed compiled snapshots.
2. Then identify whether the active voice retains its own copy or references a
   shared patch buffer.
3. Only after active voice ownership is known, test live edits such as output
   level or algorithm changes while a note is held.
4. Separate immediate-audio edits from persistent preset writes. Do not write
   factory/user bank sectors until writeback addresses and recovery are proven.
5. Avoid using app-tail zero ranges for mutable tables unless an independent
   storage contract is identified. M09/M10 show that static no-reference scans
   are insufficient.

## Risk notes

- Public Jieli AC79 “FM” references often mean FM radio, not FM synthesis.
- The public AC79 MIDI synth library appears sample/wavetable based and does not
  match v15's product-specific synth path. Do not import its structs as v15
  truth.
- R01 is safer than the revoked M09 style because it uses a small audited
  replacement area and a single embedded snapshot, but R01 is still not live
  verified.
- The v15 runtime-trace tool did not send packets because the exact v15 device
  did not enumerate. It therefore adds safety validation, not synth behavior.

## Recommended next safe work

1. Archive a fuller v15 bank report: all four 4096-byte bodies, all 128 names,
   SHA-256 per voice, and comparison against pinned public SysEx files if their
   exact blobs are available.
2. Improve static v15 tracing around `0x0201c67c`, the destination pointer in
   `r0`, and downstream voice-pool writes.
3. Prepare a non-flashing parameter-snapshot experiment plan with exact bytes and
   rollback requirements, but do not execute until the hardware recovery path is
   acceptable.
4. If a live v15 device becomes available, run only the existing guarded
   endpoint observer first, then a minimal R01 audio checklist if the owner
   explicitly authorizes flashing.
