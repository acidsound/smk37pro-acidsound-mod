# Official v15 UI/SAVE raw-prefix seed investigation

Date: 2026-08-04  
Scope: exact official v15 code paths, existing v15 traces, and offline files only. No device, USB, MIDI, flash, recovery, or v12-derived assumptions were used.

## Decision

**BLOCK for a deterministic safe host sender.**

Exact official v15 code shows that stock UI `SAVE` can write the selected raw `0xa3` record. Since Bank D presets 1..16 map to raw records `96..111`, normal firmware can write those record prefixes if the user manually selects each Bank D slot and presses stock `SAVE` after the host has materialized the desired current snapshot.

However, this is not a safe unattended host protocol. Product SysEx alone writes only the selected packed `0x80` record. The raw writer is the stock UI SAVE handler, its selection and invocation are not proven host-addressable, and its storage-write return values are ignored. No sender was emitted.

## Capability split

| Path | Exact v15 result | Raw prefix 96..111 effect |
|---|---|---|
| Product single-voice SysEx | `0x0201e468/0x0201e49c -> 0x0201e13e`, then `0x0201e46c/0x0201e4a0 -> 0x02005660` | No direct raw write. It writes the selected packed `0x80` slot through `0x02004b02`. |
| Single-parameter SysEx | `F0 43 10 aa bb dd F7`; `0x0201e634` stores `dd` to `g+0x1a14+(((aa<<7)+bb)&0xff)` | Volatile current-snapshot byte write only. For byte `0x9b`, use `aa=0x01`, `bb=0x1b`. |
| Stock UI SAVE | `0x02026da6` writes `g+0x1a14`, length `0xa3`, to `*(g+0x160)+0x4000+(bank*32+preset)*0xa3` | Yes, if Bank D slot is selected. It writes the full raw record, including prefix and preserved/current tail. |

A manual normal-firmware sequence that should seed one prefix is therefore: select Bank D preset N on the stock UI, send official product SysEx to materialize bytes `0x00..0x9a`, send single-parameter byte `0x9b` if the S1C7 Playback Note byte must differ from the stock normalized value, then press stock SAVE before any selection change.

## Exact xrefs and bytes checked

| VA | Bytes | Meaning |
|---|---|---|
| `0x0201e468` | `bfea69fe` | complete product SysEx calls 0x0201e13e packer |
| `0x0201e46c` | `bfeaf838` | complete product SysEx reloads selected record through 0x02005660 |
| `0x0201e49c` | `bfea4ffe` | segmented-final product SysEx calls 0x0201e13e packer |
| `0x0201e4a0` | `bfeade38` | segmented-final product SysEx reloads selected record through 0x02005660 |
| `0x0201e606` | `89f8180e` | single-parameter path requires exact 7-byte message |
| `0x0201e622` | `42f0141a` | single-parameter writer targets current snapshot base +0x1a14 |
| `0x0201e630` | `0017` | single-parameter index is truncated to 8 bits |
| `0x0201e634` | `d8ee0112` | single-parameter writer stores msg[5] to current snapshot index |
| `0x0201e236` | `bfea6434` | stock packer writes selected packed 0x80 record through 0x02004b02 |
| `0x02026da6` | `beeaacee` | stock SAVE writes selected raw 0xa3 record through 0x02004b02 |
| `0x02026dac` | `bfeac7b9` | stock SAVE calls stock packer after raw write |
| `0x02026dd0` | `beea97ee` | stock SAVE flushes flag table through 0x02004b02 |

## Record mapping for S1C7 prefixes

Bank D preset 1 maps to record `96`, storage `0x7d20`, physical `0x0fbd20`.
Bank D preset 16 maps to record `111`, storage `0x86ad`, physical `0x0fc6ad`.

| Slot | Bank/Preset | Record | Raw storage rel | Physical prefix range | Packed rel side effect |
|---:|---|---:|---:|---|---:|
| 0 | D 1 | 96 | `0x7d20` | `0x0fbd20..0x0fbdbb` | `0x3000` |
| 1 | D 2 | 97 | `0x7dc3` | `0x0fbdc3..0x0fbe5e` | `0x3080` |
| 2 | D 3 | 98 | `0x7e66` | `0x0fbe66..0x0fbf01` | `0x3100` |
| 3 | D 4 | 99 | `0x7f09` | `0x0fbf09..0x0fbfa4` | `0x3180` |
| 4 | D 5 | 100 | `0x7fac` | `0x0fbfac..0x0fc047` | `0x3200` |
| 5 | D 6 | 101 | `0x804f` | `0x0fc04f..0x0fc0ea` | `0x3280` |
| 6 | D 7 | 102 | `0x80f2` | `0x0fc0f2..0x0fc18d` | `0x3300` |
| 7 | D 8 | 103 | `0x8195` | `0x0fc195..0x0fc230` | `0x3380` |
| 8 | D 9 | 104 | `0x8238` | `0x0fc238..0x0fc2d3` | `0x3400` |
| 9 | D 10 | 105 | `0x82db` | `0x0fc2db..0x0fc376` | `0x3480` |
| 10 | D 11 | 106 | `0x837e` | `0x0fc37e..0x0fc419` | `0x3500` |
| 11 | D 12 | 107 | `0x8421` | `0x0fc421..0x0fc4bc` | `0x3580` |
| 12 | D 13 | 108 | `0x84c4` | `0x0fc4c4..0x0fc55f` | `0x3600` |
| 13 | D 14 | 109 | `0x8567` | `0x0fc567..0x0fc602` | `0x3680` |
| 14 | D 15 | 110 | `0x860a` | `0x0fc60a..0x0fc6a5` | `0x3700` |
| 15 | D 16 | 111 | `0x86ad` | `0x0fc6ad..0x0fc748` | `0x3780` |

## Blockers to a safe host sender

- No exact v15 host command or SysEx path is proven to set or read back g+0x3a4/g+0x3a0 selected Bank D slot; selection is stock UI state.
- No exact v15 host command is proven to invoke stock SAVE or confirm its storage writes; SAVE is a UI handler path.
- Stock SAVE ignores both 0x02004b02 returns, so the normal UI/SAVED path is not a guarded write/readback protocol.
- No normal-firmware readback path is proven for raw prefixes 96..111 after SAVE; existing readback validators require external dump artifacts.
- Therefore a deterministic unattended host sender would risk writing the wrong selected slot or reporting success after a failed/partial SAVE.

## Reproduce

```sh
python3 baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed/analyze_official_ui_save_prefix_seed.py --check
python3 baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed/validate.py
(cd baselines/v15/analysis/persistence-s2/official-ui-save-prefix-seed && shasum -a 256 -c SHA256SUMS)
```
