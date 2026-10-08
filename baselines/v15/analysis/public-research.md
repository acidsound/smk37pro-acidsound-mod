# Public research baseline: Jieli AC791N / AC79, PI32v2, USB MIDI, synthesis, and reversing tools

Research date: 2026-08-01 UTC

## Scope and evidence policy

This note records public-source research and clean v15 repository observations only. It does not modify firmware, derive addresses from an older firmware version, or import older-version function, data, ABI, or layout assumptions.

Evidence classes used here:

- **Vendor primary**: Jieli's official AC79 documentation, official Gitee SDK, and official tool index.
- **Standards primary**: USB-IF MIDI device-class specification.
- **Public implementation**: public source or binary metadata in a released SDK.
- **Community reverse-engineering**: public Ghidra modules and Jieli utilities. These are useful but are not official architecture specifications.
- **Repository v15 observation**: files under `baselines/v15/` only.

Confidence labels:

- **High**: directly stated or implemented in a primary source, or independently corroborated.
- **Medium**: supported by a credible public implementation but not by an official specification.
- **Low**: a lead that still needs independent confirmation.

## Executive conclusions

1. **AC791N/WL82 SDK code is built for `pi32v2`, CPU revision `r3`.** The official AC79 build uses `-target pi32v2 -mcpu=r3`; official headers declare a little-endian, dual-core target. **Confidence: High.**
2. **The public link map is explicit but is a virtual/link-time map, not automatically the SMK-37 Pro physical flash map.** Current public SDK layouts place SFC/XIP code at `0x02000120`, internal RAM near `0x01c00000`, optional SDRAM code/data at `0x04000120`, core SFRs at `0x01ee0000`, and cache RAM near `0x01f20000`. **Confidence: High for the SDK; no direct equivalence asserted for v15.**
3. **The best public ABI model says arguments use `r0` through `r3`, then the stack; scalar return uses `r0`; 64-bit return uses `r0:r1`; `sp` grows downward; `rets` holds the subroutine return address.** This comes from a community Ghidra compiler specification reused for pi32v2, not an official ABI manual. **Confidence: Medium.**
4. **The current public AC79 SDK contains a real-time MIDI controller and a prebuilt MIDI synthesis library, but no published USB-MIDI class source.** MIDI synthesis and USB device classes are separate subsystems in the public tree. **Confidence: High for the inspected official branch.**
5. **The v15 device enumerates a standards-shaped USB MIDIStreaming interface with two 64-byte bulk endpoints.** USB-IF specifies Audio class / MIDIStreaming subclass and bulk endpoint transport. **Confidence: High.**
6. **Public engine evidence points to sample/wavetable synthesis, not classic operator-based FM synthesis.** The AC79 MIDI library contains `midi_synth.o`, tone-file readers, sample maps, loop points, ADPCM decoding, envelopes, filtering, pan, and PCM generation. No public evidence found proves a multi-operator FM engine. **Confidence: High for sample-based synthesis; Low for any global claim that no FM engine exists elsewhere.**
7. **In AC79 public documentation, “FM” means an external FM radio receiver module**, such as QN8035, BK1080, or RDA5807, not frequency-modulation sound synthesis. **Confidence: High.**
8. **Useful public reversing tools exist, but all have important limits.** Quarkslab's Ghidra module is the strongest pi32v2 disassembler lead; `jl-misctools` can parse newer AC7xxx/UFW firmware but documents incompleteness; `jl-uboot-tool` lists AC791N/WL82 support as unknown. **Confidence: High.**

## Public source snapshot

| Source | Revision / date inspected | Role |
|---|---:|---|
| [Official Jieli AC79 SDK on Gitee](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK) | branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` | Primary SDK source, headers, linker scripts, libraries |
| [Official AC79 documentation](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/index.html) | site last updated 2023-05-25; individual pages vary | Primary platform documentation |
| [Official Jieli tool index](http://pkgman.jieliapp.com/doc/all) | table updated 2026-07-31 | Toolchain and post-build tool inventory |
| [USB Device Class Definition for MIDI Devices 1.0](https://www.usb.org/sites/default/files/midi10.pdf) | 1999-11-01 | USB MIDI descriptor and transport standard |
| [Quarkslab `ghidra-jieli`](https://github.com/quarkslab/ghidra-jieli) | `e1bd0707874b77b759401555d24839ad43af1267` | Improved community pi32v2 processor module |
| [Kagaimiq `ghidra-jieli`](https://github.com/kagaimiq/ghidra-jieli) | `b5e60122b6cd3e6b615387035994b8bed0ea1a26` | Original public ABI/compiler model and processor module |
| [Kagaimiq `jielie`](https://github.com/kagaimiq/jielie) | `1657d25e6e51df6b2c18cd55cfc576c4a6370c63` | Community chip/core notes |
| [Kagaimiq `jl-misctools`](https://github.com/kagaimiq/jl-misctools) | `0a5b12db0ef38f3042acffbe2452730a37fd2405` | Firmware/container utilities |
| [Kagaimiq `jl-uboot-tool`](https://github.com/kagaimiq/jl-uboot-tool) | `adb3f18889e88ac512ce0a3c4d8cc3d3cb30696a` | Public loader-mode dumper/flasher |

## 1. AC791N / AC79 identity and architecture

### 1.1 Vendor description

The official AC79 documentation describes AC79 as a Wi-Fi/Bluetooth multimedia SoC family with a dual-core floating-point DSP up to 320 MHz, I-cache, D-cache, MMU, 578 KiB on-chip SRAM, and optional 2/8 MiB SDRAM packages.

- Source: [official AC79 documentation index](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/index.html)
- Source: [official SDK README](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/README.md)
- Exact claim supported: AC79 is a dual-core DSP platform with floating-point/DSP acceleration, caches, MMU, substantial on-chip SRAM, and optional SDRAM.
- Confidence: **High**.

The public community chip index maps `AC791N` to the internal family name `WL82`.

- Source: [`jielie/chips/index.md`](https://github.com/kagaimiq/jielie/blob/1657d25e6e51df6b2c18cd55cfc576c4a6370c63/chips/index.md)
- Exact claim supported: `AC791N (WL82)`.
- Confidence: **Medium-High**. This is community-maintained, but the official SDK consistently uses `cpu/wl82` for AC791N projects.

### 1.2 Official compiler target

The current official AC79 Makefile selects:

```text
TOOL_DIR := /opt/jieli/pi32v2/bin
-target pi32v2
-mcpu=r3
-D__GCC_PI32V2__
```

- Source: [`apps/demo/demo_audio/board/wl82/Makefile`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/demo/demo_audio/board/wl82/Makefile), especially lines 36, 72-74, and 105 at the inspected revision.
- Exact claim supported: public AC791N/WL82 SDK objects are compiled for Jieli `pi32v2`, CPU revision `r3`.
- Confidence: **High**.

The same Makefile enables pi32v2-specific linker optimizations including SIMD, repeat-memory operations, and “large program” handling.

- Exact source flags: `-pi32v2-enable-simd=true`, `-pi32v2-enable-rep-memop`, `-pi32v2-large-program=true`.
- Confidence: **High** that the toolchain supports these features; these flags do not prove every firmware function uses them.

### 1.3 Endianness, cores, registers, and instruction width

Official WL82 `cpu.h` declares:

```text
CPU_ENDIAN = LITTLE_ENDIAN
CPU_CORE_NUM = 2
```

- Source: [`include_lib/driver/cpu/wl82/asm/cpu.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/driver/cpu/wl82/asm/cpu.h)
- Exact claim supported: WL82 is little-endian and exposes two CPU cores to the SDK.
- Confidence: **High**.

The public pi32v2 processor descriptions model:

- sixteen 32-bit GPRs, `r0` through `r15`;
- paired 64-bit registers such as `r0_r1`, `r2_r3`, etc.;
- separate special registers `reti`, `rete`, `retx`, `rets`, `psr`, `cnum`, `icfg`, `usp`, `ssp`, `sp`, and `pc`;
- little-endian 16-bit base instruction words, with 32-bit and 48-bit encodings also present;
- repeat blocks, conditional instruction blocks, saturated/SIMD-like operations, and parallel execution forms.

Sources:

- [`jielie/cpu/pi32v2.md`](https://github.com/kagaimiq/jielie/blob/1657d25e6e51df6b2c18cd55cfc576c4a6370c63/cpu/pi32v2.md)
- [Quarkslab `pi32v2.slaspec`](https://github.com/quarkslab/ghidra-jieli/blob/e1bd0707874b77b759401555d24839ad43af1267/data/languages/pi32v2.slaspec)
- Official [`include_lib/driver/cpu/wl82/asm/csfr.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/driver/cpu/wl82/asm/csfr.h), which calls the core `q32DSP` in comments and register structure names.

Confidence:

- **High** for little-endian, register names visible in official headers, and the official compiler target.
- **Medium** for complete instruction semantics, because the public reverse-engineering modules explicitly retain unknown or incomplete instructions.

## 2. PI32 / PI32v2 ABI evidence

### 2.1 Public compiler model

The original public Ghidra processor module supplies a compiler specification that is also assigned to the pi32v2 language in `JieLi.ldefs`.

The model declares:

| ABI property | Public model |
|---|---|
| Pointer size | 4 bytes |
| `short` | 2 bytes |
| `int` | 4 bytes |
| `long` | 4 bytes |
| `long long` | 8 bytes |
| Stack | `sp`, negative growth |
| Function-pointer alignment | 2 bytes |
| Subroutine return address | `rets` |
| First four scalar arguments | `r0`, `r1`, `r2`, `r3` |
| Additional arguments | stack, 4-byte aligned |
| Scalar return up to 4 bytes | `r0` |
| 5-8 byte return | joined `r0:r1` |

Sources:

- [`data/languages/pi32.cspec`](https://github.com/kagaimiq/ghidra-jieli/blob/b5e60122b6cd3e6b615387035994b8bed0ea1a26/data/languages/pi32.cspec)
- [`data/languages/JieLi.ldefs`](https://github.com/kagaimiq/ghidra-jieli/blob/b5e60122b6cd3e6b615387035994b8bed0ea1a26/data/languages/JieLi.ldefs)

Exact claim supported: this is the calling convention modeled by a widely used public Ghidra plugin, and that plugin applies the model to pi32v2.

Confidence: **Medium**.

### 2.2 Why the ABI is not yet a v15 proof

No official public AC79 ABI manual was found. The Ghidra model is community-authored, and both the original and improved processor modules warn that instruction coverage remains incomplete. The official SDK confirms the target architecture and C type widths used in headers, but it does not publish a prose calling-convention specification.

Therefore:

- Use `r0-r3`, stack spill, `r0` return, and `rets` as a **high-value analysis hypothesis**.
- Do not label v15 functions solely from this convention.
- Validate each v15 function boundary and signature from its own callers, callees, prologue/epilogue, register lifetimes, and stack accesses, as required by `baselines/v15/analysis/README.md`.

Gap: callee-saved versus caller-saved register sets are not explicitly stated in the public `pi32.cspec`. They must be established empirically or from an official compiler document if one becomes public.

## 3. Public AC791N/WL82 memory map

### 3.1 SDK link regions

The current official WL82 linker scripts define the following regions.

#### SFC/XIP build (`sdk_ld_sfc.c`)

| Region | Public expression / origin | Meaning |
|---|---:|---|
| `rom` | `0x02000120`, length `__FLASH_SIZE__` | SFC/XIP code and read-only data link address |
| `ram0` | `0x01c00000 + TLB_SIZE` | On-chip RAM after optional TLB reservation |
| `boot_info` | immediately after `ram0` | 52-byte boot-info region in current branch |
| `cache_ram` | `0x01f20000 + ((8-FREE_IACHE_WAY)*4K)` | Configurable cache-way RAM window |
| `sdram` | `0x04000120`, length `SDRAM_SIZE` | Declared even in the SFC layout for applicable sections/configurations |

The script computes:

```text
RAM0_SIZE = 0x01c7fe00 - 0x01c00000 - TLB_SIZE - BOOT_INFO_SIZE - 128
UPDATA_BEG = 0x01c7fe00 - 128
```

With MMU enabled, SFC layout uses `TLB_SIZE = 0x1000 * 2`; otherwise `TLB_SIZE = 0`.

- Source: [`cpu/wl82/sdk_ld_sfc.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/sdk_ld_sfc.c)
- Confidence: **High** for this public SDK layout.

#### SDRAM-execution build (`sdk_ld_sdram.c`)

The SDRAM layout uses the same `rom`, `ram0`, `boot_info`, and cache concepts, but places the SDRAM execution region at `0x04000120`. With MMU enabled it reserves `0x2000 * 2` for TLBs.

- Source: [`cpu/wl82/sdk_ld_sdram.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/sdk_ld_sdram.c)
- Confidence: **High**.

The official configuration generator selects matching entry addresses:

```text
ENTRY=0x02000120  # SFC mode
ENTRY=0x04000120  # SDRAM mode
CHIP_NAME=AC791N
```

- Source: [`cpu/wl82/tools/isd_config_rule.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/tools/isd_config_rule.c), lines 82-86 at the inspected revision.
- Confidence: **High**.

### 3.2 Memory-mapped register windows

The official WL82 register header defines these base windows:

```text
lsfr_base = 0x00010000  # low-speed bus
bsfr_base = 0x00020000  # Bluetooth / wireless
hsfr_base = 0x00040000  # high-speed bus
psfr_base = 0x00050000  # ports
map_adr(grp, adr) = ((64 * grp + adr) * 4)
```

The same header maps, among many others:

- USB controller at `lsfr_base + map_adr(0x18, 0x00)`;
- second USB controller at `lsfr_base + map_adr(0x27, 0x00)`;
- audio block at `lsfr_base + map_adr(0x2f, 0x00)`;
- ADC at `lsfr_base + map_adr(0x31, 0x00)`;
- EQ at `lsfr_base + map_adr(0xe0, 0x00)`;
- SFC at `hsfr_base + map_adr(0x02, 0x00)`;
- SFC encryption at `hsfr_base + map_adr(0x03, 0x00)`.

- Source: [`include_lib/driver/cpu/wl82/asm/WL82.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/driver/cpu/wl82/asm/WL82.h)
- Confidence: **High**.

Core SFRs use:

```text
csfr_base = 0x01ee0000
```

- Source: [`include_lib/driver/cpu/wl82/asm/csfr.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/driver/cpu/wl82/asm/csfr.h)
- Confidence: **High**.

### 3.3 Important boundary: SDK virtual map versus v15 package offsets

The public SDK addresses above are linker/runtime addresses. They are not, by themselves, proof of file offsets in the SMK-37 Pro v15 image.

Clean v15 repository evidence records:

- `app_area_start = 16384` (`0x4000`)
- `app_data_start = 16672` (`0x4120`)
- `app_data_size = 617012`

Source: `baselines/v15/official/package-manifest.json`, lines 6-12.

No equivalence is asserted between `0x02000120` and any v15 file offset. Establishing that mapping requires v15-internal startup, loader, or cross-reference evidence.

## 4. USB MIDI implementation evidence

### 4.1 What the v15 device exposes

The clean v15 USB probe records five interfaces. Interface 4 is:

```text
class 0x01, subclass 0x03
endpoint 0x84 IN  bulk, max packet 64
endpoint 0x04 OUT bulk, max packet 64
```

Source: `baselines/v15/device-info/probe.txt`, lines 11-22.

The USB-IF MIDI 1.0 specification states:

- USB MIDI functionality is a `MIDIStreaming` subclass of the Audio Interface Class.
- A standard MIDIStreaming interface uses `bInterfaceClass = 0x01` and `bInterfaceSubClass = 0x03`.
- MIDI endpoints use bulk transfers.
- MIDI data is carried in fixed 32-bit USB-MIDI Event Packets. Byte 0 contains a 4-bit cable number and 4-bit Code Index Number; the remaining three bytes hold the MIDI event.

- Source: [USB MIDI 1.0 specification](https://www.usb.org/sites/default/files/midi10.pdf), sections 3.2.1, 4, 6.1.1, and 6.2.1; informative descriptor example B.4.1 explicitly gives class `0x01`, subclass `0x03`.
- Confidence: **High**.

Exact conclusion: the clean v15 descriptor shape matches USB MIDI 1.0 MIDIStreaming transport at the interface and endpoint level.

### 4.2 What the public AC79 SDK publishes

The current official AC79 USB device composition function publishes registration paths for:

- mass storage;
- USB Audio Class speaker/microphone/audio;
- custom HID and HID;
- CDC;
- UVC;
- printer.

Each class follows a pattern of adding a descriptor callback with `usb_add_desc_config(...)` and calling a class-specific registration function.

- Source: [`apps/common/usb/device/usb_device.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/usb/device/usb_device.c), especially the `usb_device_mode()` class-registration blocks.
- Confidence: **High**.

The official demo-audio Makefile includes USB sources for CDC, descriptors, HID, MSD, printer, UAC/UAC2, UVC, and common USB setup. It separately includes the MIDI controller wrapper and `lib_midi_dec.a`.

- Source: [`apps/demo/demo_audio/board/wl82/Makefile`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/demo/demo_audio/board/wl82/Makefile), USB source list around lines 221-235, MIDI wrapper around line 189, MIDI library around line 382.
- The inspected official tree contains no path whose name combines USB and MIDI, and no `midi.c` under `apps/common/usb/device/`.
- Confidence: **High for the inspected branch/revision**, not a claim about private Jieli SDKs or all historical branches.

### 4.3 Most defensible implementation clue

A non-public or product-specific USB MIDI module would plausibly need to fit the public SDK's class pattern:

1. provide MIDIStreaming descriptors;
2. call `usb_add_desc_config(...)` with a descriptor-builder callback;
3. register two bulk endpoints and their handlers;
4. decode/encode 4-byte USB-MIDI Event Packets;
5. translate Note On, Note Off, Program Change, Control Change, and Pitch Bend into the separate MIDI controller API.

Only steps 1-4 are required by the USB standard; step 5 is an integration hypothesis based on the public AC79 MIDI API. This is a search model, not proof of the v15 implementation.

### 4.4 USB MIDI gaps

- No public AC79 USB-MIDI descriptor source or endpoint-handler source was found.
- No public symbol names establish how the product routes USB cable numbers to internal MIDI channels.
- The v15 probe proves descriptors and endpoints, not the internal callback, queue, or synth bridge.
- Descriptor extraction from the clean v15 device or image remains necessary to enumerate embedded jack IDs, cable count, and class-specific endpoint descriptors.

## 5. Audio, MIDI, and FM-synthesis clues

### 5.1 Public AC79 real-time MIDI control API

The current official AC79 branch contains:

- `apps/common/audio_music/midi/audio_dec_midi_ctrl.c`
- `include_lib/media/MIDI_CTRL_API.h`
- `include_lib/media/MIDI_DEC_API.h`
- `cpu/wl82/liba/lib_midi_dec.a`

The wrapper exposes or invokes:

- program selection;
- Note On and Note Off;
- pitch bend;
- velocity vibrato;
- active-key query;
- up to 16 MIDI channels in the public structures;
- configurable sample rates from 8 kHz through 48 kHz;
- 16- or 24-bit PCM and configurable output channel count;
- a tone database named `MIDI.mdb` loaded from storage or mapped flash;
- a default `MIDI_KEY_NUM` of 10, documented as configurable from 1 to 18 with a clock/performance tradeoff.

Sources:

- [`audio_dec_midi_ctrl.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/audio_music/midi/audio_dec_midi_ctrl.c)
- [`MIDI_CTRL_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/media/MIDI_CTRL_API.h)
- [`MIDI_DEC_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/media/MIDI_DEC_API.h)

Confidence: **High**.

### 5.2 Public binary-library evidence

The public archive inspected from official commit `e30b1ee...` has:

```text
SHA-256 3f4a38dbec69eb2f85c56838eaa461252c8ee0e419211d06aebf46ce9bc62f03
size 84628 bytes
archive members include midi_fread_tone.o, midi_synth.o, midi_tabs.o
```

Public symbols include:

```text
midi_fread
midi_fread_addr
midi_fread_zone
Midi_IIR_Init
midi_ctrl_gen_sample
midi_dec_gen_sample
```

Debug strings preserved in the archive include source and structure names such as:

```text
midi_synth_bluetooth.c
WaveInfo_t
sampleMap
tableStart
tableEnd
loopStart
loopLen
loopEnd
Voice_t
indexIncr
wavebuf
ADPCM decoder names
ENV / ADSR-related fields
panLft / panRgt
lowpass fields
```

- Source archive: [`cpu/wl82/liba/lib_midi_dec.a`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/liba/lib_midi_dec.a)
- Inspection method: standard `ar`, `nm`, and printable-string extraction on the public archive only.

Exact conclusion: the engine reads tone/sample data, manages wave tables and loop points, performs per-voice sample stepping, supports ADPCM-related decoding, envelopes, filtering, pan, and PCM sample generation. This is strong evidence of a sample/wavetable MIDI synthesizer.

Confidence: **High**.

### 5.3 No strong public evidence for classic FM synthesis

No inspected public AC79 MIDI header, wrapper, archive member, symbol, or debug string identified:

- operator algorithms;
- carrier/modulator operator banks;
- feedback operators;
- FM ratio/detune parameter sets;
- OPL/YM-style channel/operator structures.

This absence does not prove no private or product-specific FM engine exists. It does mean that the public engine should not be described as FM synthesis without additional evidence.

Confidence:

- **High** that the inspected public engine is sample/wavetable-oriented.
- **Low** for any universal negative statement beyond the inspected sources.

### 5.4 “FM” in the public AC79 docs is FM radio

The official AC79 FM page says the feature requires an external FM module and gives QN8035, BK1080, and RDA5807 configuration examples. It routes the module's analog audio back through a line-in ADC channel.

- Source: [official AC79 “FM radio” page](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/fm.html)
- Exact claim supported: this module is broadcast-FM reception, not an FM sound-synthesis engine.
- Confidence: **High**.

### 5.5 Public PCM integration surfaces

The AC79 audio decoder API documents:

- decoded PCM callbacks;
- selectable output sources such as DAC/IIS;
- virtual decoder output through a circular buffer;
- standard audio-server open/start/pause/stop requests.

Sources:

- [official audio decoder documentation](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/dec.html)
- [official virtual-output documentation](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/virtual_dac.html)
- [`include_lib/server/audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/server/audio_server.h)

Exact clue: an independent software synthesizer can conceptually produce PCM into the public audio pipeline, but these APIs do not prove that the stock product does so or reveal its mixer object layout.

Confidence: **High for the API; Low for product-specific integration details.**

## 6. Public firmware reversing and inspection tools

### 6.1 Quarkslab `ghidra-jieli`

- URL: [https://github.com/quarkslab/ghidra-jieli](https://github.com/quarkslab/ghidra-jieli)
- Revision: `e1bd0707874b77b759401555d24839ad43af1267`
- License: Apache-2.0.
- Public claim: an improved Ghidra processor module derived from the earlier implementation; pi32v2 “covers most instructions,” while some remain unknown.
- Useful for: pi32v2 disassembly, p-code generation, conditional blocks, repeat blocks, stack operations, and many parallelized instructions.
- Limitation: it is not complete, and its compiler model is not an official ABI specification.
- Confidence: **High** that it is currently the strongest public pi32v2 Ghidra lead found.

### 6.2 Kagaimiq `ghidra-jieli`

- URL: [https://github.com/kagaimiq/ghidra-jieli](https://github.com/kagaimiq/ghidra-jieli)
- Revision: `b5e60122b6cd3e6b615387035994b8bed0ea1a26`
- License: Apache-2.0.
- Useful for: the original public pi32/pi32v2/q32s SLEIGH work and explicit `pi32.cspec` ABI model.
- Limitation stated by the project: pi32v2 was at a very early stage in this revision; stack, flag, repeat, and parallel-execution semantics were incomplete.
- Confidence: **High** for what the files model; **Medium** for correctness of every modeled instruction or ABI rule.

### 6.3 `jl-misctools`

- URL: [https://github.com/kagaimiq/jl-misctools](https://github.com/kagaimiq/jl-misctools)
- Revision: `0a5b12db0ef38f3042acffbe2452730a37fd2405`
- License: MIT.
- Relevant tools:
  - `firmware/fwunpack_newfw.py`: handles the “new” firmware format used by AC693N and newer / AC7xxx families and can accept UFW input;
  - `firmware/recrypt.py`: transforms SFC-encrypted regions between keys or decrypts/encrypts with a selected key;
  - `firmware/bruteforce.py`: SFCENC-key brute-force helper for supported older/newer structural checks;
  - key-file parsers and generators;
  - UI resource and older-format utilities.
- Project-stated limitation: `fwunpack_newfw.py` is “far from complete”; reserved areas and other structures are not fully handled.
- Exact conclusion: it is appropriate for non-destructive parsing and cross-checking, but its output cannot be assumed complete or repack-safe.
- Confidence: **High**.

### 6.4 `jl-uboot-tool`

- URL: [https://github.com/kagaimiq/jl-uboot-tool](https://github.com/kagaimiq/jl-uboot-tool)
- Revision: `adb3f18889e88ac512ce0a3c4d8cc3d3cb30696a`
- License: MIT.
- Public functions: loader-mode flash read, write, erase, dump, RAM payload execution, and device discovery.
- Critical public status: the support table lists `WL82 / AC791N` as **unknown**.
- Exact conclusion: the project is a useful protocol and loader reference, but it is not evidence that AC791N dumping or flashing is safe or working.
- Confidence: **High**.

### 6.5 Official Jieli tools

The official tool index publishes:

- Jieli Windows and Linux toolchains;
- `isd_download` / `isd_download.exe`;
- `fw_add`;
- `ufw_maker`;
- `fat_comm`;
- `packres`;
- `remove_tailing_zeros`;
- official firmware-related PC tools and programmer packages.

- Source: [official Jieli tool index](http://pkgman.jieliapp.com/doc/all)
- The Linux toolchain short URL resolved during research to `jieli-linux-toolchains-20250805.1.tar.xz`, about 26 MB, served from Jieli's update bucket.
- Exact conclusion: these are authoritative build/package tools and valuable format references, but they are not general-purpose reverse-engineering suites.
- Confidence: **High**.

## 7. Strong search seeds for independent v15 analysis

These are public-evidence-derived search seeds, not v15 identifications:

### Architecture and control flow

- pi32v2 `rts`, `rets`, `pop pc`, and push/pop register patterns;
- `r0-r3` argument hypothesis and `r0` return hypothesis;
- 2-byte instruction alignment;
- pi32v2 repeat and conditional-block decoding;
- memory-mapped SFR windows from `WL82.h`.

### MIDI engine

Public names and concepts worth searching for through strings, symbol recovery, or structural behavior:

- `MIDI.mdb`;
- `midi_ctrl_init` / uninit shape;
- Note On, Note Off, Program Change, Pitch Bend dispatch tables;
- sample-rate lookup table `{48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000}`;
- 16-channel state;
- polyphony limits near 10 or 18;
- tone-file read/seek callbacks;
- wave sample maps, loop start/end, ADPCM, envelope, pan, low-pass, and PCM generator paths.

### USB MIDI

- Audio interface class `0x01`, MIDIStreaming subclass `0x03`, protocol `0x00`;
- bulk IN/OUT endpoints with 64-byte full-speed packets;
- 4-byte USB-MIDI Event Packet parsing where `CIN 0x8` is Note Off, `0x9` Note On, `0xB` Control Change, `0xC` Program Change, and `0xE` Pitch Bend;
- descriptor-builder and class-registration patterns resembling `usb_add_desc_config` plus endpoint handler setup.

Each seed must still be proven from clean v15 internal evidence before naming or patching a function.

## 8. Remaining gaps

### Architecture / ABI

- No official PI32v2 ABI manual was located.
- Caller-saved and callee-saved register sets remain unproven.
- Structure-passing, variadic calls, floating-point argument passing, and large-structure returns remain unproven.
- Public Ghidra pi32v2 decoding still has unknown instructions.

### Memory map

- The public SDK map does not establish the exact v15 loader-to-XIP/file-offset translation.
- v15 section boundaries, relocation behavior, MMU/TLB configuration, and cache-way allocation need clean v15 evidence.
- Public SDK default flash and SDRAM sizes are build configuration, not SMK hardware proof.

### USB MIDI

- No public AC79 USB-MIDI source implementation was found.
- Embedded MIDI jack count, cable mapping, class-specific descriptor topology, and endpoint callback identities remain unknown for v15.
- The relationship between USB cable numbers and the internal synth's 16 channels remains unknown.

### Synthesis

- Public evidence supports sample/wavetable MIDI synthesis, not the exact product tone database or mixer topology.
- No strong evidence supports a classic multi-operator FM synth in the public AC79 engine.
- The v15 product could contain additional private synthesis code; that must be established independently.

### Tooling

- `jl-misctools` new-firmware parsing is incomplete.
- `jl-uboot-tool` AC791N/WL82 support is explicitly unknown.
- Community disassemblers need validation against official toolchain output or known SDK objects before relying on edge-case instruction semantics.

## 9. Reproducibility notes

Public repositories were cloned read-only under scratch storage with filtered/shallow clones. No firmware image was changed. The following checks were performed:

- recorded official and community repository revisions with `git ls-remote` / `git rev-parse`;
- enumerated official SDK paths with `git ls-tree`;
- inspected official linker scripts, register headers, Makefiles, USB class composition, MIDI wrapper/API headers, and public archive metadata;
- fingerprinted the public `lib_midi_dec.a` archive;
- inspected archive members, public symbols, and printable debug strings;
- compared the clean v15 USB probe to the USB-IF MIDI 1.0 descriptor and endpoint requirements;
- used no older firmware function addresses, code listings, data structures, or ABI assumptions as evidence.
