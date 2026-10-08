# PCM/WAV/sample playback and real-time synthesis feasibility for official v15

Date: 2026-08-02 UTC

## Scope and safety boundary

This note evaluates whether official SMK-37 Pro v15 can plausibly support PCM/WAV/sample playback, DAC/audio mixer use, decoder-task reuse, wavetable/sample synthesis, software real-time synthesis, or audio callback injection. It uses only:

- official v15 analysis artifacts already under `baselines/v15/analysis/`;
- SMK-37 Pro public photos and local derivative notes under `docs/`;
- public Jieli AC79/WL82 SDK source and public binary-library metadata;
- public AC79 documentation.

No firmware bytes were changed. Nothing was patched. Nothing was flashed.

Feasibility grades used below:

| Grade | Meaning |
|---|---|
| **A** | Public AC79 API/source directly supports the capability, and the v15 product has enough exact evidence to locate or safely use the relevant path. |
| **B** | Public AC79 API/source directly supports the capability, and v15 has related exact evidence, but product-specific address/ABI/hook identity is still missing. |
| **C** | Plausible from public AC79 API/source or hardware evidence, but v15 product integration is unresolved. Safe only as a static research direction. |
| **D** | Not currently actionable. Important product-specific evidence is absent, contradicted, or below threshold. |

Current bottom line: public AC79/WL82 clearly supports PCM/WAV decoding, decoded-PCM callbacks, virtual decoder output, DAC/IIS output selection, and a sample/wavetable MIDI engine. Official v15 clearly has USB MIDI descriptors and exact MIDI ingress parsing/handling. However, the public MIDI synth and audio-server ABI have not been assigned to v15 addresses, and no v15 DAC/mixer/audio callback injection point is proven. Therefore all product-modification conclusions stay at **B/C/D**, not A.

## Source and revision ledger

| Source | Exact revision / URL | Role |
|---|---|---|
| Official v15 app | `build/v15-official-app.bin`, SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`, size 617,012 bytes, runtime base `0x02000000` per `baselines/v15/analysis/evidence.md` and `sdk-signatures/report.json` | Product binary under analysis |
| v15 SDK-signature report | `baselines/v15/analysis/sdk-signatures/evidence.md`; machine report `baselines/v15/analysis/sdk-signatures/report.json` | Exact public-SDK-vs-v15 match and rejection record |
| v15 Quarkslab analysis | `baselines/v15/analysis/quarkslab/evidence-report.md`; Quarkslab `ghidra-jieli` commit [`e1bd0707874b77b759401555d24839ad43af1267`](https://github.com/quarkslab/ghidra-jieli/tree/e1bd0707874b77b759401555d24839ad43af1267) | Decoder coverage and limits |
| Public AC79 SDK | [`https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK), branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` | Primary SDK source/library evidence |
| Public AC79 docs | [`release_v1.0.3` docs](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/index.html), audio decoder page [`dec.html`](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/dec.html), virtual output page [`virtual_dac.html`](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/virtual_dac.html) | Primary API documentation |
| SMK-37 Pro docs photos | `jonathaslacerda/smk-37-pro-docs` HEAD `8f1bf1115cc8fe874bbac326d4f1f1513d743844`; board photo [`internals-board2.jpg`](https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/images/smk37pro/internals-board2.jpg), output photo [`internals-board3.jpg`](https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/images/smk37pro/internals-board3.jpg) | Product hardware evidence |
| Local derivative notes | `docs/research-notes.md`, especially `Main SoC identification` and `Existing output path` | SMK-specific synthesized evidence |

## CPU/RAM/hardware evidence

| Evidence | Exact URL/file/symbol | What it supports | Confidence |
|---|---|---|---|
| AC79 is documented as a Wi-Fi/Bluetooth multimedia SoC family with dual-core floating-point DSP up to 320 MHz, I-cache, D-cache, MMU, 578 KiB on-chip SRAM, and optional 2/8 MiB SDRAM packages. | Local summary: `baselines/v15/analysis/public-research.md` lines 50-57. Primary URLs: [AC79 docs index](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/index.html), SDK README at commit [`e30b1ee.../README.md`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/README.md). | CPU headroom for audio decode/synthesis exists at platform level. | High for public AC79, not SMK-specific scheduling headroom. |
| Public WL82 SDK is little-endian and exposes two CPU cores. | [`include_lib/driver/cpu/wl82/asm/cpu.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/driver/cpu/wl82/asm/cpu.h), symbols `CPU_ENDIAN`, `CPU_CORE_NUM`; summarized in `public-research.md` lines 87-96. | Matches v15 `pi32v2:LE:32:default` analysis assumptions. | High for SDK. |
| Public WL82 demo-audio build targets `pi32v2`, CPU `r3`. | [`apps/demo/demo_audio/board/wl82/Makefile`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/demo/demo_audio/board/wl82/Makefile), symbols/flags `-target pi32v2`, `-mcpu=r3`; summarized in `public-research.md` lines 65-83. | Public archive objects are the correct architecture family for v15 matching. | High. |
| SMK main SoC is very likely AC7911B8-family Jieli device. | Public photo [`internals-board2.jpg`](https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/images/smk37pro/internals-board2.jpg); local derivative `docs/research-notes.md` lines 120-139. | Product likely belongs to AC791N/WL82 family. | High inference, not absolute part-mark cross-reference. |
| SMK output path likely uses external Cirrus CS4344 stereo DAC, not only an internal DAC pin. | Public photo [`internals-board3.jpg`](https://github.com/jonathaslacerda/smk-37-pro-docs/blob/8f1bf1115cc8fe874bbac326d4f1f1513d743844/images/smk37pro/internals-board3.jpg); local derivative `docs/research-notes.md` lines 145-164; CS4344 datasheet URL recorded there. | A software PCM path must ultimately feed the product's digital audio output/IIS-style path to CS4344, not assume analog internal-DAC pins are used. | High inference. |
| Exact v15 app size/base are known. | `baselines/v15/analysis/evidence.md` lines 12-18 and 20-31; `sdk-signatures/report.json` `inputs.app`. | Static address work can distinguish file offset, package offset, and runtime VA. | High. |

Product-specific unknowns for CPU/RAM/hardware:

- Exact free heap, stack margins, decoder work buffers, audio IRQ budget, and active audio task priorities in stock v15 are unknown.
- Whether the SMK board has external SDRAM populated is not proven by current product evidence.
- Public AC79 CPU/RAM capacity does not prove headroom for an additional real-time synth inside the product's existing UI/MIDI/audio workload.
- The public SDK `sample_source = "dac"` abstraction may map to the AC79 audio endpoint and then to IIS/CS4344 on SMK. The exact product route and register setup are not identified.

## Format and library evidence

| Capability | Exact URL/file/symbol | Evidence | Confidence |
|---|---|---|---|
| WAV and PCM decoder support in public AC79 audio server | Public SDK commit `e30b1ee...`, archive [`cpu/wl82/liba/audio_server.a`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/cpu/wl82/liba/audio_server.a); archive members `pcm_decoder.c.o`, `wav_decoder.c.o`, `wav_package.c.o`, symbols `pcm_decoder_ops`, `wav_decoder`, `wav_bitdepth_callback`, `pcm_package_ops`, `wav_package_ops`. Local extraction command: `ar t`/`nm -g` in scratch. | Public SDK includes PCM/WAV decode/package wrappers in `audio_server.a`. | High for public SDK. |
| Many file decode types are API-supported | AC79 decoder docs [`dec.html`](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/dec.html), section `3.11 dec_type`; SDK header [`include_lib/server/audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L257-L287), field `const char *dec_type`. | `wav`, `pcm`, `adpcm`, `mp3`, `flac`, etc. are accepted decode types in the documented/public audio server model. | High for public SDK/API. |
| MIDI sample/tone database format path | [`apps/common/audio_music/midi/audio_dec_midi_ctrl.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/common/audio_music/midi/audio_dec_midi_ctrl.c#L41-L48), symbol/macro `MIDI_FILE_PATH`, `MIDI.mdb`; lines 52-79 `midi_get_cfg_addr`; lines 88-116 `midi_fread_api`, `midi_fseek`. | Public MIDI engine expects a tone/sample database, either from storage or mapped flash. | High for public SDK. |
| MIDI output format parameters | [`include_lib/media/MIDI_DEC_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/media/MIDI_DEC_API.h#L10-L21), struct `MIDI_CONFIG_PARM`; [`audio_dec_midi_ctrl.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/common/audio_music/midi/audio_dec_midi_ctrl.c#L126-L153). | Sample-rate index table `{48000,44100,32000,24000,22050,16000,12000,11025,8000}`, 16/24-bit config, stereo output, `player_t` polyphony. | High for public SDK. |
| Public MIDI synth is sample/wavetable-oriented | Public archive [`cpu/wl82/liba/lib_midi_dec.a`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/cpu/wl82/liba/lib_midi_dec.a), SHA-256 `3f4a38dbec69eb2f85c56838eaa461252c8ee0e419211d06aebf46ce9bc62f03`; members `midi_fread_tone.o`, `midi_synth.o`, `midi_tabs.o`; symbols `midi_fread`, `midi_fread_addr`, `midi_fread_zone`, `Midi_IIR_Init`, `SetKeyDecay`, `midi_ctrl_gen_sample`, `midi_dec_gen_sample`; strings `WaveInfo_t`, `sampleMap`, `tableStart`, `tableEnd`, `loopStart`, `loopLen`, `Voice_t`, `indexIncr`, `wavebuf`, `adpcm_decoder_unit`, `ENV`, `panLft`, `panRgt`, low-pass fields. | The public MIDI engine reads tone/sample maps, loops waveform data, applies envelopes/filter/pan, and emits PCM. | High for public SDK. |
| Public demo-audio links both audio server and MIDI library | [`apps/demo/demo_audio/board/wl82/Makefile`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/demo/demo_audio/board/wl82/Makefile#L189-L190), `audio_dec_midi_ctrl.c`; lines 341 and 382 `audio_server.a`, `lib_midi_dec.a`; lines 355 and related decoder libs include `lib_wav_dec.a`. | Public demo path combines generic audio server with MIDI wrapper/library. | High for public SDK. |

Product-specific format unknowns:

- v15 does not currently have a defensible byte/relocation-aware match to the public `midi_synth.o`, `midi_dec.c.o`, `midi_play.c.o`, or MIDI tables. `baselines/v15/analysis/sdk-signatures/evidence.md` lines 144-160 records zero strict MIDI matches and zero accepted two-window candidates.
- `sdk-signatures/report.json` records `sdk_elf_exact.midi_named_matches: []`.
- `sdk-signatures/report.json` rejected the only exact public SDK sample-rate sequence in v15 because it is immediately followed by USB Audio Class descriptors, not a synth sample-rate table.
- No exact v15 `MIDI.mdb` path, tone-bank address, WAV file path, PCM raw sample table, or sample decoder task has been assigned.

## API and task-surface evidence

| Surface | Exact URL/file/symbol | Evidence | Confidence |
|---|---|---|---|
| Standard audio decoder task/service | AC79 decoder docs [`dec.html`](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/dec.html), usage flow `server_open("audio_server", "dec")`, `AUDIO_DEC_OPEN`, `AUDIO_DEC_START`; SDK header [`audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L56-L75). | Public API has a decoder server task model. | High for public SDK/API. |
| MIDI opens decoder service and selects DAC output | [`audio_dec_midi_ctrl.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/common/audio_music/midi/audio_dec_midi_ctrl.c#L342-L383), symbols `midi_ctrl_set_ioctl`, `midi_ctrl_dec_open`, `server_open("audio_server", "dec")`, `req.dec.dec_type = "midi"`, `req.dec.sample_source = "dac"`, `req.dec.output_buf_len = 6 * 1024`. | Public MIDI wrapper runs through audio server, not a private standalone ISR in this example. | High for public SDK. |
| Decoded PCM callback | [`include_lib/server/audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L285-L287), symbol `dec_callback`; AC79 decoder docs `struct audio_dec_req`. | Public decoder can call `int (*dec_callback)(u8 *buf, u32 len, u32 sample_rate, u8 ch_num)` after PCM decode. | High for public SDK/API. |
| Virtual decoder output | [`include_lib/server/audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L87-L96) `struct audio_cbuf_t`; `audio_dec_req.virtual_audio`; official [`virtual_dac.html`](https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/module_example/audio/virtual_dac.html). | Public decoder can emit PCM into a virtual circular buffer instead of directly playing through DAC. | High for public SDK/API. |
| Output selection to DAC/IIS | [`audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L279-L281), field `sample_source`, supports `"dac"`, `"iis0"`, `"iis1"`; docs `dec.html` section `3.12 sample_source`. | Public decoder can target internal DAC/IIS-style outputs. | High for public SDK/API. |
| Mixer/channel helper surface | [`include_lib/server/audio_dev.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_dev.h#L221-L233), symbols `dac_digital_lr_add`, `dac_digital_lr_sub`, `audio_channel_buf_data_merge`, `audio_channel_cbuf_data_merge`, `audio_subdevice_request`; archive strings in `audio_server.a` include `audio_mix_data_dec_callback`, `audio_mix_en`, `dac_digital_lr_add`, `dac_digital_lr_sub`. | Public SDK has explicit channel combine/separate helpers and mix callback names. | Medium-High for public SDK. Exact semantics require source or disassembly. |
| Audio effect callback surface | [`audio_server.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/server/audio_server.h#L358-L374), struct `audio_effect_ops`, `run(void *priv, s16 *data, int len, int sample_rate)`, `REGISTER_AUDIO_EFFECT`. | Public audio effects can process PCM frames in the decoder chain. | High for public SDK/API. |
| Real-time MIDI control API | [`MIDI_CTRL_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/media/MIDI_CTRL_API.h#L30-L42), struct `MIDI_CTRL_CONTEXT`; [`audio_dec_midi_ctrl.c`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/apps/common/audio_music/midi/audio_dec_midi_ctrl.c#L203-L245), symbols `midi_ctrl_set_porg`, `midi_ctrl_note_on`, `midi_ctrl_note_off`. | Public SDK offers program change, note on/off, pitch bend, velocity vibrato, query, glissando operations. | High for public SDK/API. |
| MIDI event/callback hooks | [`MIDI_DEC_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/media/MIDI_DEC_API.h#L67-L85), structs `MIDI_NOTE_ON`, `MIDI_NOTE_OFF`, `MIDI_ADSR`, `MIDI_CTRL_EVENT`; lines 181-185 commands `CMD_MIDI_NOTE_ON_TRIGGER`, `CMD_MIDI_NOTE_OFF_TRIGGER`, `CMD_MIDI_ADSR_TRIGGER`, `CMD_MIDI_CTRL_EVENT`; lines 207-227 `MIDI_INIT_STRUCT`. | Public MIDI decoder has hooks around note on/off, ADSR, and event protection. These are not audio-frame injection hooks but may alter MIDI/synth behavior. | High for public SDK/API. |
| Word-to-sound/sample mode | [`MIDI_DEC_API.h`](https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d/include_lib/media/MIDI_DEC_API.h#L157-L163), struct `MIDI_W2S_STRUCT`, fields `data_pos`, `data_len`, `rec_data`, `key_diff`; mode enum line 92 `CMD_MIDI_CTRL_MODE_W2S`. | Public MIDI engine has an external-source/sample mode that can map PCM-like recorded data to keys. | Medium-High for public SDK. Exact data format and product support need testing. |

Product-specific API unknowns:

- No v15 function address is proven for `server_open("audio_server", "dec")`, `audio_dec_req`, `dec_callback`, `virtual_audio`, `audio_effect_ops`, `dac_digital_lr_add/sub`, or an audio mixer callback.
- Public `audio_server.a` is a lineage-positive source, but the current v15 SDK-signature work focused on USB/calibration and selected MIDI members. It has not yet established exact v15 audio-server object identities beyond public-library presence.
- The stock v15 audio path may be a product/private synth engine rather than the public `lib_midi_dec.a` sample/wavetable engine.
- Injecting a callback through public structures requires knowing where v15 allocates/fills those structures and whether the callback pointer is actually used in the product build.

## Official v15 product evidence relevant to audio/synthesis

| Evidence | Exact file/symbol/address | Interpretation | Confidence |
|---|---|---|---|
| USB MIDI 1.0 descriptor set exists in v15. | `baselines/v15/analysis/evidence.md` lines 81-100: `midi_route\0` at VA `0x0205773b`, MIDIStreaming interface at `0x020579ae`, MIDI IN endpoint `0x02057fc6`, MIDI OUT endpoint `0x02057fd6`, coherent jack graph `0x02058274`. | Product accepts/advertises USB MIDI transport shape. | High for descriptor bytes. Runtime callback identity not proven. |
| Quarkslab decoder improved coverage but did not identify receive/dispatch entry. | `baselines/v15/analysis/quarkslab/evidence-report.md` lines 3-24 and 126-162. | Absence of audio/MIDI path identities is tool-limited, not proof of absence. | High. |
| Exact v15 MIDI ingress parser exists. | `sdk-signatures/evidence.md` lines 166-171; `report.json` raw region `raw_midi_stream_parser`, file offset `0x1050`, VA `0x02001050`, size 824, SHA-256 `d3ffb8bd02262c066e42d572fa5ae7c296fda9f2e2e3268905157e87e4b47ac2`. | Product decodes MIDI byte streams and running status/SysEx boundaries. | High for described parser. |
| Exact v15 product MIDI handler exists. | `sdk-signatures/evidence.md` lines 172-187; `report.json` raw region `product_midi_message_handler`, file offset `0x1e64a`, VA `0x0201e64a`, size 216, SHA-256 `25562e19c36d144159780b5987b4feb54d01a093ea026492d20ed5b0c563cbb9`. | Product handles selected MIDI statuses and maintains 16-slot pitch-bend/channel routing state. | High for ingress/handler behavior. Downstream synth target unresolved. |
| Independent caller to product MIDI handler exists. | `sdk-signatures/evidence.md` lines 178-182; `report.json` raw region `product_midi_handler_callsite`, file offset `0x2d1b4`, VA `0x0202d1b4`, size 64, SHA-256 `a26878bc608f094bc648bbfc5c86113978e3849284e7d6f8bd3b7ff8430a7c5c`. | Supports handler boundary and one-argument ingress ABI. | High. |
| Public SDK MIDI synth did not match v15. | `sdk-signatures/evidence.md` lines 144-160 and 202-210; `report.json` `sdk_elf_exact.midi_named_matches: []`. | Cannot name v15 Note On/Off, synth context, voice structure, or public sample synth by address. | High for negative matching result under current method. |
| Prior product patchability matrix does not include audio callback or PCM injection. | `baselines/v15/analysis/mod-capability-matrix.md` lines 27-40 and 60-72. | Existing static patch claims are about MIDI channel/voice-source changes, not generic PCM playback or callback injection. | High for current repo state. |
| M09 large-data cave incident warns against assuming app-space storage is safe. | `docs/research-notes.md` lines 628-697. | PCM/sample table insertion into apparently unused app space is unsafe without stronger evidence. | High process lesson. |

## Feasibility matrix

| Target capability | Public AC79 evidence | v15/SMK-specific evidence | Current grade | Rationale |
|---|---|---|---|---|
| PCM file playback through public decoder server | `audio_server.h` supports `dec_type`, `sample_source`, `dec_callback`; docs list `pcm`; `audio_server.a` has `pcm_decoder.c.o` and `pcm_decoder_ops`. | No exact v15 PCM decoder address or request structure identified. Product has audio output hardware and AC79 lineage. | **C** | Strong SDK support, but no product hook/ABI identity. |
| WAV file playback through public decoder server | Docs list `wav`; Makefile links `lib_wav_dec.a`; `audio_server.a` has `wav_decoder.c.o`, `wav_decoder`, `wav_bitdepth_callback`, `wav_package_ops`. | No v15 WAV decoder identity or file source path identified. | **C** | Same as PCM. Plausible but not actionable. |
| One-shot/sample playback by reusing public MIDI W2S or tone database | `MIDI_W2S_STRUCT`, `CMD_MIDI_CTRL_MODE_W2S`, `MIDI.mdb`, `midi_fread*`, sample-map strings in `midi_synth.o`. | v15 public MIDI synth match is rejected; product tone/sample DB not located. | **D/C** | Public engine supports sample concepts, but product engine identity is unresolved. |
| Public AC79 sample/wavetable synth reuse | `lib_midi_dec.a` has `midi_synth.o`, `midi_ctrl_gen_sample`, sample maps, loop points, ADPCM, envelopes, pan, low-pass. | `sdk-signatures` found zero defensible matches to public MIDI synth functions/tables in v15. | **D** for direct address reuse; **C** as search model | Public evidence is high, product identity is absent. |
| Existing product synth is reachable from MIDI ingress | v15 has exact MIDI parser/handler and 16-slot pitch bend state. | Downstream Note On/Off/synth function not identified; handler `0x90` path is product-specific and not a general Note On proof. | **B/C** | Ingress is real, but audio generation target is not. |
| Software real-time synth emitting PCM into audio server | Public platform has CPU/RAM headroom, decoder callback, virtual output, effect run callback, sample_source DAC/IIS. | No v15 audio server structure/hook address, free RAM, timing budget, or mixer insertion point. | **C** | Architecturally plausible in AC79, currently unsafe for SMK v15 modification. |
| DAC/audio mixer injection | `audio_dev.h` exposes `dac_digital_lr_add/sub`, channel merge helpers, `audio_subdevice_request`; `audio_server.a` strings include `audio_mix_data_dec_callback`, `audio_mix_en`. | SMK uses likely CS4344 external DAC, but the exact product digital route/mixer callback is not identified. | **C/D** | Need exact v15 call path before writing any hook. |
| Decoded-PCM observation callback | Public `audio_dec_req.dec_callback` gives decoded PCM callback. | No v15 `audio_dec_req` instance or decoder-open callsite identified. | **C** for observation in a public app; **D** for v15 injection now | Public API exists, product injection point absent. |
| Audio effect callback injection | Public `audio_effect_ops.run` can process `s16 *data` frames. | No v15 effect registry, enabled effect chain, or writable registration path identified. | **D** | Not actionable without registry/call-chain proof. |

## Product-specific unknowns kept separate

These are not solved by public AC79 SDK evidence:

1. **Exact stock synth type.** Public AC79 evidence supports sample/wavetable MIDI synthesis. Existing SMK-side mod notes discuss FM-style 156-byte voices and product-specific voice snapshots. Current v15 evidence does not prove that the product uses the public `lib_midi_dec.a` sample engine, a private FM engine, or a hybrid.
2. **Downstream Note On/Off addresses.** The exact v15 ingress parser and handler are known, but the general downstream note allocator/synth entry points are not.
3. **Audio-server object identity in v15.** No exact address is assigned for `audio_server`, `audio_dec_req`, `audio_effect_ops`, `audio_mix_data_dec_callback`, `dac_digital_lr_add/sub`, or decoder task queues.
4. **PCM frame format at the product output.** Public APIs use 16/24-bit PCM and `s16 *` effect frames, but the SMK path to CS4344 could include sample-rate conversion, channel mapping, EQ/DRC, mute/fade, or I2S-specific packing not yet traced.
5. **Memory budget.** Public AC79 SRAM capacity is known, but stock v15 heap/BSS usage, decoder workbuf allocation, audio output buffer occupancy, and spare cycle budget are unknown.
6. **Safe storage for samples.** M09 demonstrates that zero-filled or unreferenced app-space regions are not automatically safe data caves. Any PCM/sample insertion needs a proven resource section or external storage path.
7. **Runtime validation route.** The current task explicitly forbids patch/flash. All next steps below are static/read-only unless a future task authorizes a live experiment.

## Next non-destructive validations

1. **Extend SDK signature matching to audio-server objects.** Compile or otherwise normalize public `audio_server.a` bitcode members beyond the selected MIDI objects: `audio_server.c.o`, `pcm_decoder.c.o`, `wav_decoder.c.o`, `audio_dev.c.o`, `wav_package.c.o`, and channel/mix helpers. Require the same two-independent-match threshold used in `sdk-signatures/evidence.md`.
2. **Search v15 for audio request construction patterns.** Look for constants and field shapes from `midi_ctrl_dec_open`: `server_open("audio_server", "dec")`, `AUDIO_DEC_OPEN`, `AUDIO_DEC_START`, output buffer `6 * 1024`, `dec_type = "midi"`, `sample_source = "dac"`, and `sample_rate = 0`. Do not assign function names from similarity alone.
3. **Search v15 for `audio_dec_req.dec_callback` writes.** Find candidate structures where a function pointer is stored at the `dec_callback` slot relative to nearby `dec_type`, `sample_source`, `virtual_audio`, `output_buf_len`, and `sample_rate` fields. Accept only if cross-referenced to a decoder-open request path.
4. **Map product audio output route.** Starting from exact product strings and USB/MIDI handler, identify the synth output or final audio-mix call chain. Cross-check with public symbols `dac_digital_lr_add`, `dac_digital_lr_sub`, `audio_mix_data_dec_callback`, and channel merge helpers, but keep all public names provisional until matched.
5. **RAM/cycle budget from static data.** Derive BSS/heap/task-stack estimates from v15 app references and public SDK map conventions. Separately estimate a minimal PCM oscillator or one-shot player budget at 16-bit stereo 44.1/48 kHz. Do not use AC79 headline CPU speed as proof of free budget.
6. **Resource-format audit.** Search exact v15 for public MIDI tone artifacts (`MIDI.mdb`, `WaveInfo_t`-like table shapes, ADPCM step/index tables, sample-rate tables) and for product-specific FM/voice table shapes. Record rejected candidates with why, as in `sdk-signatures/evidence.md`.
7. **Read-only hardware correlation.** Use board photos/continuity notes only to confirm whether the SoC audio pins plausibly route to CS4344 SDIN/SCLK/LRCK/MCLK. Do not probe powered hardware or flash firmware under this task.

## Conclusion

- **Public AC79 capability:** strong. PCM/WAV decode, decoder tasks, DAC/IIS output selection, virtual output, decoded-PCM callbacks, audio effects, and sample/wavetable MIDI synthesis are all present in public AC79/WL82 sources/libraries.
- **Official v15 product capability:** partially known. USB MIDI transport and MIDI ingress are exact. The downstream synth/audio callback/mixer/DAC path is not identified.
- **Modification feasibility now:** static research only. PCM/WAV/sample playback and software real-time PCM synthesis are plausible directions, but any v15 callback injection or sample-player patch is below the evidence threshold until exact product addresses, ABI, RAM budget, and output route are proven.
