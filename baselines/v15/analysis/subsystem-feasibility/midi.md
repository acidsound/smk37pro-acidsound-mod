# v15 MIDI subsystem feasibility

Status: 조사 문서. 최초 작성 작업에서는 펌웨어 패치, 리패키지, OTA, flash, endpoint 전송 실행을 수행하지 않았다.

## 2026-08-02 R02 live update

후속 R02 통제 실험은 이전의 named-timbre 실패 결론을 갱신했다. 공식 product
SysEx 형식 `F0 43 00 00 01 1B + 0x9c bytes + F7`로 Bank D 표시 14
Mooger #1 runtime voice를 `0x01c37fd0`에 staging한 뒤, Ch10 Note On/Off가
동일 source를 사용하도록 했다. 실제 장치에서 Ch10 음색이 Mooger #1과 일치했고,
Note Off가 정상이며, Ch1 UI patch를 변경해도 Ch10 음색이 유지됐다.

이 성공은 [`../flash-candidates/R02/live-validation-20260802.md`](../flash-candidates/R02/live-validation-20260802.md)에 기록했다. 다만 `0x01c37fd0`은
공유 transient SysEx workspace이므로 영구 저장, 동시 SysEx, reboot/SAVE,
16-pad per-note patch set은 아직 해결되지 않았다. 아래 R01/R01b/R01c 실패 기록은
정적 app/text snapshot 방식의 역사적 반증으로 읽어야 한다.

## 범위와 판정 기준

요청 범위는 공식 v15 내부 분석, `smk-37-pro-docs` 및 이 저장소의 파생 자료, 공개 AC79 SDK를 근거별로 분리해 MIDI input/output, channel routing, Note On/Off, CC, Program Change, pitch bend, SysEx, USB MIDI endpoint별 수정 가능성을 평가하는 것이다.

이 문서의 근거 구분은 다음과 같다.

- **직접 v15 근거**: `build/v15-official-app.bin` 또는 `baselines/v15/` 산출물에서 직접 나온 byte, address, listing, manifest, descriptor, hash, v15 read-only observation.
- **SDK 근거**: 공개 Jieli AC79/WL82 SDK, 공식 문서, 공개 library/header/Makefile에서 나온 일반 API/ABI/구조. v15 주소로 승격하지 않는다.
- **추론**: 직접 v15 근거와 SDK/product-doc 근거를 연결한 search model 또는 mod 가능성 판단. 독립 검증 전에는 사실로 취급하지 않는다.
- **실기 관찰**: 실제 장치에서 관찰된 USB enumeration, owner live test, runtime-trace 결과. v12/M05-M10 관찰은 product-line 파생 근거이며 공식 v15 직접 근거가 아니다.

가능성 등급:

| 등급 | 의미 |
|---|---|
| 높음 | v15 내부 주소와 동작 후보가 직접 확인되어 dry-run 수준 설계가 가능하다. 실기 동작 보증은 별도 표시가 있어야 한다. |
| 중간 | v15에 강한 단서가 있으나 caller chain, endpoint callback, downstream audio/UI 효과, 또는 ABI 일부가 미확정이다. |
| 낮음 | 공개 SDK나 파생 관찰로 일반 가능성은 있으나 v15 주소/호출자/상태 구조가 부족하다. |
| 보류 | 현재 증거로 안전한 변경 목표를 정의할 수 없다. |

## 고정 입력과 revision ledger

| 범주 | 파일/URL | revision/hash | 이 문서에서의 역할 |
|---|---|---|---|
| 공식 v15 package | `build/SMK-37_Pro_015.fwsc`, manifest `baselines/v15/official/package-manifest.json` | package SHA-256 `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` | 공식 v15 package 기준 |
| 공식 v15 app | `build/v15-official-app.bin` | 617,012 bytes, SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` | 모든 v15 runtime VA의 byte source |
| 주소 모델 | `baselines/v15/analysis/evidence.md` | runtime base `0x02000000`; package/flash storage offset = file offset `+0x4120` | file/runtime/flash 주소 변환 |
| Quarkslab decoder | `https://github.com/quarkslab/ghidra-jieli` | `e1bd0707874b77b759401555d24839ad43af1267`, `baselines/v15/analysis/quarkslab/evidence-report.md` | v15 listing 및 xref coverage 개선 |
| Kagaimiq decoder | `https://github.com/kagaimiq/ghidra-jieli` | `b5e60122b6cd3e6b615387035994b8bed0ea1a26` plus local patch SHA-256 `298aa34ba5e0c75e94b28f7288825fa9c2c48bb3abe0f6e19551d6bbf46b683d` | 초기 PI32v2/ABI 모델과 비교군 |
| 공개 AC79 SDK | `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK` | branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d` | USB/audio/MIDI public API 및 library 근거 |
| 공개 AC79 문서 | `https://doc.zh-jieli.com/AC79/zh-cn/release_v1.0.3/index.html`, `https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/` | 문서 snapshot은 페이지별 상이. 이 저장소의 public research는 2026-08-01 UTC 기준 | platform 기능 및 USB/audio 설명 |
| USB MIDI 표준 | `https://www.usb.org/sites/default/files/midi10.pdf` | USB MIDI 1.0, 1999-11-01 | MIDIStreaming descriptor/endpoint/CIN 해석 |
| `smk-37-pro-docs` | `https://github.com/jonathaslacerda/smk-37-pro-docs` | `main` = `8f1bf1115cc8fe874bbac326d4f1f1513d743844`; `docs/research-notes.md`도 같은 commit을 기록 | 공개 제품 manual/images/firmware index 근거 |
| v15 device info | `baselines/v15/device-info/device-info.txt`, `probe.txt` | captured `2026-08-01T15:44:29Z` | 공식 v15 identity와 USB interface enumeration |
| v15 runtime trace attempt | `baselines/v15/analysis/runtime-trace/report.md` | report date `2026-08-01 UTC` | endpoint transfer가 실행되지 않았음을 기록 |

## 요약 매트릭스

| 항목 | 가능성 | 직접 v15 근거 | SDK 근거 | 추론 | 실기 관찰 | 다음 검증 |
|---|---|---|---|---|---|---|
| USB MIDI endpoint 식별/보존 | 높음 for 식별/보존, 낮음-중간 for endpoint 변경 | Descriptor anchors: MIDIStreaming interface `0x020579ae`, class header `0x020579b7`, CIN length table `0x02057ab0`, IN endpoint `0x02057fc6`, OUT endpoint `0x02057fd6`, jack graph `0x02058274`. `probe.txt`도 interface 4, EP `0x04` OUT/`0x84` IN 확인. | USB MIDI 1.0은 Audio class `0x01`, MIDIStreaming subclass `0x03`, bulk endpoint, 4-byte event packet을 정의. 공개 AC79 SDK는 USB class registration pattern은 있으나 public USB-MIDI class source는 없음. | endpoint descriptor는 안전하게 인식하고 보존할 수 있다. endpoint 번호나 cable topology 변경은 callback/descriptor consistency가 미확정이라 위험하다. | 공식 v15 장치가 VID:PID `4353:cf4d`, interface 4, bulk endpoints `0x04/0x84`로 열거됨. | descriptor builder/callback xref 찾기, class endpoint descriptor와 runtime registration path 연결, read-only enumeration 재확인. |
| MIDI input, USB OUT `0x04`에서 message parser까지 | 중간 | Raw MIDI stream parser `0x02001050`는 channel status, running status, SysEx boundary, status-nibble length table, ring buffer write를 처리. 그러나 endpoint `0x04` callback에서 이 parser로 가는 chain은 미확정. | 공개 SDK는 MIDI controller wrapper와 decoder library를 제공하지만 USB-MIDI class source는 없음. | v15에 USB-MIDI descriptor와 parser가 모두 있으므로 input path 존재 가능성은 높지만, endpoint callback 주소를 아직 mod point로 주장할 수 없다. | runtime-trace 2026-08-01은 장치 부재로 interface claim 전 거부. OUT transfer 0건. | exact v15 장치 연결 후에도 이 작업 범위에서는 전송 금지. 우선 정적 xref, USB registration 후보, ring-buffer consumer caller를 재분석. 별도 승인 시 fixed matrix만 실행. |
| MIDI output, device-to-host IN `0x84` | 낮음 | IN endpoint descriptor `0x02057fc6`와 live enumeration은 있음. v15 output formatter/send function 주소는 아직 식별되지 않음. | 공개 AC79 SDK USB core에는 `usb_output` exact v15 match가 `0x02004192`로 있음. USB-MIDI packet formatter는 공개 branch에 없음. | endpoint는 존재하지만 어떤 local event가 IN packet으로 변환되는지, cable number가 어떻게 선택되는지 모른다. | v15 IN traffic 관찰 없음. v12/M06 파생 관찰에서는 physical pads가 USB MIDI로 Ch10 Note On/Off를 내보냈지만 v15 직접 근거가 아니다. | IN endpoint writer caller chain, 4-byte USB-MIDI packet buffer pattern, local pad/key event to USB bridge 식별. 비파괴 IN sniffing은 별도 승인 후. |
| Channel routing | 높음, v15 실기 입증 | Dispatcher `0x0201c5ec`: `r3=[r1]`, `r4=status>>4`, `r9=status & 0x0f`; Note On/Off source hook에서 `r9==9` 분기가 가능하다. | 공개 MIDI API는 16 channel state를 전제한다. | message가 dispatcher에 도달한 이후 채널 니블 기반 source 분리가 가능하다. | 물리 Pad `99 24 66`과 R01 계열에서 Ch1/Ch10이 다른 소리를 내는 것을 확인했다. 이는 경로 분리 증거이며 의도한 factory 음색 선택 증거는 아니다. | RAM source checkpoint와 overlapping Ch1/Ch10 stress. |
| Note On | 높음 for v15 live hook | `0x0201c67c`가 RAM `0x01c34c74`에서 `0x9c` bytes를 per-voice slot으로 복사한다. | 공개 SDK는 Note On `(key, velocity, channel)` 형태를 제공. | Ch10 source pointer를 분기할 수 있지만 source 객체의 주소 공간·lifetime도 맞아야 한다. | R01 계열에서 Ch10 branch 도달은 통과했다. app/text-resident snapshot의 named timbre identity는 실패했다. | official-loader-produced RAM clone을 동일 stock Patch와 A/B 비교. |
| Note Off | 높음, matched-source 요구 실기 입증 | `0x0201c63e`도 같은 `0x9c` source copy ABI를 사용한다. | 공개 SDK Note Off prototype은 key/channel/time을 받는다. | Note On과 Note Off가 같은 Ch10 source identity를 사용해야 한다. | 원 R01은 On/Off source 불일치로 고착음. R01b/R01c의 matched source에서 Note Off 정상. | overlapping release order, CC64/CC123 회귀 시험. |
| Control Change, CC | 중간-낮음 | `0x0201c6b2..0x0201c710` path가 status `0xb0` 후보로 보이며 controller byte `r2=[r1+1]`, value `r1=[r1+2]`를 사용. Recognized controller checks include `0x40`, `0x02`, `0x04`, `0x01`; some paths store to `r4+0x3c`, `r7+0x10`, `r7+0x14`, `r4+0x9` and call `0x0201c59e` or `0x020017c2`. Product handler `0x0201e64a` also handles exact `0xb0` with controller `0` and value `0x65`. | 공개 SDK lists controller/config operation `ctl_confing` and velocity vibrato, but v15 MIDI synth object matching was zero. | 일부 CC는 이미 product parameters or mode state에 매핑된 듯하다. General MIDI CC map 전체 수정은 controller dispatch table/state meaning을 모르면 위험하다. | v15 CC runtime acceptance 관찰 없음. runtime matrix contains CC1, CC64, CC123 but was not executed. | 각 CC number별 side effect table 작성, `0x0201c59e` semantics 확인, harmless read-only UI/audio observation protocol 설계. |
| Program Change | 중간 | Dispatcher switch 안의 `0x0201c6d2..0x0201c6da` path가 2-byte channel voice status 후보로, `[r1+1]`를 읽어 `r7+0x18`에 store 후 `0x0201c59e` call. 이 해석은 status nibble switch 구조에 기반한 v15 listing inference이며 아직 named symbol은 없음. | 공개 SDK exposes `set_prog` operation and controller command Set Program `0xf2`. | v15에 Program-like state store는 있으나 UI patch/preset loader와 연결되는지, channel별인지 global인지 미확정. Program Change로 patch selection mod를 구현하려면 UI/current-patch state와 충돌 가능성이 있다. | v15 Program Change 실기 관찰 없음. v12 M05-M08 explicitly had no Program Change support in custom patch path. | switch table case targets를 완전히 복원, `r7+0x18` state consumer와 preset loader xref 확인, Program Change fixed matrix는 별도 승인 후. |
| Pitch bend | 중간-높음 | Dispatcher pitch path `0x0201c69a..0x0201c6b0`: status high nibble `0xe0`, value `([r1+2] << 7) | [r1+1]`, halfword store at `r7+0x2`. Product handler `0x0201e64a` has another pitch-bend-like path for `(status & 0xf0)==0xe0`, loops 16 routing records, and writes 14-bit values into 16-entry halfword arrays at global offsets `0x704` and `0x724`. | 공개 SDK exposes `pitch_bend` operation, command `0xf3`, and `midi_pitchBend` symbol in public archives. | Pitch bend input decode/state is directly visible and likely modifiable for scaling/range/filtering. Audible bend range and channel isolation are still unverified. | runtime matrix includes bend min/center/max but was not executed. No v15 audio observation. | Identify `r7` channel/voice control struct, consumers of `r7+0x2` and global arrays `0x704/0x724`, static range clamp check, optional future fixed bend observation only with approval. |
| SysEx | 보류 for preserving stock product SysEx with code-cave patches, 중간 for parser-level recognition | Parser `0x02001050` supports SysEx boundaries and running status. Independent caller at file `0x2d1b4`, VA `0x0202d1b4`, validates seven-byte `f0 35 59 ... f7`, reconstructs a status byte through a nibble table, writes message buffer, and calls `0x0201e64a`. R01 intentionally occupies `0x0201e13e..0x0201e1fe` and disables old SysEx direct callers at `0x0201e468` and `0x0201e49c`. | Public SDK MIDI control API does not provide SMK product SysEx semantics. USB MIDI spec defines SysEx event packet CINs 4/5/6/7. | Parser-level SysEx is real, but stock product SysEx function identity and safe replacement space are fragile. R01-style code cave trades away Yamaha single-voice pack/save. | v15 SysEx runtime observation 없음. runtime matrix includes SysEx boundaries and identity request but was not executed. v12 notes warn not to send Yamaha preset SysEx during M05 test. | Preserve-before-modify audit of `0x0201e13e` routine, locate alternate safe code/data cave, fixed SysEx boundary dry-run only. No arbitrary SysEx fuzzing. |
| USB MIDI cable numbers | 낮음 | Descriptor jack graph at `0x02058274` and class endpoint descriptors indicate three associated embedded jacks. No v15 code path mapping cable number to routing was identified. | USB MIDI event packet byte 0 high nibble is cable number. Public AC79 SDK has no USB-MIDI class source. | Cable 0/1/2/3 behavior cannot be inferred from descriptors alone. | v15 no transfer observation. v12/M06 pad output duplication on cables 0 and 1 is product-line observation only. | Search packet formatter/parser for `byte0 >> 4`/CIN masks, execute cable fixed matrix only in a future separately approved runtime test. |

## 직접 v15 근거

### Package, base, and descriptors

`baselines/v15/analysis/evidence.md` fixes the official app SHA-256 and the address model. All runtime VAs in this document use file offset `+ 0x02000000`; storage/flash offsets use file offset `+ 0x4120` from `baselines/v15/official/package-manifest.json`.

USB MIDI byte anchors, all single occurrence in the exact v15 app:

| Evidence | file offset | runtime VA | flash offset | interpretation |
|---|---:|---:|---:|---|
| ASCII `midi_route\0` | `0x5773b` | `0x0205773b` | `0x5b85b` | MIDI routing component-like string |
| MIDIStreaming interface | `0x579ae` | `0x020579ae` | `0x5bace` | Audio class, MIDIStreaming subclass, two endpoints |
| MIDIStreaming class header | `0x579b7` | `0x020579b7` | `0x5bad7` | USB MIDI 1.0 class-specific header |
| CIN payload lengths | `0x57ab0` | `0x02057ab0` | `0x5bbd0` | 16-entry USB-MIDI payload byte count table |
| USB device descriptor | `0x57b53` | `0x02057b53` | `0x5bc73` | VID `0x4353`, PID `0x4b4d` in app bytes |
| UTF-16LE `SMK-37 Pro Midi` | `0x57fa8` | `0x02057fa8` | `0x5c0c8` | USB product/manufacturer string data |
| MIDI IN endpoint | `0x57fc6` | `0x02057fc6` | `0x5c0e6` | device-to-host bulk endpoint `0x84`, 64 bytes |
| IN class endpoint | `0x57fcf` | `0x02057fcf` | `0x5c0ef` | three associated embedded MIDI jacks |
| MIDI OUT endpoint | `0x57fd6` | `0x02057fd6` | `0x5c0f6` | host-to-device bulk endpoint `0x04`, 64 bytes |
| OUT class endpoint | `0x57fdf` | `0x02057fdf` | `0x5c0ff` | three associated embedded MIDI jacks |
| MIDI jack graph | `0x58274` | `0x02058274` | `0x5c394` | coherent 12-descriptor topology |

Important boundary: these bytes prove descriptor templates and USB MIDI shape. They do not by themselves identify the endpoint callback or prove how callbacks dispatch messages.

### Parser and product MIDI handlers

`baselines/v15/analysis/sdk-signatures/evidence.md` records exact v15 product-side findings that are not public SDK synth matches:

1. **Raw MIDI stream parser**: file `0x1050`, VA `0x02001050`, exact 824-byte region hash in `sdk-signatures/report.json`. It recognizes channel statuses, uses a status-nibble length table, supports running status and SysEx boundaries, and writes completed messages to a ring buffer.
2. **Product MIDI message handler**: file `0x1e64a`, VA `0x0201e64a`, exact 216-byte region hash in `sdk-signatures/report.json`. It handles exact statuses `0x90`, `0x9f`, `0xb0`, and channelized pitch bend `(status & 0xf0)==0xe0` for 16 routing records. Its `0x90` path is product-specific and restricted to note `0x73`; it is not a general synth Note On proof.
3. **Independent caller**: file `0x2d1b4`, VA `0x0202d1b4`, validates `f0 35 59 ... f7`, reconstructs a status byte through a nibble table, writes it into a message buffer, and calls `0x0201e64a` with the buffer pointer in `r0`.

### Dispatcher and synthesis-adjacent event paths

The Quarkslab exhaustive listing `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz` exposes a dispatcher at `0x0201c5ec`:

- `0x0201c5ee`: load status byte from message buffer.
- `0x0201c5f0`: `r4 = status >> 4`.
- `0x0201c5fe`: `r9 = status & 0x0f`, channel nibble.
- `0x0201c63e`: Note Off candidate copies `0x9c` bytes through `memcpy 0x02048cce`.
- `0x0201c67c`: Note On candidate copies `0x9c` bytes through `memcpy 0x02048cce`.
- `0x0201c69a..0x0201c6b0`: pitch bend candidate builds 14-bit value and stores it.
- `0x0201c6b2..0x0201c710`: CC-like candidate reads controller/value and handles recognized controllers.
- `0x0201c6d2..0x0201c6da`: Program/pressure-like two-byte channel message candidate; Program Change interpretation still requires switch-table confirmation.
- `0x0201c736` and `0x0201e644`: recovered callers to `0x0201c5ec`.

`tools/build_v15_r01_hand_drum.py` and `baselines/v15/analysis/flash-candidates/R01/app-manifest.json` use these v15-only addresses for a dry-run/static patch design:

- dispatcher: `0x0201c5ec`;
- Note On hook: `0x0201c67c`;
- Note Off hook preserved: `0x0201c63e`;
- factory loader: `0x02005660`;
- memcpy: `0x02048cce`;
- wrapper/data location: `0x0201e13e..0x0201e1fe`;
- disabled old SysEx direct callers in that candidate: `0x0201e468`, `0x0201e49c`;
- input app SHA-256 remains exact official v15 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.

This is static evidence only. R01 is explicitly not live-verified in `baselines/v15/analysis/mod-capability-matrix.md`.

## SDK 근거

### Public MIDI control API and library

Source revision: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`.

Relevant files/URLs:

- `apps/common/audio_music/midi/audio_dec_midi_ctrl.c`: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/audio_music/midi/audio_dec_midi_ctrl.c`
- `include_lib/media/MIDI_CTRL_API.h`: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/media/MIDI_CTRL_API.h`
- `include_lib/media/MIDI_DEC_API.h`: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/include_lib/media/MIDI_DEC_API.h`
- `cpu/wl82/liba/lib_midi_dec.a`: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/cpu/wl82/liba/lib_midi_dec.a`

Recovered public API/model from `baselines/v15/analysis/sdk-signatures/evidence.md`:

- `MIDI_CTRL_CONTEXT` has eleven 32-bit function pointers: `need_workbuf_size`, `open`, `run`, `set_prog`, `note_on`, `note_off`, `pitch_bend`, `ctl_confing`, `vel_vibrate`, `query_play_key`, `glissando`.
- Public signatures: `note_on(void *work_buf, u8 key, u8 velocity, u8 channel)` and `note_off(void *work_buf, u8 key, u8 channel, u16 time_ms)`.
- Controller commands: Note On `0xf0`, Note Off `0xf1`, Set Program `0xf2`, Pitch Bend `0xf3`, velocity vibrato `0xf4`, query `0xf5`.
- Public state model includes 16 channel control entries.
- Public Note On masks key/velocity to 7 bits, treats velocity zero as stop, resolves tone zones, then calls player-control Note On. Public Note Off scans active players and can set decay.

Boundary: the same evidence file reports **zero** accepted relocation-aware v15 matches for seven selected public MIDI objects across 57 functions, zero exact public MIDI lookup-table matches, and zero exact SDK-ELF functions with MIDI/Note/Pitch/Glissando names. Therefore the SDK gives a search model, not v15 function names or addresses.

### Public USB device implementation

Relevant SDK files/URLs:

- `apps/common/usb/device/usb_device.c`: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/usb/device/usb_device.c`
- demo audio Makefile: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/demo/demo_audio/board/wl82/Makefile`

The public branch publishes USB device composition for MSD, UAC, HID, CDC, UVC, and printer, using descriptor callbacks and class registration functions. The inspected public branch has no published USB-MIDI device-class source and no `midi.c` under `apps/common/usb/device/`. The demo Makefile includes USB classes separately from MIDI controller/library sources.

Consequence: v15's USB-MIDI endpoint handler is likely product-specific or private-SDK code. Public USB sources help search for registration patterns but do not identify the v15 endpoint callback.

## `smk-37-pro-docs` 및 파생 자료 근거

### Product docs

`smk-37-pro-docs` URL/revision:

- repository: `https://github.com/jonathaslacerda/smk-37-pro-docs`
- revision checked by `git ls-remote`: `8f1bf1115cc8fe874bbac326d4f1f1513d743844`
- manual URL cited by this repository: `https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/manual/smk-37-pro-user-manual.pdf`
- board image URL cited by this repository: `https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/images/smk37pro`

`docs/research-notes.md` records that the manual states the USB host should enumerate the SMK-37 Pro as both MIDI and Audio. It also records rear-panel physical I/O including USB-C and 3.5 mm MIDI Out. Product docs establish product-level presence of MIDI/USB functionality, not v15 internal addresses.

### Derived v12/M05-M10 observations, not direct v15 proof

These are useful product-line constraints but must not be promoted to official v15 addresses:

- `docs/firmware-versioning.md` M05 live result: USB MIDI channel 1 retained patch N while channel 2 sounded patch N+1 simultaneously on v12-derived custom firmware.
- M06 live result: local keyboard remained Ch1/current patch N, physical pads used Ch10/patch N+1 through a local FM bridge.
- M07 live result: per-note timbres worked but contaminated Ch1/local keys, so channel isolation failed.
- M08 live result: Ch1 retained UI-selected patch while Ch10 retained fixed 16-note map across UI Patch changes; no normal-use problem observed. Polyphony/voice stealing remained untested.
- M09/M10 incident records show that unproven data/code cave assumptions can cause pre-USB boot failure. This increases caution for any v15 code/data cave or SysEx routine replacement.

Derived observation value: the SMK product audio path can honor per-event/per-voice snapshots and channel-gated timbre selection. Limitation: those are v12 custom builds, not official v15 static addresses or v15 runtime success.

## 실기 관찰

### Official v15 enumeration

`baselines/v15/device-info/device-info.txt`, captured `2026-08-01T15:44:29Z`:

- device info response name: `SMK-37 Pro`;
- version: `015`.

`baselines/v15/device-info/probe.txt`, same capture:

- VID:PID `4353:cf4d`;
- speed: full speed, 12 Mbit/s;
- manufacturer: `SMK-37 Pro Midi`;
- configuration: 5 interfaces;
- interface 4 alt 0: class `0x01`, subclass `0x03`, 2 endpoints;
- endpoint `0x84` IN bulk, max packet 64;
- endpoint `0x04` OUT bulk, max packet 64.

This is direct v15 live enumeration evidence for interface and endpoints. It does not show accepted packets, emitted IN packets, audible notes, UI changes, or controller semantics.

### Official v15 runtime-trace attempt

`baselines/v15/analysis/runtime-trace/report.md` records a safe observer and fixed matrix covering cables, channels, CINs, Program Change, CC, pitch bend, SysEx boundaries, universal Identity Request, and bounded malformed cases. Live execution did **not** send packets because the exact device was not visible. The observer refused before interface claim and before any endpoint transfer.

Therefore no v15 runtime conclusion exists for whether endpoint `0x04` accepts or ignores any cable number, CIN, channel, Program Change, CC, pitch bend, SysEx boundary, or malformed case.

## Risk notes and next validation plan

1. **Do not conflate endpoint descriptors with callback identity.** The descriptors and live enumeration are high-confidence. The receive/send function addresses are not.
2. **Do not import v12 addresses into v15.** v12 M05-M08 results are valuable product-line evidence but only v15 byte/listing evidence can justify v15 patch points.
3. **Preserve Note Off unless its exact channel/note/time semantics are proven.** R01 correctly leaves `0x0201c63e` unchanged.
4. **Treat SysEx routine space as scarce and risky.** R01 uses the old SysEx region and disables direct callers; this is acceptable only for a checkpoint that explicitly sacrifices that feature.
5. **No patch/flash in this task.** Next validation should start with static analysis, listing extraction, hash-guarded dry-run manifests, and read-only enumeration. Any future endpoint transfer or firmware install requires a separate explicit approval and safety protocol.

Recommended next non-flash checks:

- Extract and annotate the full switch table for `0x0201c5ec`, including exact case target for Note Off, Note On, poly pressure, CC, Program Change, channel pressure, and pitch bend fallback.
- Trace callers `0x0201c736` and `0x0201e644` backward to identify whether either is USB endpoint, local keyboard, local pad, or product SysEx ingress.
- Search for consumers of `r7+0x2`, `r7+0x10`, `r7+0x14`, `r7+0x18`, `r4+0x3c`, and `r4+0x9` to name pitch/CC/program state safely.
- Search for 4-byte USB-MIDI packet construction/parse masks: CIN low nibble, cable high nibble, `0x0f`, `0xf0`, `0x04`, `0x84`, 64-byte packet loops.
- Locate IN endpoint writer caller chain around exact `usb_output` match `0x02004192` and distinguish generic USB output from USB-MIDI event packet send.
- Preserve a no-flash fixed matrix from `runtime-trace/matrix.txt`; execute it only under a future separately approved runtime observation task.
