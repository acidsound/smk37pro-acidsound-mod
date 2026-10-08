# Official v15 subsystem feasibility matrix

Date: 2026-08-02 UTC

이 문서는 SMK-37 Pro 공식 v15의 mod 가능성을 **UI, MIDI, FM, PCM 재생,
실시간 synthesis**로 나누어 요약한다. 상세 근거는 분야별 문서에 있고, 이 표는
우선순위와 현재 한계를 빠르게 판단하기 위한 index다.

## 근거 등급

- **V15**: 공식 v15 app/full-flash/장치 관찰에서 직접 확보
- **SDK**: 고정 revision의 공개 Jieli AC79 SDK 또는 공식 문서에서 확인
- **DOC**: `smk-37-pro-docs`, 매뉴얼, 사진, 이슈, 파생 문서에서 확인
- **BUILD**: exact-SHA builder, manifest, byte assertion, dry-run으로 검증
- **LIVE**: 해당 기능의 실제 v15 산출물을 Flash하거나 장치에서 직접 검증

가능성은 `높음`, `중간`, `낮음`, `보류`로 표시한다. `LIVE`가 비어 있으면 실제
제품 동작을 보장하지 않는다.

## 통합 matrix

| 분야 | 세부 기능 | 가능성 | V15 | SDK | DOC | BUILD | LIVE | 현재 가능한 범위와 한계 |
|---|---|---:|:---:|:---:|:---:|:---:|:---:|---|
| UI | 같은 길이 ASCII label/version 변경 | 높음 | [x] | [x] | [x] | [ ] | [x] | v15 app의 문자열 위치와 일부 포인터가 확인됐다. 폐기된 v15 M01/M02에서 표시 변경과 정상 부팅을 확인했지만 재사용 가능한 UI builder는 아직 없다. |
| UI | `#RRGGBB` 색상 문자열 변경 | 중간-높음 | [x] | [x] | [ ] | [ ] | [ ] | app 내 색상 문자열은 확인됐으나 어떤 widget에 적용되는지와 실기 결과는 미확인이다. |
| UI | LCD init/gamma/rotation | 중간 | [~] | [x] | [x] | [ ] | [ ] | ST7789V 계열 명령 단서가 있으나 exact table offset, write function, bus와 framebuffer가 미확정이다. |
| UI | font/bitmap/icon/new page | 낮음 | [ ] | [x] | [x] | [ ] | [ ] | SDK에는 resource UI가 있으나 v15 package에서 동일 resource format과 renderer를 찾지 못했다. |
| UI | 버튼 remap과 LED 제어 | 낮음 | [ ] | [x] | [x] | [ ] | [ ] | 물리 기능은 명백하지만 v15 scan/update 함수, ABI, GPIO/LED chain이 없다. |
| MIDI | USB MIDI descriptor/endpoints 보존 | 높음 | [x] | [x] | [x] | [x] | [x] | interface 4와 bulk `0x04/0x84`, descriptor/jack graph가 확인됐다. endpoint topology 변경은 별도 문제다. |
| MIDI | 채널 판별과 Note On timbre source 분기 | 높음 | [x] | [x] | [x] | [x] | [x] | 물리 Pad Ch10의 `r9==9` 분기와 Ch1 독립 source path를 실기 확인했다. R02에서 공식 SysEx staging RAM의 Mooger #1을 Ch10에 적용하고 Ch1 UI patch 변경 후에도 유지됨을 확인했다. |
| MIDI | Note Off source 일치 | 높음 | [x] | [x] | [ ] | [x] | [x] | 원 R01은 source 불일치로 고착음이 발생했다. R02는 Ch10 Note On/Off 모두 동일한 staging RAM source를 사용해 Mooger #1의 정상 Note Off와 무고착을 실기 확인했다. |
| MIDI | pitch bend decode/state 변경 | 중간-높음 | [x] | [x] | [x] | [ ] | [ ] | 14-bit decode와 16-slot state가 보이나 audible consumer와 채널 격리는 미확정이다. |
| MIDI | CC와 Program Change 라우팅 | 중간 | [~] | [x] | [x] | [ ] | [ ] | dispatcher case와 일부 상태 store는 보이나 controller 의미와 UI/current-patch 충돌 가능성이 남는다. |
| MIDI | device-to-host MIDI output과 물리 pad bridge | 중간 | [~] | [~] | [x] | [ ] | [x] | 물리 문제 해결 후 Pad에서 `99 24 66` Ch10 Note On을 실기 확인했다. packet formatter와 local scan/send caller 주소는 여전히 미확정이다. |
| MIDI | SysEx parser 및 preset transport | 중간-높음 for controlled packet | [x] | [~] | [x] | [x] | [x] | 공식 `F0 43 00 00 01 1B + 0x9c + F7` packet이 `0x01c37fd0`을 채우는 경로와 실제 수신을 R02에서 확인했다. 단, R02는 pack/save caller를 비활성화하며 staging은 공유 transient RAM이므로 stock 보존·동시성은 미해결이다. |
| FM | DX7-style 128-byte factory/user voice bank | 높음 | [x] | [~] | [x] | [x] | [ ] | full flash `0xf4000..0xf7fff`에 4 x 4096-byte bank가 있고 VMEM 구조와 이름 필드가 확인됐다. |
| FM | 128-byte voice를 156-byte per-note 객체로 확장 | 높음 | [x] | [~] | [x] | [x] | [x] | 공식 loader/converter의 Mooger #1 runtime bytes와 제품 SysEx staging을 결합한 R02에서 Bank D 표시 14의 의도 음색을 실기 재현했다. app/text 정적 snapshot 방식만 폐기 상태다. |
| FM | 채널별 고정 FM timbre 선택 | 높음 for transient checkpoint | [x] | [~] | [x] | [x] | [x] | R02에서 Ch10에 Mooger #1을 정확히 적용하고, Ch1 patch를 변경해도 Ch10 음색이 유지되며 Note Off가 정상임을 확인했다. 영구 Ch10 소유 RAM, reboot/SAVE, 동시 SysEx 안전성은 아직 없다. |
| FM | operator/envelope/algorithm 개별 편집 | 중간 | [~] | [~] | [x] | [x] | [ ] | packed-to-runtime byte map은 결정적이지만 각 runtime byte의 audible semantics와 허용 범위는 parameter sweep이 필요하다. |
| FM | 현재 발음 중인 voice의 실시간 parameter 변경 | 낮음-중간 | [ ] | [~] | [x] | [ ] | [ ] | future Note On snapshot 변경은 가능하지만 active voice ownership과 render-time 참조 방식은 모른다. |
| FM | polyphony/voice allocator 변경 | 낮음 | [ ] | [~] | [x] | [ ] | [ ] | 제품 문서는 12-note polyphony를 주장하지만 v15 allocator와 voice stealing 구조가 없다. |
| PCM | WAV/PCM 파일 decode 및 재생 API 재사용 | 중간 | [ ] | [x] | [x] | [ ] | [ ] | AC79 audio server에 WAV/PCM decoder가 있지만 v15 주소, filesystem source, output route가 아직 없다. |
| PCM | decoded PCM callback/virtual output | 중간 | [ ] | [x] | [x] | [ ] | [ ] | SDK에는 virtual DAC와 decoded-buffer callback이 있으나 v15 product ABI와 hook은 미식별이다. |
| PCM | IIS/외부 CS4344 출력 경로 사용 | 중간 | [~] | [x] | [x] | [ ] | [ ] | 보드 사진과 DAC 자료는 출력 경로를 지지하지만 v15 IIS/mixer initialization 주소가 없다. |
| PCM | sample/wavetable drum engine 이식 | 낮음-중간 | [ ] | [x] | [x] | [ ] | [ ] | 공개 Jieli MIDI engine은 sample/MIDI.mdb 기반이지만 57개 함수가 v15에 매칭되지 않았다. 별도 이식은 메모리·scheduler·audio mix 통합이 필요하다. |
| 실시간 synthesis | 기존 FM engine을 MIDI로 실시간 연주 | 높음 | [x] | [~] | [x] | [x] | [x] | Ch1과 Ch10의 발음·분리·Note Off를 확인했고, R02에서 Ch10의 독립 named patch state를 transient RAM 조건 아래 실기 입증했다. production storage와 per-note set은 미구현이다. |
| 실시간 synthesis | 새 software oscillator/audio callback 주입 | 낮음 | [ ] | [x] | [x] | [ ] | [ ] | SoC 성능은 충분할 가능성이 있으나 v15 callback, mixer, heap, IRQ budget과 코드 저장 공간이 모두 미확정이다. |
| 실시간 synthesis | PCM과 FM의 동시 mixer routing | 낮음 | [ ] | [x] | [x] | [ ] | [ ] | 플랫폼 mixer 가능성은 있으나 제품 audio graph와 동시부하 headroom이 없다. |

표의 `[~]`는 관련 byte/API 단서는 있으나 해당 기능을 직접 입증하지 못했다는 뜻이다.

## 분야별 결론

### UI

지금 바로 가장 설명 가능한 수정은 **같은 길이 ASCII label/version**과 후보
`#RRGGBB` 색상이다. 새 화면, 한글 font, bitmap, 버튼, LED는 renderer와 event
chain을 찾기 전까지 패치 대상으로 삼지 않는다.

### MIDI

현재 가장 강한 영역이다. dispatcher 이후의 **채널 판별과 matched Note On/Off
source 분리**는 실기 입증됐다. USB endpoint에서 parser까지의 caller chain,
controller 의미, SysEx 보존은 추가 분석이 필요하다.

### FM

공식 v15 full flash의 DX7-style bank와 156-byte Note-time copy는 강한 근거이며,
R02에서 제품 SysEx staging RAM을 source로 사용해 **Bank D 표시 14 Mooger #1의
채널별 고정 음색 선택을 실기 입증했다.** app/text 정적 snapshot 방식은 실패했고,
현재 성공 방식도 공유 transient RAM이므로 다음 단계는 Ch10 전용 RAM 소유권,
동시 SysEx 보호, reboot/SAVE lifecycle을 구현하는 것이다.

### PCM 재생

AC79 플랫폼 자체는 WAV/PCM decoder, audio server, virtual output, IIS/DAC를
제공한다. 그러나 공개 audio/MIDI library가 v15 product code에 매칭되지 않았으므로
현재는 **플랫폼 가능성만 높고 v15 mod 가능성은 중간 이하**다.

### 실시간 synthesis

기존 FM engine을 이용한 MIDI 연주는 가능성이 높다. 새 oscillator나 sample engine을
추가하는 것은 CPU 사양만으로 판단할 수 없으며 audio callback, mixer, RAM/stack,
scheduler와 code placement를 먼저 입증해야 한다.

## 우선순위

1. R02에서 입증한 runtime voice를 transient SysEx workspace가 아닌 Ch10 전용 RAM으로 복사하고 generation/lifetime guard를 추가한다.
2. 16개 Pad note별 156-byte patch set의 RAM/Flash layout과 Note On/Off identity를 설계한다.
3. UI 문자열 xref와 renderer, LCD init table의 exact 주소를 고정한다.
4. CC/Program/pitch bend consumer와 MIDI output formatter를 추적한다.
5. `audio_server.a` positive-control 방식으로 v15 audio decoder/mixer signature를 확장한다.
6. v15 audio output graph와 RAM/CPU headroom을 측정한 뒤 PCM 또는 새 synthesis를 판단한다.

## 상세 문서와 출처

- [`ui.md`](ui.md)
- [`midi.md`](midi.md)
- [`fm.md`](fm.md)
- [`pcm-realtime-synth.md`](pcm-realtime-synth.md)
- [`smk-docs-lineage.md`](smk-docs-lineage.md)
- [`../mod-capability-matrix.md`](../mod-capability-matrix.md)

핵심 외부 기준:

- `jonathaslacerda/smk-37-pro-docs` pinned HEAD
  `8f1bf1115cc8fe874bbac326d4f1f1513d743844`
- Jieli AC79 SDK branch `release/AC79NN_SDK_V1.2.0`, commit
  `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`
- Quarkslab `ghidra-jieli` commit
  `e1bd0707874b77b759401555d24839ad43af1267`

`smk-docs-lineage.md`에는 원본 저장소의 124개 commit 계보, 유일한 공개 fork,
firmware/SysEx/manual/image tree, 인용된 gist·Jieli·kagaimiq 자료와 링크 상태를
별도로 기록했다.
