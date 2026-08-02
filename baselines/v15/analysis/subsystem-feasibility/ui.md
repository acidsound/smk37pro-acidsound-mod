# v15 UI subsystem feasibility

Status: 조사 문서. 펌웨어 패치, 리패키지, 플래시를 수행하지 않았다.

## 범위와 판정 기준

이 문서는 공식 v15 분석 산출물, 공개 `smk-37-pro-docs`, 공개 Jieli AC79 SDK/문서를 분리해 SMK-37 Pro v15 UI 수정 가능성을 평가한다.

- 공식 v15 기준 이미지: `build/v15-official-app.bin`, 617,012 bytes, SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
- 주소 모델: file offset `x`, runtime VA `0x02000000 + x`, package/flash storage offset `x + 0x4120`. 근거: `baselines/v15/analysis/evidence.md`.
- 공개 SDK 기준: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`. 근거: `baselines/v15/analysis/sdk-signatures/evidence.md` 및 `baselines/v15/analysis/public-research.md`.
- 공개 제품 문서 기준: `https://github.com/jonathaslacerda/smk-37-pro-docs`, 정확한 revision은 이 저장소 문서에 고정되어 있지 않다. 다음 단계에서 `git ls-remote` 또는 vendor snapshot pinning이 필요하다.

가능성 등급:

| 등급 | 의미 |
|---|---|
| 높음 | v15 내부 바이트/주소와 공개 근거가 직접 맞물리며, 같은 길이 또는 작은 데이터 변경 수준에서 설계 가능하다. |
| 중간 | v15에 강한 단서가 있으나 호출자, 상태 ABI, 리소스 포맷, 또는 전기적 연결 중 일부가 미확정이다. |
| 낮음 | 공개 SDK/제품 문서로 일반 가능성은 보이나 v15 주소, ABI, 런타임 경로가 없다. |
| 보류 | 현재 증거로는 안전한 변경 목표를 정의할 수 없다. |

## 요약 매트릭스

| 하위 시스템 | 가능성 | 직접 v15 근거 | public SDK evidence | product-doc inference | 필요한 다음 증거 |
|---|---|---|---|---|---|
| LCD/display driver | 중간 | ST7789V 유사 init command table이 v15에 존재한다는 기존 조사. 정확 주소와 호출자는 아직 이 파일에서 재검증하지 않았다. | Jieli SDK의 `apps/common/ui/lcd_driver/lcd_st7789v.c`가 같은 명령군을 제공한다. AC79 LCD 문서가 LCD peripheral/UI 예제를 제공한다. | 1.54-inch 정사각 패널이면 240 x 240 ST7789 계열일 가능성이 높다. FPC/버스는 미확정. | init table의 file offset/VA, LCD write 함수 xref, 보드 FPC 마킹, SPI/8080/기타 버스 logic capture. |
| resources/fonts/bitmaps | 낮음-중간 | v15 패키지에는 별도 `JL.sty`, `menu.res`, `str.res`, PNG/JPEG 번들이 노출되지 않는다. UI 문자열/색상은 `app.bin`에 직접 존재한다. | AC79 UI framework와 UI tool 문서는 리소스/스타일 기반 UI를 설명하지만, v15 패키지 구조와 1:1 대응은 미확정이다. | 공개 제품 펌웨어 index는 v11-v15 앱이 제품별로 분리되어 있음을 뒷받침하지만 리소스 포맷은 설명하지 않는다. | v15 내부 리소스 테이블 식별, font glyph/bitmap magic search, renderer 함수 xref, SDK UI resource compiler 산출물과 byte-level 비교. |
| UI state | 중간 | 일부 UI 문자열 포인터와 화면 문자열은 확인된다. `Pad Bank-` 포인터가 `0x058304 -> 0x0205d9c5`, `Keys Channel-` 포인터가 `0x058314 -> 0x0205d9e9`로 확인됐다. | 공개 SDK는 UI 상태 모델을 제공하지만 v15의 struct layout으로 직접 매칭되지는 않았다. SDK-signatures에서 MIDI/버튼 유사 operation table 후보는 UI/button-state callback으로 보였으나 공개 MIDI ABI와 불일치해 폐기됐다. | 제품 UI에는 패치/뱅크/설정 화면이 존재한다는 추론은 가능하나 상태 변수 위치는 제품 문서만으로 알 수 없다. | 각 문자열 xref의 렌더 호출자, 선택 패치 상태 변수, 화면 전환 state machine, 저장/로드 VM 접근 경로. |
| buttons | 낮음-중간 | `sdk-signatures/evidence.md`는 `0x58248`의 11-code-pointer run을 공개 MIDI context로 보지 않고 product UI/button-state callback 후보로 폐기했다. 이는 버튼/UI 관련 코드가 근처에 있을 수 있다는 단서일 뿐 ABI는 아니다. | 공개 SDK GPIO/key/button 예제는 AC79에서 버튼 스캔이 가능함을 보이지만 v15 key matrix 주소를 제공하지 않는다. | `smk-37-pro-docs`의 보드 사진/제품 설명은 물리 버튼 존재와 패널 배치를 추론하게 하지만 scan line/pin mapping은 미확정이다. | key scan 함수, debounce/state struct, GPIO pin map, 버튼 이벤트 dispatcher xref, 실기 read-only trace. |
| LED | 낮음 | 공식 v15 분석에서 LED 제어 주소나 ABI는 아직 없다. 기존 capability matrix도 `UI-03` 버튼 이벤트 및 LED 제어를 미조사로 표시한다. | 공개 SDK는 GPIO/PWM/LED 제어 가능성을 제공한다. v15 LED 함수 매칭은 없다. | 제품에는 pad LEDs/panel LEDs가 존재한다. M09 incident 문서의 관찰은 전원/앱 부팅 상태 추론에는 쓰이나 LED 제어 ABI 근거는 아니다. | LED GPIO/PWM pin map, pad LED update table, brightness/state buffer, UI 이벤트와 LED 갱신 xref, 비파괴 logic capture. |
| patch-name/version rendering | 높음 for same-length ASCII, 중간 for layout/font | v15 `app.bin`에 UI 문자열과 색상이 직접 있다. 확인한 file offset/VA/flash: `Firmware` `0x5d8f5`/`0x0205d8f5`/`0x61a15`, `Pad Bank-` `0x5d9c5`/`0x0205d9c5`/`0x61ae5`, `Keys Channel-` `0x5d9e9`/`0x0205d9e9`/`0x61b09`, `Cut Off-` `0x5d852`/`0x0205d852`/`0x61972`, `Distortion-` `0x5d85b`/`0x0205d85b`/`0x6197b`, `Algorithm-` `0x5d876`/`0x0205d876`/`0x61996`, `Feedback-` `0x5d881`/`0x0205d881`/`0x619a1`, `Mono/Poly` `0x5d88b`/`0x0205d88b`/`0x619ab`, `SAVE` `0x57298`/`0x02057298`/`0x5b3b8`, `SAVED` `0x5d990`/`0x0205d990`/`0x61ab0`, color strings `#F5BC27` `0x57ce4`/`0x02057ce4`/`0x5be04`, `#D9D9D9` `0x57730`/`0x02057730`/`0x5b850`. | SDK UI framework/tool docs explain text/resource rendering concepts, but v15 renderer ABI is not matched. | v12 live experiments in `docs/firmware-versioning.md` showed same-length version/display strings can render, including `M02` and two-line `Hello,`/`acidsound`. That is product-line inference from v12, not direct v15 proof. | For v15, same-length string patch dry-run manifest only. Before any flash, need v15-specific renderer xrefs, bounds behavior for NUL/length, CRC/package verifier, and recovery-safe policy approval. |

## 직접 v15 근거

### 패키지와 주소

`baselines/v15/analysis/evidence.md`는 v15 `app.bin` SHA-256, runtime base `0x02000000`, package/flash offset `+0x4120`을 고정한다. 이 문서의 모든 v15 주소는 그 모델을 따른다.

`docs/research-notes.md`의 v15 추출 기록은 package 내부가 `app.bin`, `cfg_tool`, `cfg/eq_cfg_hw.bin` 중심이며 별도 노출 리소스 번들이 없다고 기록한다. 따라서 현재 가장 보수적인 UI 변경 후보는 app-resident ASCII/color bytes다.

### 확인된 UI 문자열과 색상 바이트

다음 값은 `build/v15-official-app.bin`에서 직접 재검색했다.

| 문자열 | file offset | runtime VA | package/flash offset | 수정 가능성 |
|---|---:|---:|---:|---|
| `SAVE` | `0x57298` | `0x02057298` | `0x5b3b8` | 같은 길이 ASCII만 높음 |
| `#D9D9D9` | `0x57730` | `0x02057730` | `0x5b850` | 6-digit RGB color는 높음 |
| `#F5BC27` | `0x57ce4` | `0x02057ce4` | `0x5be04` | 6-digit RGB color는 높음 |
| `Cut Off-` | `0x5d852` | `0x0205d852` | `0x61972` | 같은 길이 ASCII만 높음 |
| `Distortion-` | `0x5d85b` | `0x0205d85b` | `0x6197b` | 같은 길이 ASCII만 높음 |
| `Algorithm-` | `0x5d876` | `0x0205d876` | `0x61996` | 같은 길이 ASCII만 높음 |
| `Feedback-` | `0x5d881` | `0x0205d881` | `0x619a1` | 같은 길이 ASCII만 높음 |
| `Mono/Poly` | `0x5d88b` | `0x0205d88b` | `0x619ab` | 같은 길이 ASCII만 높음 |
| `Firmware` | `0x5d8f5` | `0x0205d8f5` | `0x61a15` | 같은 길이 ASCII만 높음 |
| `SAVED` | `0x5d990` | `0x0205d990` | `0x61ab0` | 같은 길이 ASCII만 높음 |
| `Pad Bank-` | `0x5d9c5` | `0x0205d9c5` | `0x61ae5` | pointer xref 있음 |
| `Keys Channel-` | `0x5d9e9` | `0x0205d9e9` | `0x61b09` | pointer xref 있음 |

`baselines/v15/analysis/evidence.md`는 `Pad Bank-`와 `Keys Channel-`에 대한 내부 포인터도 제시한다.

| pointer file offset | pointer value | target file offset | target text |
|---:|---:|---:|---|
| `0x058304` | `0x0205d9c5` | `0x5d9c5` | `Pad Bank-` |
| `0x058314` | `0x0205d9e9` | `0x5d9e9` | `Keys Channel-` |

이 포인터는 문자열이 런타임에서 참조된다는 직접 근거다. 그러나 이것만으로 렌더 함수, 줄바꿈, 폰트, clipping, language glyph coverage는 확정되지 않는다.

### LCD controller 단서

`docs/research-notes.md`는 v15 application 안에서 `0x11`, `0x36`, `0x3A 0x05`, `0xB2`, `0xB7`, `0xBB`, `0xC2`, `0xE0`, `0xE1`, `0x21`을 포함하는 LCD init table을 기록한다. `0x3A 0x05`는 RGB565 pixel format 선택이다. 이 명령군은 ST7789V 계열 controller와 강하게 맞지만, 현재 문서화된 v15 산출물에는 table offset, 호출자, 버스 mode가 아직 고정되어 있지 않다.

## public SDK evidence

### LCD/display driver

- SDK URL/revision: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`.
- Relevant file/URL: `apps/common/ui/lcd_driver/lcd_st7789v.c`, `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK/blob/release/AC79NN_SDK_V1.2.0/apps/common/ui/lcd_driver/lcd_st7789v.c`.
- Official docs: AC79 LCD peripheral page `https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/peripherals/lcd.html`.

의미: 공개 SDK가 ST7789V driver와 LCD interface support를 제공하므로, v15의 init table이 SDK driver 계열에서 왔을 가능성이 있다. 한계: v15 driver 함수 주소, bus pinout, framebuffer ownership, refresh cadence는 이 근거만으로 알 수 없다.

### UI resources/fonts/bitmaps

- Official docs: AC79 UI framework `https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/ui/ui.html`.
- Official docs: AC79 UI tool `https://doc.zh-jieli.com/AC79/zh-cn/release_v1.2.0/module_example/ui/ui_tool.html`.

의미: Jieli 플랫폼에는 UI framework/tool/resource path가 존재한다. 한계: v15 package에는 노출된 `JL.sty`, `menu.res`, `str.res` 등이 없어서 공개 UI resource model을 곧바로 v15에 적용할 수 없다. 폰트/비트맵 교체 가능성은 renderer/resource table을 찾기 전까지 낮다.

### Buttons/LED/UI state

공개 AC79 SDK는 GPIO, key scan, UI event, LED류 peripheral programming이 가능한 플랫폼임을 보여준다. 그러나 `baselines/v15/analysis/sdk-signatures/evidence.md`의 relocation-aware matching은 MIDI 쪽에서 공개 ABI를 v15 주소로 승격하지 않았고, `0x58248` 후보도 operation size가 맞지 않아 product UI/button-state callback 후보로만 남겼다. 따라서 buttons/LED는 SDK 일반 가능성이지 v15 patch address evidence가 아니다.

## product-doc inference

`smk-37-pro-docs`는 공개 제품 펌웨어/이미지/문서의 출처로 쓰인다.

- Repository: `https://github.com/jonathaslacerda/smk-37-pro-docs`.
- Firmware index URL: `https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/firmware/FIRMWARE.md`.
- Board/product images URL used elsewhere in this repo: `https://github.com/jonathaslacerda/smk-37-pro-docs/tree/main/images/smk37pro`.
- Revision: 현재 `baselines/v15/analysis/public-research.md`에는 이 repository의 commit pin이 없다. 다음 증거로 commit hash를 고정해야 한다.

추론:

1. SMK-37 Pro에는 화면, 물리 버튼, 패드/패널 LED가 있으므로 UI state와 button/LED coupling이 존재할 가능성이 높다.
2. 제품별 v11-v15 application이 distinct하므로 다른 제품/버전의 UI address를 v15에 이식해서는 안 된다.
3. v12 실기 기록(`docs/firmware-versioning.md`)은 같은 제품군에서 display/version 문자열 변경이 실제 표시될 수 있음을 보인다. 하지만 v12 결과는 v15 주소/렌더러 직접 근거가 아니므로 v15에서는 dry-run과 정적 xref가 먼저다.

## 하위 시스템별 상세 판정

### 1. LCD/display driver

가능성: **중간**.

가능한 변경:

- 같은 controller family에서 init gamma/color/rotation 일부 조정 가능성.
- command-compatible same-resolution panel 교체 가능성.

위험/제약:

- resolution 변경은 framebuffer size, dirty rectangle, DMA/bus bandwidth, UI coordinate assumptions를 모두 건드리므로 낮음.
- bus mode와 pin mapping이 미확정이라 실기 없는 정적 패치로는 위험하다.

필요한 다음 증거:

- v15 LCD init table의 exact file offset/VA/flash offset.
- init table xref와 LCD command/data write 함수 주소.
- SDK `lcd_st7789v.c`와 v15 table의 byte-level diff.
- board FPC marking, continuity mapping, 비파괴 logic capture.

### 2. resources/fonts/bitmaps

가능성: **낮음-중간**.

가능한 변경:

- 기존 ASCII 문자열을 같은 길이로 교체.
- 기존 RGB hex color 문자열을 같은 길이로 교체.

어려운 변경:

- 새 폰트, 한글 glyph, 새 icon/page, bitmap replacement.
- 긴 문자열 또는 layout 변경.

필요한 다음 증거:

- `app.bin` 내부 resource directory/table 후보.
- font glyph stride/encoding 후보와 renderer xrefs.
- SDK UI tool output sample과 v15 byte pattern 비교.
- 문자열 길이/terminator/bounds behavior 확인.

### 3. UI state

가능성: **중간**.

가능한 변경:

- 현재 화면 label text/color 수준은 가능성이 높다.
- 선택 patch/bank/channel 표시 로직의 상태 변수 추적은 추가 xref 후 가능할 수 있다.

위험/제약:

- v15에서 patch-selection UI state struct의 base address가 아직 없다.
- 저장/로드와 VM persistence가 얽혀 있을 가능성이 있다.

필요한 다음 증거:

- `Pad Bank-`, `Keys Channel-`, `Firmware`, `SAVE/SAVED` xref 기반 렌더 함수 식별.
- 현재 patch number/name source pointer 추적.
- VM write/read 또는 preset table access와 UI redraw coupling 분석.

### 4. Buttons

가능성: **낮음-중간**.

가능한 변경:

- 버튼 event dispatcher가 식별되면 단순 remap 또는 event suppression은 가능할 수 있다.

위험/제약:

- 현재 v15에서 key scan, debounce, long-press, encoder/button distinction 주소가 없다.
- 버튼은 OTA/recovery/user safety와 연결될 수 있어 임의 변경 위험이 크다.

필요한 다음 증거:

- key scan table/function address.
- GPIO pin map 또는 ADC key ladder 근거.
- UI/button callback candidate `0x58248` 주변의 disassembly와 caller chain.
- 실기 read-only event trace.

### 5. LED

가능성: **낮음**.

가능한 변경:

- LED state buffer와 update routine이 발견되면 색/밝기/패턴 변경 가능성이 있다.

위험/제약:

- 현재 공식 v15 근거는 LED 제어 주소를 제공하지 않는다.
- 패드 LED는 연주 상태, boot state, power state와 공유될 수 있다.

필요한 다음 증거:

- LED GPIO/PWM/SPI/shift-register chain 확인.
- pad LED table 또는 framebuffer 유사 buffer 찾기.
- button event와 LED update xref.
- 비파괴 logic capture.

### 6. patch-name/version rendering

가능성: **높음 for same-length ASCII/color**, **중간 for layout/font**, **낮음 for longer/new glyph text**.

가능한 변경:

- `Firmware`, `Pad Bank-`, `Keys Channel-`, 파라미터 label, `SAVE/SAVED` 같은 app-resident ASCII를 같은 길이로 변경.
- `#RRGGBB` color 문자열을 같은 길이 hex로 변경.

위험/제약:

- 문자열 길이를 늘리면 adjacent data와 포인터 테이블을 손상할 수 있다.
- 한글/아이콘은 font/resource/renderer 분석 전에는 불가에 가깝다.
- v12 실기 display string 성공은 v15에 대한 직접 증명이 아니다.

필요한 다음 증거:

- v15용 read-only render xref report.
- 동일 길이 변경만 포함한 manifest/diff dry-run.
- package CRC 재계산 검증만 수행하고 플래시 금지.
- recovery 경로와 실기 승인 전까지 flashing 금지.

## 결론

현재 방어 가능한 v15 UI 수정 후보는 `app.bin` 안의 같은 길이 ASCII label과 `#RRGGBB` 색상 문자열이다. LCD controller family는 ST7789V 계열로 강하게 보이나, driver 함수/버스/프레임버퍼가 아직 고정되지 않아 display driver 변경은 중간 가능성에 머문다. 폰트, 비트맵, 새 페이지, 버튼 remap, LED 제어는 공개 SDK와 제품 문서로 일반 가능성만 확인된 상태이며 v15 주소/ABI 근거가 부족하다.

다음 작업은 v15 전용 정적 분석으로 LCD init table offset, renderer xref, UI state/callback table, button/LED update path를 고정하는 것이다. 그 전까지 firmware patch/flash는 수행하지 않는다.
