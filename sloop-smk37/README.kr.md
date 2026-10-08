# SLOOP for SMK-37 Pro (`sloop-smk37`)

[English](README.md) | [한국어](README.kr.md)

**M-VAVE SMK-37 Pro** 용 커스텀 펌웨어. [`isod89/sloop-fm1`](https://github.com/isod89/sloop-fm1)
(SLOOP 2.4.1, FM-1 그루브박스 펌웨어)과 **동일하게 작동**합니다: 4트랙(신스 3 + 드럼),
10개 엔진(DX7 패치 받는 6-op FM 포함), 라이브 레이어, 파라미터 락/마이크로 타이밍/필이
있는 시퀀서, 송 모드, 웹 에디터 프로토콜, USB MIDI + USB 오디오 — 전부 SMK-37 Pro 패널에서.

두 기기는 JieLi **AC791N / WL82** SoC(pi32v2)를 공유하므로, 이 작업은 SLOOP의 재구성이
아닌 **보드 지원 패키지(BSP) 포트**입니다: SLOOP 코어는 핀된 업스트림 커밋(`SLOOP_PIN`)
그대로 **무수정**으로 쓰고, 이 디렉터리는 차이만 제공합니다 — SMK-37 Pro 보드 HAL,
패널 맵, 패키징 경로, 테스트.

> ⚠️ 리서치 포트. 아직 실기기 검증 전입니다. 여기의 모든 검증은 오프라인(호스트 테스트 +
> 스톡 v15 펌웨어 정적 증거)입니다. 플래시는 이 저장소의 게이트(`docs/firmware-runbook.md`,
> `docs/usb-flash-safety-case.md`, exact-hash OTA 게이트, 롤백 계획 우선) 밑에서만 합니다.
> 저장소 하드 룰 유지: **게이트 밖의 실기기 쓰기 금지.**

## 패널: 실스크린에 없는 버튼은 패드가 담당

SMK-37 Pro 실스크린에는 FM-1의 기능 버튼 14개 중 9개가 없습니다. **그 9개는 패드** —
패드를 누르고 있으면 레이어, 탭하면 페이지, 패드 LED가 해당 기능의 상태를 보여줍니다
(LED 라인 맵 `SMK37_LEDMAP`, 배선은 [UNVERIFIED], 브링업에서 확인):

| SLOOP (FM-1) | SMK-37 Pro | | SLOOP (FM-1) | SMK-37 Pro |
|---|---|---|---|---|
| FX | **패드 1** | | ARP | ARP 버튼 |
| SCL | SCALE 버튼 | | SEQ | SEQ PLAY 버튼 |
| ENV | **패드 2** | | PLAY | PLAY 버튼 |
| LFO | **패드 3** | | REC | REC 버튼 |
| EDIT | **패드 4** | | OCT− | **패드 8** |
| GLO | **패드 5** | | OCT+ | **패드 9** |
| HOME | **패드 6** | | SELECT / ALGORITHM / PRESETS 노브 | K5 / K6 / K7 |
| SAVE | **패드 7** | | KNOB 1..4 | K1..K4 |
| 27 노트 키 (F3..G5 그리드) | 건반 창 F2..G4 (흰건반 16 + 검은건반 11) | | MASTER 포터 | 페이더 4 (MASTER) |

패드 10–16, K8, 페이더 1–3, 휠, 나머지 실스크린 버튼(NOTE REPEAT, CHORD, BANK, X/Y,
SEQ REC, ENGINE, PRESET, ◄, ►, FUNCTIONS, TEACH, RECORDER)은 **기본 미할당**:
FM-1에 있는 제어는 전부 도달 가능하고, FM-1에 없는 것이 코어 동작을 바꾸지 않습니다 —
포트는 동일하게 작동하고 남는 하드웨어는 대기 상태. 물리→논리 배선은
`board/hal/smk37_map.h` (`SMK37_SLOT_OF[]`); HARDWARE CALIBRATION(부팅 시 패드 8+9 동시
누름)은 업스트림처럼 슬롯 위 라벨 순열을 학습합니다.

SMK-37 Pro에는 **TRS MIDI IN 잭이 없습니다**(OUT만). 따라서 빌드 기본값
`FELUCCA_UART=0`; `board/hal/fm1_uart.h`는 향후 DIN 측 시퀀서 미러링을 위해 TRS OUT TX
경로를 제공합니다. FM-1의 인앱 업데이터는 FM-1 인스톨러의 와이어 프로토콜이므로 여기선
`FELUCCA_OTA=0`: 업데이트/롤백은 이 저장소 자체 경로(`tools/make_smk37_fwsc.py` +
`exact_ota`, 강제 복구는 `esp32c3-usbkey`)로 합니다.

## 패드: 스위치 색상

스위치로 쓰는 각 패드는 자기 색을 갖습니다. LCD 팔레트에서 가져옴 (`board/hal/smk37_pad_rgb.h`):

| 패드 | 스위치 | 색 | | 패드 | 스위치 | 색 |
|---|---|---|---|---|---|---|
| 1 | FX | 보라 | | 6 | HOME | 흰색 |
| 2 | ENV | 청록 | | 7 | SAVE | 분홍 |
| 3 | LFO | 초록 | | 8 | OCT− | 파랑 |
| 4 | EDIT | 노랑 | | 9 | OCT+ | 라임 |
| 5 | GLO | 주황 | | 10–16 | 없음 | 꺼짐 |

밝기는 코어가 이미 계산하는 LED 상태를 따릅니다: 켜짐 = 전체 색, 흐림(레이어 랜드마크, 드럼 고스트/하드) = 1/4,
LIGHTS 백라이트 ≈ 1/10, 꺼짐 = 어두움. 색은 매 스캔마다 계산합니다 (셀 9개 읽기).

**아직 패드에 나오지 않음:** 패드 RGB 프로토콜이 해독되지 않았습니다 (`board/hal/smk37_pad_hw.h`, `SMK37_PAD_HW_NONE`).
백엔드가 검증되기 전까지 패드는 매트릭스 LED 라인(`SMK37_LEDMAP`, 역시 미검증)만 보여줍니다.
실제 색을 내려면 패드 LED 라인을 로직 애널라이저로 읽기 전용 캡처 1회가 필요합니다 (`docs/gap-analysis.md` §4).

## 이 빌드가 하지 않는 것

이 빌드는 의도적으로 RAM 전용이며 앱 내 업데이터가 없습니다
(`FELUCCA_FLASH=0 FELUCCA_OTA=0`, `docs/gap-analysis.md` §1, §3). FM-1의 저장 맵이 이 보드의 앱 슬롯 안에 있어서,
설정이나 프로젝트를 저장하면 실행 중인 코드를 덮어쓸 수 있습니다. FM-1 대비 빠진 것: 전원을 꺼도 유지되는
설정·프로젝트·프리셋·자동저장, 웹 에디터 프로토콜, 사용자 샘플, 앱 내 업데이트, USB 레스큐.
전체 목록과 소유자가 정해야 할 미결 사항은 `docs/gap-analysis.md`에 있습니다.

## 구성

```
sloop-smk37/
├── SLOOP_PIN               핀된 업스트림 커밋 (PROVENANCE.md)
├── board/
│   ├── hal/                SMK-37 Pro 보드 HAL (FM-1 보드 HAL을 섀도)
│   │   ├── smk37_board.h     핀맵 + 증거 라벨 ([DECODED]/[INFERRED]/[UNVERIFIED])
│   │   ├── smk37_map.h       순수 테이블: 스캔 매트릭스, LED 맵, 건반 창, 패드→슬롯 배선
│   │   ├── fm1_input.h       스캔 글루: 로/스트로브/SPI2 체인, 디바운스, quadrature, LED
│   │   ├── smk37_pad_rgb.h   패드 색상·밝기 (순수 함수, 호스트 테스트)
│   │   ├── smk37_pad_hw.h    패드 RGB 출력: 프로토콜 검증 전까지 NONE
│   │   ├── fm1_lcd_hw.h      SPI1 LCD, D/C = PB5, CS = PC8, 240x240 RGB565
│   │   ├── fm1_audio.h       ALNK0 -> CS4344 (PC0/1/2/6)
│   │   ├── fm1_adc.h         SARADC: 페이더, 휠, 페달, 배터리
│   │   └── fm1_uart.h        TRS MIDI OUT TX (이 보드는 IN 잭 없음)
│   └── src/panel.c         패널 테이블 + 설정 (업스트림 panel.c 대체)
├── tools/
│   ├── fetch_sloop.py      핀된 업스트림 트리 취득/검증
│   ├── build_smk37.py      BSP 오버레이 타깃 빌드 + 게이트 + 통과 기록(.check.json)
│   └── make_smk37_fwsc.py  app.bin을 v15 FWSC 컨테이너로 패키징 (exact_ota 경로)
├── tests/
│   ├── panel_smk37_test.c     보드 맵 + LED 맵 단위 테스트 (호스트)
│   ├── unity_syntax.sh        SLOOP 전체 unity TU를 이 HAL로 컴파일 (구문/타입)
│   ├── ui_pages_smk37_test.c  업스트림 라이브 UI 퍼즈를 이 패널로 컴파일
│   └── run_smk37_tests.sh
├── docs/port-evidence.md   모든 보드 상수와 그 출처
└── docs/gap-analysis.md    FM-1 대비 차이, 벽돌 검토, 미결 결정
```

칩 단위 HAL(GPIO 포트, TIMER4/5, IRQ/P33, SFC 플래시, USB0)은 FM-1과 같은 실리콘이라
업스트림 것을 그대로 씁니다. 오버레이는 include 경로에 `board/hal`, `board/src`를 앞에
두므로 `fm1_input.h`, `fm1_lcd_hw.h`, `fm1_audio.h`, `fm1_adc.h`, `fm1_uart.h`, `panel.c`만
포트 것이고 나머지는 업스트림 것입니다.

## 빌드와 테스트

```sh
# 호스트 테스트 (하드웨어 불필요): 보드 맵 + 이 패널로 돌리는 업스트림 UI 퍼즈
SLOOP_SRC=/path/to/sloop-fm1 tests/run_smk37_tests.sh     # 없으면 핀을 받아옴

# 타깃 이미지 (JieLi pi32v2 Linux 툴체인; non-x86_64에선 업스트림처럼 Docker)
JIELI_TOOLCHAIN=~/.jieli/toolchain tools/build_smk37.py

# SMK-37 Pro v15 OTA 컨테이너로 오프라인 패키징
tools/make_smk37_fwsc.py --app build/smk37-sloop.bin \
    --template /path/to/SMK-37_Pro_015.fwsc --output-dir build
```

`make_smk37_fwsc.py`는 엔트리 스텁 `04818000`으로 시작하지 않거나, v15 앱 슬롯을 넘거나,
SHA-256이 일치하는 `PASS` 빌드 기록(`build/smk37-sloop.check.json`)이 없는 이미지를 거부합니다
(기록은 `build_smk37.py`의 모든 게이트 통과 후에만 기록). 거부 시 종료코드 2, 아무것도 쓰지 않음.

`build_smk37.py`는 산출 전에 게이트합니다: `0x02000120`의 엔트리 스텁/`_start`,
`.ram_text` 내 call 없음, 이미지 ≤ v15 앱 슬롯 617,012 B, 그리고 2026-08-15 브릭 교훈
(RC-1) — **SDRAM 창 `0x04000000` 섹션 금지**, 확인된 RAM/XIP 창 밖 섹션 금지.

## 상태

- 2026-10-08: 포트 작성. 호스트 테스트 통과 (보드 맵; SMK-37 패널로 돌린 업스트림
  라이브 UI 퍼즈 — 20000 프레임 랜덤 사용 포함).
- 2026-10-09: 네트워크 단절 후 감사. 수정: 코어의 LED 조회가 스캔 키맵을 읽고 있었음 (잘못된
  LED, 건반 표시가 패드를 점등할 수 있었음) → `SMK37_LEDMAP` 추가 + 테스트. 호스트 UI 테스트가
  실제 HAL을 컴파일하지 않음을 발견 → `unity_syntax.sh` 추가 (SLOOP 전체 TU 구문 검사 통과).
  `make_smk37_fwsc.py`가 100 B 더미를 패키징하던 문제 → 게이트 통과 전 거부하도록 수정.
  `upstream/`은 git 무시.
- 보드 HAL 전기 상세는 증거 라벨을 유지. [INFERRED]/[UNVERIFIED] 항목(스캔 체인의 컬럼
  수, ADC 채널 순서, 백라이트 핀, 패드/LED 라인 맵, 패드 RGB 시리얼 경로)은 `docs/port-evidence.md` §2의
  브링업 체크리스트이며, 캘리브레이션이 닿는 부분은 실기기에서 재학습 가능.
- 2026-10-09 (2차, 패드·갭 검토): 스위치 9개의 패드 색 추가 (호스트 테스트 통과, 출력은 미검증).
  `FELUCCA_FLASH=1`이면 실행 중인 코드를 덮어쓸 수 있음을 발견 (FM-1 저장 맵이 SMK 앱 슬롯 안에 있음) →
  RAM 전용 빌드 + 링크 게이트. 패리티 갭(에디터, 영속성, 업데이터, 레스큐)은 `docs/gap-analysis.md`에 기록.
- 플래시/실기기 실행 안 함: 저장소의 실기기 무접촉 룰 유지.

## 라이선스

업스트림 SLOOP와 동일하게 GPL-3.0-only (`PROVENANCE.md`, 업스트림 `LICENSING.md` 참조).
업스트림 저작권은 원 보유자에게 있으며, 이 포트는 같은 라이선스 아래 보드 파일을 추가합니다.
