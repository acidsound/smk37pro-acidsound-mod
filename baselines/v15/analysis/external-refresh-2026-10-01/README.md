# 외부 자료 재조사 — 2026-10-01

기존 외부 조사의 마지막 기준은 `../public-research.md`(2026-08-01)와
`docs/research-notes.md`의 커뮤니티 스냅샷(커밋 `8f1bf111`, 2026-03-24)이다.
이 문서는 그 이후 **새로 확인된 외부 사실만** 기록한다. 외부 자료는 신뢰 경계
밖이므로 여기서는 "발견"까지만 주장하고, 우리 장치에서 검증된 것으로 승격하지
않는다.

## 0. 가장 중요한 것 — 펌웨어 16 (1.16)이 2026-08-12에 출시됐다

우리 프로젝트 전체(S1C 계보, 모든 OTA 패키지)가 **v15 = `SMK-37 Pro_015`** 에
SHA로 고정되어 있는데, 그 사이 **v16이 나왔고 우리는 그것을 baseline으로 삼은 적이
없다.** 커뮤니티 저장소에 2026-08-19 업로드됐다.

| 항목 | 값 |
|---|---|
| 파일 | `firmware/smk37pro/SMK-37_Pro_016.fwsc` |
| 크기 | **705,252 B** (v15: 701,140 B) |
| SHA-256 | `2d98ce72530e71d617384963423820536f094501299e2cfec0a8d3c3fb6bcfb0` |
| 추출한 flash.bin SHA-256 | `e524920a5e5dc4b3…` (v15: `f77e9ab3cee79113…`) |
| 동반 변형 | Elite / MKE-P37 / Starrykey 37 Play 016 동시 출시 |

출처: <https://github.com/jonathaslacerda/smk-37-pro-docs/blob/main/firmware/FIRMWARE.md>

> **2026-10-08 정정**: 위 표의 "추출한 flash.bin SHA-256 `e524920a…`"는 **잘못된 추출 결과**로 판명되었다.
> v16은 **36블록** interleave인데 20블록을 가정해 추출한 것(마커 16바이트 혼입 + `0x9C000` 절단)이었다.
> 올바른 v16 flash.bin: **643,072 B (`0x9D000`)**, SHA-256
> `5fa98871641617e08495086b57b4cf3257d31c60906dfb109d0453df59bb1540`.
> app.bin 추출 자체는 정확했다 (app SHA-256 `0f64fbf6ffc454eea686d78cf89f35e593229765bdcf166f10a8bd714abcb09a`).
> 근거와 재현: `external-research/REVIEW-2026-10-08-amalahama-smk37-firmware-custom-mod.md`.

**1.16 변경 내역 (커뮤니티 기재):**

- Chord Recognition Expansion
- Tempo — 불안정 템포 문제 해결
- MIDI — 건반 note 전송 지연 문제 해결
- Transpose — oct −3에서 transpose를 −12까지 내려 note 0 도달
- **Globe — USB Rec 기능 추가. audio input을 output에 믹스하는 옵션**
- **Patch — Local Control 기능 추가. FM 음원에 대한 로컬 MIDI 제어를 끌 수 있음**
- Pitch — center point를 64로 변경

**우리 프로젝트에 대한 함의(중요):**

1. **S1C 계보 전체가 무효화될 수 있다.** 모든 후보 패키지와 `exact_ota`
   래퍼는 v15 앱 SHA `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
   에 고정되어 있다. 장치가 1.16으로 올라가면 그 패키지들은 **거부**된다.
2. **벤더가 우리가 만들려던 기능을 일부 이미 넣었다.** "Local Control(FM 음원
   로컬 제어 차단)"은 우리 멀티팀브럴/채널 분리 연구의 목표와 직접 겹친다.
   **v16은 "어떻게 하는지"에 대한 벤더의 실제 답을 담은 표본**이다.
3. **v15→v16 diff는 G-03/G-04/G-07의 지름길일 수 있다.** 같은 엔진에 기능이
   추가된 두 빌드가 있으면, 코드/데이터 차이로 FM 엔진·UI·USB 경로의 소유자를
   좁힐 수 있다. 지금까지 없던 대조 기준이다.
4. USB Rec 추가는 USB 경로(디스크립터/엔드포인트) 변경을 동반했을 가능성이 있다.

**보관**: `build/SMK-37_Pro_016.fwsc` (SHA-256 위와 동일). v12/v15와 같은 위치.

## 1. 커뮤니티 저장소에 새 커밋 10개 (2026-03-24 → 2026-09-28)

우리 스냅샷 `8f1bf111`(2026-03-24) 이후:

| 날짜 | 내용 |
|---|---|
| 2026-08-19 | 4개 변형 **016 펌웨어 업로드** + `firmware/FIRMWARE.md` 갱신 |
| 2026-09-03 | README 갱신 |
| 2026-09-28 | README 갱신 ×3 |

README에서 확인된 변경: SoC 표기가
`~~SoC JieLi C108221-11B8~~` → **`SoC JieLi AC7911B8`**(EdCo 인용)로 정정됐고,
kagaimiq 칩 DB와 별도 datasheet 링크가 추가됐다. 우리의 G-01 판정(마킹
`C108221-11B8` ↔ AC7911B8, 8 Mbit Flash)과 **방향이 일치**한다.

## 2. 새 외부 자원

### 2.1 SSTIC 2026 — Pi32v2 SLEIGH 개선 (2026-06-04)

Damien Cauquil(Quarkslab, `virtualabs`), "Rétro-ingénierie d'un micrologiciel pour
architecture Pi32v2" — JieLi **AC6958** 스마트워치 대상.

- 발표: <https://www.sstic.org/2026/presentation/retro-ingenierie-micrologiciel-pi32v2/>
- 논문 PDF: <https://www.sstic.org/media/SSTIC2026/SSTIC-actes/retro-ingenierie-micrologiciel-pi32v2/SSTIC2026-Article-retro-ingenierie-micrologiciel-pi32v2-cauquil.pdf>
- **SLEIGH 구현 저장소: <https://github.com/virtualabs/ghidra-jieli>** (논문에서 인용)

내용: 누락 명령 식별 → 인코딩 해석 → 불완전한 SLEIGH에 추가, 고급 SLEIGH 기법.
**다만 저장소 최신 커밋은 2025-05-29**이고, 우리가 이미 쓰는
`quarkslab/ghidra-jieli`(단일 커밋 `e1bd0707`, 2026-03-09)와 계보가 겹칠
가능성이 높다. 즉 **"더 나은 디코더가 새로 생겼다"기보다는, 우리가 쓰는 디코더의
출처/방법론 문헌이 공개된 것**으로 보는 것이 정확하다. 우리 `quarkslab` 대
`kagaimiq+patch` 비교는 이미 수행했고 quarkslab이 압도적으로 우세했다.
→ **조치는 "방법론 참고 + 가끔 upstream 확인"이지, 디코더 교체가 아니다.**

### 2.2 ElectronicCats — JieLi 배지 RE (AC707N/BR35)

<https://github.com/ElectronicCats/jieli-ble-badge-research>

- **`tools/ufw-repack/dump2ufw.py`**: byte-exact 덤프를 **플래시 가능한 .ufw로
  재포장**. 우리 `docs/flash-layout-cipher-analysis.md`의 "가드 복원"이
  *덤프 파일*까지만 만드는 것과 달리, 그 다음 단계(다시 쓸 수 있는 이미지)를 한다.
- `tools/chipkey/` + vendored `jltech`(cipher/CRC/chipkey codec, jl-misctools에서
  역공학). 그들 장치의 chipkey는 **`0x9847`** — 우리 `CHIP_KEY = 0x980F`와 같은
  `0x98xx` 계열이다. chipkey가 PID/부품별로 달라진다는 서술은 우리가 미해결로
  남긴 JLFS 헤더 키(`0x132b`) 문제에 참고가 된다.
- **독립적으로 같은 브릭 기제를 보고했다**: *"A raw SDK `make` image carries the
  native uboot instead, which cannot do that rewrite — flash one and the badge
  bricks silently at apply."* 반면 **OEM .ufw에 app.bin만 이식하고 OEM uboot를
  byte-identical로 유지**하면 정상 동작한다.
  → 우리 2026-08-15 사고("SDK 앱을 그대로 구워 넣음")와 **동일한 실패 클래스**이며,
  우리가 세운 규칙(R1~R6, 링크 맵 게이트)과 독립적으로 일치한다.

### 2.3 공식 AC7911B8 Datasheet V1.1

<https://www.zh-jieli.com/upload/202204/AC791XN-datasheet/AC7911B8_Datasheet_V1.1.pdf>
— 우리 로컬 사본은 V1.0(SDK 동봉). V1.1에서 부품 번호 메모리 코드 표가 바뀌었는지
확인 가치가 있다(G-01 근거 보강).

## 3. 시도했지만 결론이 안 난 것 — 016 앱 디코드

v15 디코더 경로는 **검증됐다**: 패키지 `flash.bin`의 `0x4120`부터 617,012 B에
SFC cipher(`CHIP_KEY=0x980F`, base `0x4000`)를 적용하면
`build/v15-official-app.bin`과 **byte-identical**(`36fe8299…`)이 나온다.

그러나 **같은 가정을 016에 적용하면 앱이 나오지 않는다.** 관측:

- 016의 JLFS 헤더 영역(`0x4000`)은 015와 달리 **앞부분 16바이트가 `0xFF`** 이고,
  그 뒤로 015와 **긴 동일 구간**이 이어진다 → 구조가 시프트됐거나 엔트리가 바뀌었다.
- 알려진 진입 바이트(`04 81 80 00 ee ff d4 a2`)를 전제로 (시작 오프셋 × 16-bit
  키) 전수 탐색을 했으나 **해 0개**.

**이것은 "016 키가 다르다"는 증거가 아니라, "016 앱의 시작 바이트가 v15와 다르다"는
관측**이다. 즉 016은 v15와 같은 방식으로 디코드되지 않으며, **016 전용 레이아웃/키
분석이 별도로 필요**하다. (앱 영역이 ciphertext라는 점은 015와 동일: 양쪽 모두
의미 있는 ASCII 문자열이 없다.)

## 4. 다음 단계 제안

1. **016 레이아웃 복원** — JLFS `app_area_head`/`app.bin` 엔트리를 016 기준으로
   재해석하고 앱 이미지를 얻는다. 그러면 **015↔016 앱 diff**가 가능해진다.
2. 그 diff로 **"Local Control"/"USB Rec"/Chord 구현 위치**를 찾는다 → G-03/G-04/G-07
   및 멀티팀브럴 설계에 직접 투입.
3. `dump2ufw.py` 검토 — 우리 가드 복원 산출물을 **플래시 가능한 이미지로 만드는
   경로**가 실제로 성립하는지(RS-232/RCSP가 아닌 SMK USB-MIDI OTA에 맞는지) 확인.
4. `virtualabs/ghidra-jieli`와 우리 `quarkslab` 핀의 관계 확인(포크인지, 상류인지).
5. V1.1 데이터시트의 부품 번호 표 대조.

## 5. 명시적 비주장 (non-claims)

- 이 문서의 외부 자료는 **우리 장치에서 검증되지 않았다.** 특히 1.16 변경 내역은
   커뮤니티 기재이며 우리가 실기로 확인한 것이 아니다.
- 펌웨어 016 패키지의 **설치를 권고하지 않는다.** v15 기반 복구 자산과 S1C 계보가
  전부 무효화되며, 016용 복구·복원 자산은 아직 없다.
- `2d98ce72…` / `e524920a…`는 **다운로드한 파일의 해시**이며, 벤더 서명 검증이
  아니다.
- 016 앱 디코드 실패를 "016이 위험하다"는 결론으로 확장하지 않는다. 단지 우리
  도구가 아직 016을 읽지 못한다는 뜻이다.
