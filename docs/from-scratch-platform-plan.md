# 바닥부터 플랫폼 재구축 계획 (SDK 기반)

작성: 2026-08-14 · 상태: **P0a PASS (SDK 빌드 완료, macOS+container+qemu)** — P0b(플래시)는 USB 접근 대기

## 1. 배경과 동기

기존 펌웨어 역분석 경로(패치 기반 수정)는 UI/LCD에서 벽에 부딪혔습니다:

- **최종 LCD/framebuffer write ABI 미해결** [PF-016] — ST7789 유사 시퀀스(0x02058aec)가
  실제 함수와 충돌해 확정 불가.
- **LED/UI/input/LCD/widget 매치 0건** [PF-017] — SDK의 `led_ui_server`와 v15 제품
  펌웨어 매치 없음.
- setter→callback→dirty→redraw→LCD write 전체 경로 미추적.

**바닥부터 접근**은 이 벽을 구조적으로 우회합니다: 드라이버를 우리가 직접 작성하므로
**framebuffer는 우리 소유**가 됩니다. 그리고 이 장치는 "문서화된 플랫폼"(Jieli AC791N +
공식 SDK/툴체인/문서)이어서, 막연한 재작성이 아니라 **지원되는 임베디드 SDK 위의 정상적인
브링업**입니다.

이 계획은 기존 S1C6/에디터 작업을 대체하지 않습니다. S1C6+에디터는 실용 경로로 유지하고,
이 경로는 병렬 플랫폼 트랙(야심적 방향)입니다.

## 2. 하드웨어 확인 사실 (증거 기반)

| 구성 | 확인 내용 | 근거 |
|---|---|---|
| SoC | **Jieli AC791N (내부명 WL82)**, pi32v2 듀얼코어 FP DSP 320MHz, 578KiB SRAM | `baselines/v15/analysis/public-research.md` §1 |
| 공식 SDK | `fw-AC79_AIoT_SDK` (Gitee, release/AC79NN_SDK_V1.2.0) — LCD·USB·UI·오디오 모듈 | public-research 소스 스냅샷 |
| 공식 문서 | doc.zh-jieli.com/AC79 — LCD 인터페이스, 모듈 예제 | research-notes LCD 절 |
| LCD | **ST7789V** — v15 초기화 테이블(`0x11,0x36,0x3A 0x05,0xB2…`)이 공식 `lcd_st7789v.c`와 일치, RGB565, ~240×240 | research-notes §LCD |
| USB | 표준 USB-MIDI MIDIStreaming, 2×64B bulk — v15 디스크립터 캡처 완료 | public-research §5 |
| 오디오 | 외부 **CS4344** (I2S) — ADC3/5는 제어용 ADC, 오디오 아님 | research-notes |
| 툴체인 | Jieli pi32v2 GCC (Windows CodeBlocks 기본, **Linux 경로 존재**) | 공식 문서 3장 |
| 커뮤니티 도구 | Quarkslab `ghidra-jieli`, `jl-misctools`, `jl-uboot-tool` | public-research |

## 3. 소유 자산 (이미 있는 것)

- **ddxx7 DX7 FM 엔진** (`github.com/acidsound/ddxx7`, `public/dx7-processor.js` 1012줄):
  6-op · 32 알고리즘 · 피드백 테이블 · LFO/엔벨로프/피치엔벨로프. **Web Audio 의존 0의 순수
  샘플 계산 엔진 + LUT 기반**(MCU 친화). `sysex.ts`가 155B VCED 파싱/내보내기까지 보유.
  → C 포팅은 기계적이며 **호스트에서 JS 레퍼런스와 샘플 대조 검증 가능**.
- 기존 분석 자산: 보이스/플래시 레이아웃, OTA 경로(exact_ota, 업데이트 모드 4d4a:4155),
  USB 디스크립터, SysEx 16-slot 프로토콜.
- `esp32c3-usbkey`: WL82 부트롬 강제 진입 복구 도구.
- 패치 기반 빌드 툴(smk37_v15_app_patch.py 등): 앱 전용 패치 + CRC 필드 처리 — **커스텀 앱
  플래싱 경로의 기반**.

## 4. 아키텍처 방향

- SDK 기반 앱. 플래시 레이아웃은 v15와 호환 유지: boot/레이아웃(0x00000000..0x4000)은
  보호 해시가 있는 영역이므로 **그대로 두고 app 영역(0x4000..)만 교체**.
- 런타임 매핑 0x02000000, 데이터 복사 + BSS 제로 부팅은 유지 (메모리 맵 증거).
- **플래싱**: 기존 OTA 경로(USB 업데이트 모드)를 재사용 가능한지가 P0 판정 항목 —
  Jieli 공식 다운로드 도구(Windows) 없이도 앱을 올릴 수 있으면 macOS 워크플로우가 완성됨.
- 롤백 안전: 현재 S1C6 fwsc + rollback 섹터 유지, 언제든 복원.
- 최종 형태: ST7789V framebuffer + USB-MIDI + ddxx7 FM(Ch10 드럼) + (장기) 시퀀서 UI.

## 5. 단계 (P0~P4)와 게이트

| 단계 | 내용 | 게이트(판정) | 난이도 |
|---|---|---|---|
| **P0** | 툴체인+SDK 브링업 | pi32v2 컴파일 → SDK demo 빌드 → **보드에서 hello world**(콘솔/GPIO). v15 링크맵(0x02000000)과 SDK 링크맵(0x02000120) 정합 확인 | 임계 경로 |
| **P1** | ST7789V framebuffer | SDK `lcd_st7789v` 드라이버로 테스트 패턴 표시. LCD 전기 버스(SPI?) 확정 | 중간 |
| **P2** | USB-MIDI 클래스 | macOS/에디터에서 USB-MIDI 인식, 노트 온/오프 왕복. (공개 SDK에 클래스 소스 없음 → 직접 구현, v15 디스크립터 참조) | 중간 |
| **P3** | ddxx7 FM 포팅 | 호스트에서 JS↔C 샘플 대조 → 장치에서 16노트 드럼 음 출력 | **낮음 (소유 자산)** |
| **P4** | 시퀀서 UI | framebuffer 위 UI + 패드 입력 + 시퀀스 재생 (타이밍/스케줄러 아키텍처) | 높음 (설계 필요) |

## 6. 리스크 / 미지

1. **툴체인 환경**: Windows 기본 → macOS에선 Linux VM/컨테이너 필요. pi32v2 GCC를 Linux에서
   빌드·실행할 수 있는지가 최우선 판정 항목.
2. **보드 하드웨어 상세**: 정확한 AC791N 변형/RAM 구성, LCD 전기 버스(FFC 10핀, SPI 여부),
   핀맵(키/엔코더/오디오/USB), 크리스탈. → 보드 사진·FPC 마킹·연속성 측정·부팅 커맨드 캡처
   (research-notes 체크리스트 참조).
3. **USB-MIDI 클래스 소스 부재**: 구현 필요 (표준 스펙 + v15 디스크립터로 충분).
4. **시퀀서 타이밍**: 장치의 인터럽트/스케줄러/오디오 콜백 구조는 아직 미분석 — P4에서 설계.
5. **16음 다성 CPU 예산**: LUT 기반 FM은 320MHz FP DSP에 여유 예상이지만 실측 필요.

## 7. 첫 단계 논의 (가장 먼저 해볼 것)

### 후보

- **A. P0 툴체인+SDK 브링업** — 방향의 임계 게이트. "이 칩에 자체 펌웨어를 올릴 수 있는가"를
  판정하는 최고 정보량 실험. 단, 환경 구축(리눅스 VM + Jieli 툴체인)이 선행돼야 하고
  첫 결과까지 시간이 걸릴 수 있음.
- **B. ddxx7 DSP → C 포팅** — **하드웨어 0 필요**, 오늘 바로 시작 가능. 호스트에서
  JS 레퍼런스와 샘플 대조로 검증 가능. P3 자산을 미리 완성하고 "가장 어렵다"던 부분을
  확실히 해제. 장치 없이도 진척이 보이는 안전 트랙.
- **C. 보드 하드웨어 조사** — P1(LCD) 전제. 카메라/루페 + 연속성 측정 필요. 하드웨어가
  준비됐을 때만 시작 가능.

### 권장 (2026-08-14 수정)

**첫 단계는 P0 하나입니다.** ddxx7 C 포팅은 "올릴 방법"이 확인되기 전에는 가치가
없습니다(플래시 불가능하면 공중의 작업). C 포팅은 P0 통과 뒤의 P3 자산으로만 의미가
있습니다.

P0을 세 갈래로 좁힙니다:

1. **P0a 빌드**: 리눅스 환경에 Jieli 툴체인+SDK → demo 타깃 빌드 성공 (컴파일 파이프라인 증명).
2. **P0b 플래시**: 빌드 결과물을 **기존 OTA/업데이트 모드 경로(exact_ota, 4d4a:4155)로
   장치에 쓰기** — 성공하면 macOS 워크플로우 완성. 실패 시 Jieli 공식 다운로드 도구
   (Windows)를 fallback으로 검토.
3. **P0c 관측**: 올린 앱이 관측 가능한 것. **첫 앱을 LCD 테스트 패턴으로 만들면
   빌드+플래시+LCD(P1)를 한 번에 증명**하는 최고 정보량 선택.

P0이 실패하면 이 방향 자체가 종료되므로, 그 전에는 C 포팅을 시작하지 않습니다.
C(보드 조사)는 가능한 만큼(사진/FPC 마킹) 병렬로 진행.

### P0a 결과 — **PASS (2026-08-14, macOS arm64)**

**결론: Jieli 툴체인 + AC79 SDK가 macOS(Apple container + qemu)에서 demo 타깃을 정상
빌드합니다.** `make ac791n_demo_demo_hello` clean rebuild → exit 0, 산출물:

- `sdk.elf` (1,024,432B) — CPU/wl82 링크 완료
- `app.bin` (119,748B) — .text+.data+.ram0_data+.cache_ram_data 연결 (플래시용)
- `symbol_tbl.txt`, `sdk.map`

**구성 (워크스페이스 `linux-build/`에 영속)**:

| 구성요소 | 비고 |
|---|---|
| `container` (Apple) | `smk-jieli-build` 컨테이너, `/build` ↔ `linux-build/` 바인드 마운트 |
| Jieli linux 툴체인 | `pkgman.jieliapp.com/s/linux-toolchain` (20250324.1, **x86-64 전용**) |
| `fw-AC79_AIoT_SDK` | GitHub 미러(jeffreywugz) `release/AC79NN_SDK_V1.0.3` |
| linux post-build | `pkgman.jieliapp.com/s/linux-postbuild` (isd_download/fw_add/ufw_maker…) |
| amd64 sysroot | `debootstrap` + libstdc++/libgcc (컨테이너 `/root/amd64-rootfs`) |

**핵심 트릭 — x86-64 툴체인을 arm64에서 실행**: qemu-user는 guest execve를 호스트에
그대로 통과시켜 **중첩 exec(x86-64→x86-64)가 ENOEXEC**로 깨집니다(clang driver→cc1,
LTO gold plugin→clang). 해결:

1. 툴체인 ELF를 `.bin`으로 옮기고 같은 이름의 **셸 스크립트 래퍼**(qemu 재진입)로 대체
   (`/opt/jieli/pi32v2/bin` — Makefile 경로 유지, lib/include는 실체로 심링크).
2. **LD_PRELOAD 셤** (`linux-build/exec-shim.c`, x86-64 크로스 컴파일): emulated
   프로세스가 `/opt/jieli/`의 `*.bin`을 exec/posix_spawn하면 스크립트 래퍼로 리다이렉트.
   LD_PRELOAD는 래퍼가 `-E`로 재주입 → 전 체인 커버.
3. `linux-build/download.sh` → SDK `cpu/wl82/tools/download.sh` (Linux post-build):
   objcopy 섹션 추출 → app.bin (isd_download 플래시 단계는 장치 세션에서만 별도 실행).

재현: `container exec smk-jieli-build bash -c 'ulimit -n 8192; cd /build/fw-AC79_AIoT_SDK
&& make ac791n_demo_demo_hello'`

### P0b 상태 — **② fwsc 재포장 경로로 확정 (2026-08-14) — OrbStack/호스트 센더 불필요**

**결정**: SDK 앱을 기존 SMK OTA 경로(exact_ota)로 플래시합니다. fwsc가 Jieli
표준 UFW 포맷이고 검증이 **CRC16 자체일관성(서명 없음)** 이라 임의 app 내용이
통과합니다 — S1C1~S1C6(변경 내용) 전부 stage-1 통과가 증거. 상세:
`baselines/v15/analysis/fwsc-repack-sdk-app/report.md`

- **pack 도구**: `tools/pack_sdk_app_fwsc.py` — SDK app.bin을 0xFF 패딩 후 v15
  UFW 템플릿에 치환(구조 불변, CRC만 재계산). demo_hello 실패키징 + 오프라인
  게이트(양성 PASS/음성 REJECT/재파싱/보호 해시 불변) 전부 통과.
  - 산출물: `SMK37Pro-v15-SDK-DEMO-HELLO.fwsc`, 토큰
    `INSTALL-SMK37PRO-V15-SDK-DEMO-HELLO-4D39EFE4`, 전용 `exact_ota.c`
- **다음(= P0c)**: exact_ota 컴파일 → 장치 업데이트 모드 → `upload --confirm …`
  → SDK 앱 부팅 관측. 복원 안전망: 보호 부트 불변 + S1C6 자산 + forced-loader.
- **버려진 대안**: OrbStack/UTM(USB 패스스루 VM)과 tonorflash 호스트 센더 재구현은
  불필요해짐. `isd_download`/`fw_add`/`ufw_maker`는 SDK 앱의 표준 업데이트
  패키징(update.ufw)이 필요해질 때(2차) 참고용으로 유지.

## 8. 관련 문서

- `baselines/v15/analysis/public-research.md` — SoC/SDK/USB/합성 리서치 베이스라인
- `docs/research-notes.md` — LCD/오디오/보드 미지 사항 체크리스트
- `docs/dx7-editor-interop-plan.md` — Dexed 연동(에디터 브리지) 설계
- `docs/handoff.md` — 전체 현황 진입점
- `docs/linux-build-flash-procedure.md` — Windows 도구 vs Linux 경로 대조 & 플래시 절차
