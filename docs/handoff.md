# SMK-37 Pro Mod — 핸드오프 문서

작성: 2026-08-14 · 이 문서는 이 저장소의 **진입점**입니다. 각 주제의 상세는 하단
"문서 맵"의 링크를 따라가세요.

## 1. 현재 상태 (한눈에)

| 항목 | 상태 |
|---|---|
| 장치 펌웨어 | **S1C6 (표시 마커 `S16`)** — flash + 실기기 live 검증 완료 (2026-08-14) |
| FM Drum Preset | **identity-safe 해제 완료** — requested map(36..51)을 explicit Playback Note로 전송 |
| 에디터 | GitHub Pages 배포 완료 — **실기기 Pad 연주까지 확인됨** |
| Release | `v15-s1c6-reset-signature-isolation` (공개) |
| 공개 저장소 | `main` 최신 (`07b134a`) |

핵심 한 줄: **"임의 Playback Note가 안전하지 않다"는 제약은 프로듀서 리셋
시그니처 결함이 원인이었고, S1C6 펌웨어로 분리·해소되어 FM Drum 키트의 의도한
드럼 맵(36..51)이 실기기에서 정상 동작합니다.**

## 2. 이번 작업의 목표와 결과

원래 목표: 임의 Playback Note를 안전하게 쓰기 위한 펌웨어 변경 연구 →
가능해지면 FM Drum preset의 identity-safe 제한 해제.

| 단계 | 내용 | 결과 |
|---|---|---|
| Phase 0 | FM kit explicit-playback 실기기 테스트 (S1C5) | FAIL — 루트 원인 추적 |
| 루트 원인 | 직접 USB 대조로 byte 161 가설 반증 | **리셋 시그니처 콜리전 확정** |
| Phase 1 | S1C6(S16) 리셋 검출 분리 펌웨어 | flash + 재로드 회귀 live PASS |
| Phase 2 | 에디터 identity-safe 해제 (explicit playback) | 배포 + 실기기 확인 |
| Phase 3 | Release | `v15-s1c6-reset-signature-isolation` |

## 3. 기술 핵심 (다음 작업자가 반드시 알아야 할 것)

### byte 161의 이중 역할

163바이트 DX7 single-voice 패킷의 **byte 161**은 (1) Yamaha 체크섬 자리,
(2) SMK 전송 시 transport 바이트(S1C3 이전 `0x3F` / S1C4+ Playback Note
`0..127`), (3) firmware producer의 map source(`0x01c46f20 + slot`)를 겸합니다.

### 루트 원인: 프로듀서 리셋 시그니처 콜리전 (S1C5)

S1C5의 reset wrapper(`0x0201e228`)는 **모든 패킷**의 `stage[0..1] == 0x62 0x63`
(wire bytes 6..7 = 보이스 데이터 첫 2바이트)을 리셋 시그니처로 검사했습니다.
이 시그니처는 Bank D 슬롯0 보이스(BUZZ BASS)의 실제 음성 데이터에서 차용된
것으로, "첫 패킷이 리셋 겸 보이스"라는 설계 가정이었습니다.

- FM 키트의 **HITUN RIMS**(note 49 = 전송 slot 13 = 14번째 패킷)가 bytes 6..7
  = `62 63` → **중간 슬롯에서 리셋 발화** → count/state 클리어 → ARMED 미도달 →
  디폴트 복귀.
- Bank D가 성공한 것은 유일한 `62 63` 보이스(BUZZ BASS)가 **첫 패킷**이었기
  때문 — 운 좋게 동작한 것.
- 부차 결함: 슬롯0이 `62 63`이 아닌 키트(FM 키트 LONG TOM = `63 63`)는 적재된
  키트 위 재로드 불가 (count-full 게이트의 조용한 실패).

### S1C6 해결: 리셋 검출 분리

- **시그니처 교체**: `0x64 0x65` — payload bytes 0..1 = OP1 EG rates 1..2
  (DX7 범위 0..99)라 **구조적으로 불가능**. 번들 32개 스캔 0건.
- **명시적 리셋 패킷**: 리셋 매치 시 lock/count/state 클리어 → csync →
  **producer 미호출 반환** (리셋은 보이스가 아니며 슬롯을 소비하지 않음).
- **in-place 40B**: selector/producer core `0x0201e13e..0x0201e228`와 callsite
  byte-for-byte 보존 (M09 교훈: code cave 없음).
- 표시 마커: `S16` (**3자 버저닝 규칙** — 4자 `S1C5`는 화면에서 `S1C`로 잘려
  오독 사고가 있었음. `S` + 2자리, 번호 재사용 금지).

### 17패킷 전송 프로토콜 (S16 전용)

리셋 패킷 1개(`f0 43 00 00 01 1b 64 65 00…00 f7`, byte 161 = 0) + 보이스 16개
= **17개**. 전원 사이클 없이 적재된 키트 위 재로드 가능. 에디터 `sendAll`은
리셋 선행, 100ms 간격.

> ⚠️ **S1C5 이하에서는 17패킷 프로토콜이 동작하지 않습니다** (리셋 패킷이
> 보이스로 오인됨). 에디터의 리셋 선행 전송은 S16 전용.

### FM Drum 전송 byte 161 (실기기 검증 순열)

전송 순서(note 36..51)에서 byte 161은 pad 순 요청 맵의 순열:
`[44,45,46,47,36,37,38,39,48,49,50,51,40,41,42,43]` — 직접 USB·에디터 경로
모두 이 값으로 실기기 검증 완료.

### 휘발성 RAM

16-slot 패치 세트는 **volatile RAM transaction**입니다. 재부팅·펌웨어 업데이트
후 재전송 필요 (영속화 경로 S1C7~S1C9 모두 분석으로 차단됨 — 미해결).

## 4. 문서 맵

| 문서 | 내용 |
|---|---|
| [`docs/playback-note-safety-plan.md`](playback-note-safety-plan.md) | 연구·계획·Phase 0~3 전체 기록 (루트 원인, 설계, 검증) |
| [`docs/v15-s1c-status.md`](v15-s1c-status.md) | S1C 시리즈 펌웨어 타임라인·현재 설치 |
| [`docs/firmware-versioning.md`](firmware-versioning.md) | 버저닝 규칙 (3자 체계) |
| [`patch-set-editor/docs/HANDOFF.md`](../patch-set-editor/docs/HANDOFF.md) | 에디터 핸드오프 |
| [`patch-set-editor/docs/PROTOCOL.md`](../patch-set-editor/docs/PROTOCOL.md) | SysEx/전송 프로토콜 |
| [`patch-set-editor/docs/DEPLOY.md`](../patch-set-editor/docs/DEPLOY.md) | Pages 배포 |
| [`README.md`](../README.md) | 저장소 개요 |

## 5. 산출물 위치

| 항목 | 위치 |
|---|---|
| S1C6 펌웨어 빌드·아티팩트 (워크스페이스 전용, release에만 공개) | `baselines/v15/analysis/flash-candidates/S1C6-reset-signature-isolation/` |
| Release (fwsc + app.bin + manifests + OTA 로그 + SHA256SUMS) | `v15-s1c6-reset-signature-isolation` |
| 에디터 (Pages) | https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/ |
| S1C6 OTA token | `INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93` |
| S1C6 fwsc SHA-256 | `fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886` |
| S1C6 app SHA-256 | `312790c080f6fcead69eccd84edf2c608ef3fa7e772455d781ab086dafed44b1` |

## 6. 운영

### S1C6 OTA (exact_ota)

```
# 워크스페이스 src + fwsc/protocol/device_info/flash_read/sha256 포함 컴파일
cc -O2 -std=c11 exact_ota.c src/ota.c src/fwsc.c src/sha256.c src/protocol.c \
   src/device_info.c src/flash_read.c $(pkg-config --cflags --libs libusb-1.0)

exact_ota check <fwsc>                                   # 양성 PASS + 타 버전 REJECT
exact_ota upload <fwsc> <transcript.log> --confirm <token>  # 플래시 중 USB 분리 금지
```

주의: macOS에서 MIDIServer(CoreMIDI)가 인터페이스를 점유하면 claim이 실패 —
`killall MIDIServer` 후 재시도. 플래시 후 5초 대기 중 MIDIServer가 다시
점유하면 post-update identity 확인이 실패로 보일 수 있음(플래시 자체는 정상).

### 에디터 재전송

장치 재부팅 후 에디터에서 "16개 Patch 전송"(리셋 1 + 16, S16 전용). Web MIDI
세션이 끊기면(예: MIDIServer 재시작) 브라우저 탭을 새로 열어 재연결.

### Pages 재배포

`main` push 시 GitHub Actions(`deploy-pages.yml`)가 자동 배포. 에디터 코드를
바꾸면 `index.html`의 `app.js?v=...` 캐시버스트를 반드시 갱신.

## 7. 남은 작업 / 알려진 제약

1. **휘발성 RAM persistence 미해결** — 전원 사이클 후 재전송 필요 (S1C7~S1C9
   분석 차단, S2 unsafe). 원한다면 별도 연구 과제.
2. **중복 Playback Note cross-release** — 사용자가 중복 note를 쓸 경우 voice
   identity가 note 기반이라 근본 한계 (Option D 문서화·보류).
3. **에디터 펌웨어 버전 가드 (제안)** — S16 전용 리셋 패킷을 S1C5 이하 장치에서
   보내지 않도록 장치 버전 확인 추가.
4. **페이지/문서의 identity-safe 잔여 문구** — 검색 시 과거 기록(Phase 0) 문구가
   남아 있음. 현재 상태는 위 §1이 기준.
5. **에디터 테스트는 로컬에서 14/14** — Pages 배포 workflow도 동일 테스트를
   실행해 배포를 게이트.

## 8. 타임라인 요약

| 날짜 | 사건 |
|---|---|
| 2026-08-04 | S1C5 flash + live 검증 (all-C4 PASS) |
| 2026-08-12 | Release `v15-s1c5-marked-playback` |
| 2026-08-13 | 임의 Playback Note 연구·계획 수립 |
| 2026-08-14 | Phase 0 실측 → **루트 원인 확정** (리셋 시그니처 콜리전) |
| 2026-08-14 | S1C6(S16) 구현·OTA·재로드 회귀 live PASS |
| 2026-08-14 | Phase 2 에디터 explicit playback 배포 + 실기기 Pad 확인 |
| 2026-08-14 | Release `v15-s1c6-reset-signature-isolation` |
