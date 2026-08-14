# 자체 복구 가능한 SDK 앱 — SMK OTA 서버 이식 설계

작성: 2026-08-14 · 상태: **프로토콜 명세 도출 완료, 구현 예정** (B1~B4)

## 1. 목적

"바닥부터" 플랫폼의 첫 플래시(P0c)를 **안전하게** 하기 위한 부트로더 기초.
SDK로 빌드한 앱 자체가 SMK OTA 서버를 구현해, 플래시 후에도 `exact_ota`로
언제든 S16(S1C6)로 복원할 수 있게 합니다. Jieli 강제 업그레이드 도구(4.0)와
esp32c3-usbkey(부트롬 강제 진입)는 최후 수단으로만 남깁니다.

## 2. 판정 근거 (왜 SDK 앱에 OTA 서버를 이식해야 하는가)

| 확인 항목 | 결과 |
|---|---|
| SMK 업데이트 모드(4d4a:4155)는 **v15 app 데이터에 구현** | `f0 22 24 35` SysEx·PID 4155·디스크립터 모두 app 영역 |
| SDK 스톡 `usb_update2.bin`은 SMK 프로토콜과 **불일치** | `00 59 30` 프레이밍 0건, `0xE0000000/0xF0000000` 0건, 4d4a/4155 디스크립터 0건 |
| M09 선례 | 앱 교체로 업데이트 진입 소실 → 복구에 부트롬 강제 진입(하드웨어) 필요 |

→ SDK 앱으로 교체하면 SMK 업데이트 모드가 사라지므로, **새 앱이 그 역할을
대체 구현**해야만 소프트웨어 경로로 복원이 가능합니다.

## 3. SMK OTA 프로토콜 명세 (S1C6 로그 + protocol.c에서 도출)

### 3.1 전송 계층

- USB: MIDI Streaming 인터페이스, bulk 엔드포인트 OUT 0x04 / IN 0x84
- USB-MIDI 패킷: 4바이트 (`code_index 0x04/0x05/0x06/0x07` + 데이터 3/1/2/3B)
- SysEx 프레이밍: `f0` … `f7` 로 감싸고 내부는 **8→7비트 패킹**
  (`smk37_frame_binary`/`smk37_usb_packetize` — `src/protocol.c`에 전부 공개)

### 3.2 요청/응답 패킷 (모두 `00 59 30` 헤더)

```
[0]=00 [1]=59 [2]=30 [3..5]=len+8 (LE24) [6]=flash_type
[7..10]=address (LE32) [11..13]=length (LE24)
[14..14+len-1]=data (응답만) [마지막]=complement checksum(byte6부터 len+8바이트)
```

- **요청 (장치→호스트)**: data 길이 0, 15바이트 — 읽을 flash 주소/길이를 요청
- **응답 (호스트→장치)**: `length+15`바이트, 요청 주소의 payload 데이터 포함

### 3.3 세션 흐름 (S1C6 트랜스크립트 1290 요청 분석)

**Stage-1 (48 요청 — 검증, 정상 앱이 수행):**
```
0x0000/512, 0x0200/512, 0x0400/512(×2), 0x4400/512, 0x0400/32, 0x0400/512, 0x4400/32
→ UFW 헤더(0x0..0x400) + JLFS 영역 헤더(0x4400=flash 0x4000) 구조 검증
0xa63a0 → 0xaafc0 (512B 청크, 마지막 481B) → payload 꼬리(0xa63a0..0xab1c0) 검증
→ 요청 0xE0000000/8 → 호스트 `success\0` 응답 → 업데이트 모드로 재인넘eration
```

**Stage-2 (1240 요청 — 쓰기, 업데이트 로더가 수행):**
```
payload 0x0..0x9C400 전 영역, 대부분 512B 청크 (32B×12, 16B×6, 10B×1)
매핑: payload[0x400+i] → flash[i]  (flash 0x0..0x9C000 전체 기록)
마지막에 0x4a00→0x4400 역순(JLFS 헤더 영역 = 커밋 포인트), 0x100/10B
→ 요청 0xF0000000/8 → `success\0` → 리부트
```

## 4. 구현 단계 (SDK 앱, `apps/demo/demo_hello` 변형)

| 단계 | 내용 | 검증 |
|---|---|---|
| **B1** | USB-MIDI 인넘eration: 4d4a:4155 + MIDI Streaming iface + ep 0x04/0x84 (업데이트 모드 디스크립터) | macOS에서 인넘eration 확인 |
| **B2** | MIDI 전송: 수신(unpacketize→7→8 언팩), 송신(패킹→프레임→packetize) | 호스트와 왕복 테스트 |
| **B3** | 세션 로직: 업그레이드 SysEx 수신 → stage-1(요청 시퀀스 + 검증) → 재인넘eration → stage-2(플래시 기록) → 리부트 | exact_ota로 S1C6 복원 왕복 |
| **B4** | 빌드 → fwsc 패킹(`tools/pack_sdk_app_fwsc.py`) → 오프라인 검증 | pack 게이트 |

검증 세부: stage-1 검증은 UFW 헤더 CRC + JLFS 구조 + 꼬리 지역 리드로 충분
(복원 대상이 검증된 S1C6 fwsc이므로 전체 CRC 재계산 불필요). flash 기록은
SDK update 라이브러리(CONFIG_UPDATA_ENABLE로 이미 링크됨)의 쓰기 API 사용.

## 5. 안전한 P0c 절차

1. **현재 상태 복원 자산** (준비 완료): `S1C6-reset-signature-isolation`의
   `SMK37Pro-v15-S1C6-reset-signature-isolation-S16-marked.fwsc` + `exact_ota.c`
   → 컴파일 → `check` 양성 확인 (S16 복원용)
2. **B 완료 후**: 자체 복구 SDK 앱을 fwsc로 패킹 → exact_ota로 플래시
   → 부팅 관측 → **즉시 exact_ota로 S1C6 복원 → 왕복 검증** (이게 안전망 실증)
3. 왕복 확인 후 실제 P0c 관측(앱 부팅 행동) 진행 — 이제 언제든 되돌아올 수 있음

## 6. 관련 문서/자료

- 프로토콜 호스트 측: `src/protocol.c`, `src/ota.c` (공개 구현 — 장치 측 미러 기준)
- 요청 로그: `logs/v15/ota-v15-s1c6-reset-sig-20260814.log` (1290 요청 전체)
- 분석 도구: `tools/analyze_ota_log.py`
- fwsc 패킹: `tools/pack_sdk_app_fwsc.py`
- 강제 복구(최후 수단): `docs/forced-recovery-plan.md`, `esp32c3-usbkey/`
