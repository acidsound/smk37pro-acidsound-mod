# v15 S1C 시리즈 현황

작성: 2026-08-13 (기준: 최근 성공 flash 2026-08-04)

## 2026-08-14 상태 갱신 — S1C6(S16) 실기기 검증 PASS (Phase 1 완료)

**Phase 1(R-B) 펌웨어 S1C6을 실기기에 OTA + live 검증 완료**했습니다. 표시
마커는 `S16`(3자 버저닝 규칙 적용). FM Drum 로드 실패의 루트 원인인 프로듀서
리셋 시그니처 콜리전을, 구조적 불가능 시그니처(`0x64 0x65`) + 명시적 리셋
패킷(리셋 패킷은 보이스로 적재하지 않음)으로 분리했습니다.

- **OTA**: exact_ota `check`(양성 PASS + S1C5 음성 REJECT) → `upload …
  --confirm INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93` 성공. stage-1 검증
  요청 1290개 완주(08-04 패턴과 동일) + completion ack, 장치 정상 모드 복귀
  (identity `SMK-37 Pro_015` 응답).
- **재로드 회귀**: 직접 USB로 (1) all-C4 17패킷(리셋+16, byte 161=60) → (2)
  **전원 사이클 없이** FM 키트 17패킷(리셋+16, byte 161=requested 36..51)
  재전송, 에러 0 → **FM 키트 재로드 성공**.
- **requested map live 검증**: Pad 1–16 전부 의도한 드럼 음색으로 소리남
  (HITUN RIMS `62 63`·LONG TOM `63 63` 충돌 보이스 포함). 표시 `S16` 확인.
- 에디터 `RESET_PACKET`(wire 6..7=`64 65`, byte 161=0)은 live 검증 패킷과
  바이트 동일, `sendAll`은 리셋 선행 17패킷(테스트 14/14).
- **Phase 2 (identity-safe 해제) 완료 (2026-08-14)**: FM Drum manifest
  `playbackNote` = requested map(36..51) 복원, format
  `smk37-v15-s1c6-explicit-playback-fm-drum-preset-v1` 승격, 샘플 patch-set
  JSON 재생성, 테스트 14/14. 에디터 main push 시 Pages 자동 재배포.

## 2026-08-14 상태 갱신 — 정정: 장치는 S1C5 (표시 잘림 오독) · 버저닝 3자 전환

초기 "장치 = S1C1" 보고는 **잘못된 정보**였습니다. 표시 마커 `S1C5`의 마지막
글자가 잘려 `S1C`로만 보인 데서 비롯된 오독이며, 실제 장치는 **S1C5 (marked)**
(2026-08-04 설치 기록과 일치)입니다. S1C1은 마커 변경이 없는 boundary-only
빌드라 `S1C`가 표시될 수 없습니다.

**의미**:

- Phase 0 (2026-08-14) FM Drum 테스트 결과는 **유효한 S1C5 실측 = FAIL**이며
  **루트 원인이 확정**됐습니다: byte 161 값(36..51 vs 60)은 **무관** — 직접
  USB로 둘 다 로드 성공. 실패 원인은 프로듀서 reset wrapper의
  `stage[0..1] == 0x62 0x63` 검사가 FM 키트의 HITUN RIMS 보이스 데이터
  (bytes 6..7)와 충돌해, 전송 slot 13에서 리셋이 발화하며 트랜잭션이
  소거되기 때문입니다. 상세는
  [`playback-note-safety-plan.md`](playback-note-safety-plan.md) §0 참조.
- **버저닝 3자 전환**: 4자 마커가 표시에서 잘리는 문제(M-시리즈 `M001`→`M00`
  교훈의 반복)를 방지하기 위해, 이후 표시 마커는 **정확히 3자**(`S` + 2자리,
  S1C5 → `S15`, 다음 빌드 `S16`…)로 통일합니다. 현재 설치된 S1C5의 마커
  (`S1C5`, 표시 `S1C`)는 유지합니다.

## 배경

공식 v15(`SMK-37 Pro_015`) 기준선 위에서 16-slot 패치 적재(Playback Note) 기능을
구현한 후보 시리즈. 각 후보는 `baselines/v15/analysis/flash-candidates/`에
offline 검증(validate.py), exact-OTA 컴파일, rollback sector, live transcript로
보존되어 있습니다. 상세 증거는 로컬 워크스페이스의 `baselines/`에 있으며, 이
저장소에는 요약만 기록합니다.

## 타임라인

| 단계 | 내용 | 상태 |
|---|---|---|
| H0 | heap-only app (메모리 경계 확인) | flash 성공 (2026-08-02) |
| H1 | producer-unconsumed 실험 | flash 성공 |
| H2 | owned-source corrected fallback | flash 성공 |
| R01 | hand-drum live | flash 성공 (2026-08-02) |
| R01b | buzz-bass | flash 성공 |
| R01c | mooger1 | flash 성공 |
| R01d | ram-mooger1 | flash 성공 |
| R02 | SysEx staging | flash 성공 |
| R03 | fixed-prefix | flash 성공 (재부팅 후 정상) |
| S1C1 | boundary-only 16-slot 적재 경계 확인 | flash 성공 |
| S1C2 | two-slot selector live | flash 성공 (v2까지 검증) |
| S1C3 | 16-slot functional (reset-aware, restage-paced) | **flash 성공** (2026-08-03) |
| S1C4 | playback-note v1/v2(failclosed)/v3-segmented | v3-segmented-final **flash 성공** (2026-08-04) |
| S1C5 | playback register return + marked variant | flash 성공 + verified (2026-08-04) |
| **S1C6** | **reset signature isolation (표시 S16)** | **flash 성공 + live 검증 PASS (2026-08-14) — 현재 설치** |
| S1C6 | raw-record persistence 후보 | **blocked/refuted** (분석으로 차단) |
| S1C7 | current-set helper checkpoint | **live 실패** — root cause 문서화, S1C5로 복원 |
| S1C8 | manifest-gated persistence | **blocked** (one-shot writer 차단 분석) |
| S1C9 | min-budget persistence | **blocked** (예산 부족) |
| S2 | persistent default | **unsafe로 차단** (복원 배치 감사) |

## 현재 설치 펌웨어: S1C6 (S16) — Reset Signature Isolation

- FWSC SHA-256: `fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886`
- OTA token: `INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93`
- 기반: S1C5-marked (playback register return 보존) + reset wrapper tail 재작성
  (selector/producer core `0x0201e13e..0x0201e228` byte-for-byte 보존)
- 표시 마커: `S16` (3자 버저닝)
- Live 결과: 2026-08-14 OTA 완료 + 재로드 회귀 PASS (all-C4 → FM 키트 재로드,
  전원 사이클 없음) + FM requested map(36..51) 16음 드럼 음색 확인
- 호스트: 에디터 `sendAll`이 리셋 패킷 1개 + 보이스 16개 = 17개 전송 (S16 전용)

### 이전 설치: S1-C5 Marked Playback Note (2026-08-14 S1C6으로 교체)

- FWSC SHA-256: `cfafa3273ca0ba741616e5f3aa87f262a45ecd84445bdefd969900dad256b480`
- App SHA-256: `c8dd9e9e19369a65fd46fb48aabc69a2af7977a456f4152e77cd90a742f7cfe5`
- 기반: S1-C4 v3 segmented-final (producer/selector 보존)
- OTA token: `INSTALL-SMK37PRO-V15-S1C5-MARKED-PLAYBACK-CFAFA327`
- Live 결과: 2026-08-04 OTA 완료, `post-update=SMK-37 Pro_015 verified`

### 기능 요약

- 16개 Pad 각각에 DX7 single-voice SysEx 적재 (volatile RAM 16-slot transaction).
- 각 패킷 byte 161에 Playback Note(`0..127`) 인코딩 — 내부 Ch10 신스 발음 음높이.
- Note Off는 `[r0]`→`r5`, Note On은 `[r0]`→`r6` reload window (post-hook), stock
  velocity store 보존.
- Trigger Note(물리 Pad 식별) 불변. 중복 Playback Note(C4 등) 허용이 packet
  artifacts로 증명됨.

### 제약 (루트 원인: 프로듀서 리셋 시그니처 콜리전)

**2026-08-14 확정**: identity-safe를 유지하던 실질 이유(byte 161 = 36..51이
트랜잭션을 붕괴)는 **반증**됐습니다. 직접 USB 대조로 byte 161 값과 무관하게
Bank D(36..51)와 all-C4(60) 모두 로드 성공했고, FM 키트만 실패했습니다.

실패 원인은 reset wrapper(`0x0201e228`)가 **모든 패킷**의 `stage[0..1] ==
0x62 0x63`(wire bytes 6..7 = 보이스 데이터 첫 2바이트)을 리셋 시그니처로
검사하는 것인데, 이 시그니처는 Bank D 슬롯0 보이스(BUZZ BASS)의 실제 음성
데이터에서 차용된 것입니다. FM 키트의 **HITUN RIMS**(note 49 → 전송 slot 13 =
14번째 패킷)가 bytes 6..7 = `62 63`이라 중간 슬롯에서 리셋이 발화해
count/state가 클리어되고, ARMED(count 16)에 도달하지 못해 디폴트로 복귀합니다.
Bank D가 성공한 것은 유일한 `62 63` 보이스(BUZZ BASS, note 36)가 첫 패킷이었기
때문입니다.

→ FM Drum preset identity-safe 해제(임의 Playback Note)의 전제는
**리셋 검출을 음성 데이터와 분리하는 펌웨어 수정**(S1C6/S16, 옵션 R-B: 명시적
리셋 패킷 + 구조적 불가능 시그니처)입니다. byte 161은 이미 자유입니다.

임의 Playback Note 안전 사용 연구·해제 계획은
[`docs/playback-note-safety-plan.md`](playback-note-safety-plan.md)에 있습니다.

## 영속화(persistence) 미해결

S1C6~S1C9까지 적재된 16-slot 패치를 전원 사이클 후에도 유지하는 경로를
조사했지만 모두 차단되었습니다. 현재는 **휘발성 RAM 전용**이며 재부팅 후
재전송이 필요합니다. 웹 에디터가 이 전송을 담당합니다.
