# v15 S1C 시리즈 현황

작성: 2026-08-13 (기준: 최근 성공 flash 2026-08-04)

## 2026-08-14 상태 갱신 — 정정: 장치는 S1C5 (표시 잘림 오독) · 버저닝 3자 전환

초기 "장치 = S1C1" 보고는 **잘못된 정보**였습니다. 표시 마커 `S1C5`의 마지막
글자가 잘려 `S1C`로만 보인 데서 비롯된 오독이며, 실제 장치는 **S1C5 (marked)**
(2026-08-04 설치 기록과 일치)입니다. S1C1은 마커 변경이 없는 boundary-only
빌드라 `S1C`가 표시될 수 없습니다.

**의미**:

- Phase 0 (2026-08-14) FM Drum 테스트 결과(identity-safe preset 실패 +
  explicit-playback 디폴트 복귀)는 **유효한 S1C5 실측 = FAIL**입니다.
  byte 161 = 36..51(trigger 범위)이 핵심 변수로 의심되며(all-C4 = 60은
  2026-08-04 live PASS), 상세는
  [`playback-note-safety-plan.md`](playback-note-safety-plan.md)
  "Phase 0 시도 기록" 참조.
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
| **S1C5** | **playback register return + marked variant** | **flash 성공 + verified (2026-08-04) — 현재 설치** |
| S1C6 | raw-record persistence 후보 | **blocked/refuted** (분석으로 차단) |
| S1C7 | current-set helper checkpoint | **live 실패** — root cause 문서화, S1C5로 복원 |
| S1C8 | manifest-gated persistence | **blocked** (one-shot writer 차단 분석) |
| S1C9 | min-budget persistence | **blocked** (예산 부족) |
| S2 | persistent default | **unsafe로 차단** (복원 배치 감사) |

## 현재 설치 펌웨어: S1-C5 Marked Playback Note

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

### 제약 (S1-C5 identity 결합)

S1-C4 시절 live 분석에서 packet byte 161이 trigger/transaction identity로
취급되어 임의 Playback Note에서 transaction이 붕괴하는 문제가 확인되었습니다.
S1-C5의 post-hook register reload 수정으로 all-C4(중복) 포함 임의 Playback
Note가 live 검증되었지만, **trigger 범위(36..51) 내 playback note의 voice-identity
상호작용은 아직 미검증**이므로 웹 에디터의 FM Drum preset은 identity-safe
(Original) 정책을 유지합니다.

임의 Playback Note 안전 사용 연구·해제 계획은
[`docs/playback-note-safety-plan.md`](playback-note-safety-plan.md)에 있습니다.

## 영속화(persistence) 미해결

S1C6~S1C9까지 적재된 16-slot 패치를 전원 사이클 후에도 유지하는 경로를
조사했지만 모두 차단되었습니다. 현재는 **휘발성 RAM 전용**이며 재부팅 후
재전송이 필요합니다. 웹 에디터가 이 전송을 담당합니다.
