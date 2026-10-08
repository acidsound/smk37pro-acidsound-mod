# FM Drum identity-safe 해제 — Phase 0 실기기 테스트

목적: **펌웨어 변경 없이** FM Drum preset의 requested map(36..51)을 explicit
Playback Note로 적용했을 때 현재 설치된 S1C5에서 안전한지 실측합니다.
계획: `docs/playback-note-safety-plan.md`.

## 사용법

1. SMK-37 Pro 전원 확인 — 표시 마커가 4자(`S1C5`)면 마지막 글자가 잘려 `S1C`로만
   보이므로 버전은 OTA 로그·문서 기준으로 확인 (장치는 S1C5 marked).
2. [Patch Set Editor](http://127.0.0.1:3737) 또는 GitHub Pages 버전에서
   **Set 가져오기** → `FM-Drum-Kit.explicit-playback.smkpatchset.json`.
3. Web MIDI 연결 → **16개 Patch 전송**.
4. Pad 1–16 연주 확인.

## 확인 항목

- 16음 모두 의도한 드럼 음색·음높이로 소리나는가
- 동시 발음 pad 간 cross-release / voice steal 없음
- 반복 연타 stuck note 없음
- 한 pad의 Note Off가 다른 pad의 음을 죽이지 않음

## 판정 기록

| 날짜 | 장치 상태 | 결과 | 비고 |
|---|---|---|---|
| 2026-08-14 | **S1C5** (marked) | **FAIL — 루트 원인 확정** | identity-safe preset 실패 + explicit-playback 로드 후 디폴트 복귀. 대조 결과: byte 161 값(36..51 vs 60)은 무관 (직접 USB로 둘 다 로드 성공). **원인 = 프로듀서 reset wrapper의 `stage[0..1] == 62 63` 검사가 HITUN RIMS 보이스 데이터(bytes 6..7)와 충돌** — 전송 slot 13(14번째)에서 리셋 발화 → 트랜잭션 소거 → ARMED 미도달 → 디폴트. 상세: `docs/playback-note-safety-plan.md` §0 |
| 2026-08-14 | **S1C6 (S16)** | **PASS — 재로드 회귀 + requested map 전부 확인** | S1C6 OTA 성공(stage-1 1290요청 완주 + completion ack, 표시 `S16`). 직접 USB로 (1) all-C4 17패킷(리셋+16, byte 161=60) → (2) **전원 사이클 없이** FM 키트 17패킷(리셋+16, byte 161=requested 36..51) 재전송 — 에러 0. Pad 1–16 전부 의도한 드럼 음색(HITUN RIMS `62 63`·LONG TOM `63 63` 포함)으로 소리남. 에디터 `RESET_PACKET`도 동일 바이트 검증 완료 |

- PASS → `docs/playback-note-safety-plan.md` Phase 2로 (identity-safe 해제).
- FAIL → 실패 pad 조합·증상을 기록하고 Phase 1(펌웨어 변경)로.

## 생성 근거

이 파일은 identity-safe patch-set JSON
(`apps/smk37-patch-set-editor/public/samples/fm-drum-kit/FM-Drum-Kit-patches.fm.smkpatchset.json`)
의 `requestedPlaybackNote`를 `playbackNote`로 복원하고 format을
`smk37-v15-s1c3-web-patch-set-v2`(현재 에디터가 import 가능)로 승격해
생성했습니다. `parsePatchSetDocument` 왕복 16 slot 검증 완료.
