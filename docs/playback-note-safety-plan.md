# 임의 Playback Note 안전 사용 계획

작성: 2026-08-13 · 상태: 연구 완료, 실행 대기 (Phase 0 실기기 테스트 필요)

## 1. 요약 (결론)

- 현재 설치 펌웨어 **S1-C5 Marked Playback** (`cfafa327…`)는 producer/consumer
  양쪽에서 임의 Playback Note(0..127, 중복 포함)를 이미 **live 검증**했습니다
  (2026-08-04, all-C4 세트 포함, 사용자 확인 "perfect").
- FM Drum preset이 identity-safe(Original)로 고정된 이유는 S1-C4 시절 live 실패
  (all-C4 → Ch1 fallback)와, 이후에도 **trigger 범위(36..51) 내 playback note의
  voice-identity 상호작용이 ABI로 미검증**이기 때문입니다.
- FM Drum preset의 requested map(36..51, 전부 **distinct**)은 one-to-one이므로
  현재 S1C5 코드 기준 이론상 안전합니다. **가장 짧은 경로는 펌웨어 변경 없이
  실기기 live 테스트(Phase 0)로 확인하는 것**입니다.
- 만약 Phase 0에서 실패하거나, 방어적으로 완전히 분리하고 싶다면
  **byte 161을 trigger identity(36..51)로 유지하고 Playback Note map을 별도
  transport로 쓰는 펌웨어 변경**(Option A/B)이 필요합니다. S1C5 owned window에는
  여유가 거의 없어(2-byte tail) 재작성 또는 새 코드 cave가 필요합니다.

## 2. 제약의 기원: byte 161의 이중 역할

163바이트 DX7 single-voice 패킷에서 **byte 161**은 다음 세 가지를 동시에 겸합니다.

1. Yamaha 체크섬 자리(에디터 파일에서는 유효 체크섬 — `validateEditorSysEx`)
2. SMK 전송 시 **transport 바이트**: S1-C3 이전 `0x3F`(런타임 플래그),
   S1-C4+ Playback Note(0..127)
3. **firmware producer의 map source**: wire byte 161 → `0x01c46f20 + slot`

### producer (패킷 수신, `0x0201e196..0x0201e222`)

- slot은 **도착 순서**(`loaded_count`)로 배정됨 — note 36..51 순서 전송 전제.
- `staging[0x9b]`(wire byte 161) → `map[slot]`, staging은 0x3f로 복원 후 slot 복사.
- 16개 모두 수신 시 state = ARMED (map 공개는 ARMED가 마지막).

### selector (Ch10 Note On/Off, `0x0201e13e..0x0201e194`)

- source slot = `trigger_note - 36` **만** (playback note로 source를 바꾸지 않음).
- ARMED·valid 게이트 통과 후 `map[trigger slot]` 로드 → `dest+0x9c`에 기록.
- S1-C4 v3까지는 post-hook window가 무력화(`mov r0,r0` ×3)되어 consumer의
  note 레지스터(r5/r6)가 갱신되지 않음 → **중복/비-trigger note에서 붕괴**.
- **S1C5 수정**: Note Off `0x0201c644 = lb.z r5,[r0]`, Note On
  `0x0201c682 = lb.z r6,[r0]` — consumer가 map 값을 일관되게 사용. velocity
  store(`0x0201c68c`) 보존.

### live 재분석 기록

`baselines/v15/analysis/playback-note/live-reanalysis/` (S1-C4 시점):

> "Playback Original works when byte 161 remains trigger 36..51; all-C4 fails
> when byte 161 is 60 repeated. Therefore byte 161 must be treated as
> trigger/transaction identity, not a safe playback-note sideband."

S1C5의 register-return 수정이 이 붕괴를 해소했으며(producer는 S1-C4 v3와
byte-for-byte 동일), 이후 all-C4 live 검증이 통과했습니다. 따라서 "identity
결합"은 **producer가 아니라 consumer의 note identity 문제**로 확정됩니다.

## 3. 현재 코드 기준 안전 조건 (S1C5)

1. **one-to-one**: 동시 발음될 수 있는 trigger slot들 사이에서 playback note가
   중복되면 cross-release/voice-steal 위험
   (voice identity = stored synth note, 별도 trigger identity 필드 미검증 —
   `playback-note/abi` 보고서).
2. **Note On/Off 대칭**: 동일 trigger의 On/Off가 같은 playback note를 사용 —
   S1C5에서 충족.
3. **trigger identity 유지**: source slot = trigger_note - 36, byte 161이
   transaction에 관여하던 시절의 제약은 S1C5에서 live 해소.
4. **36..51(trigger 범위) 내 playback note는 ABI 미검증**: FM kit requested
   map(36..51)이 여기에 해당 — 이것이 현재 identity-safe 유지의 실질적 이유.

## 4. FM Drum preset requested map 분석

| 관점 | 결과 |
|---|---|
| one-to-one | ✓ 16개 전부 distinct (36..51) |
| Note On/Off 대칭 | ✓ (S1C5 consumer 동일 map 사용) |
| trigger 범위 내 | △ 36..51 — voice allocator와의 상호작용 미검증 |
| identity-safe(현재) byte 161 | = trigger note 36..51 (slot 순서) |
| requested 적용 시 byte 161 | = {44,45,46,47,36,37,38,39,48,49,50,51,40,41,42,43} (전부 distinct) |

→ **이론적으로는 안전**. 유일한 미검증 지점은 "playback note가 36..51 범위일 때
FM voice allocator가 trigger note와 혼동하는지"입니다. 이건 live 테스트로만
결정됩니다.

## 5. 펌웨어 변경 옵션 (필요 시)

| 옵션 | 내용 | byte 161 | 중복 note | 난이도 |
|---|---|---|---|---|
| **A. identity-preserving map transport** | 전용 "map packet"(시그니처 + 16 map 바이트)을 producer가 처리. voice 패킷의 byte 161은 항상 trigger 36..51 유지 | trigger identity 고정 | producer 레벨 안전 | 중 (owned window 재작성 or cave) |
| **B. reset/seed packet 확장** | 기존 reset 시그니처(`0x62 0x63` at staging[0..1]) 패킷에 16-byte map payload 추가 | trigger identity 고정 | producer 레벨 안전 | 중 |
| **C. static map 컴파일** | map을 펌웨어에 고정 (호스트는 voice만 전송) | trigger identity 고정 | 맵 변경 불가 | 낮음 (유연성↓) |
| **D. voice cookie / active-note identity** | note 기반이 아닌 별도 voice identity 도입 → 중복 note cross-release 해결 | 임의 가능 | **해결** | 높음 (대규모, M09류 위험) |

**권장**: Phase 0 결과에 따라 A(또는 B)를 S1C6 번호 체계로 진행. D는 FM kit에서
중복 note가 실제로 필요해질 때까지 보류.

구현 제약: S1C5 selector/producer owned window
(`0x0201e13e..0x0201e254`)에는 2-byte tail만 여유가 있으므로
(`persistence-s2/restore-placement-audit`), A/B 구현은 window 재작성 또는 새
code cave + 호출부 재작성이 필요합니다. M09 사고 교훈(`docs/m09-brick-incident.md`)
대로 **data cave 안전성과 wrapper를 분리 검증**해야 합니다.

## 6. 단계별 실행 계획

### Phase 0 — 실기기 live 테스트 (펌웨어 변경 없음, 최우선)

준비물: `baselines/v15/analysis/playback-note/fm-drum-lift-test/`
`FM-Drum-Kit.explicit-playback.smkpatchset.json` — FM kit 16음에 requested
map(36..51)을 explicit playback note로 적용한 테스트 set (format v2로
importable).

절차:
1. 현재 S1C5 장치 부팅 확인 (표시 `S1C5`).
2. Patch Set Editor → **Set 가져오기**로 테스트 JSON 로드.
3. Web MIDI 연결 → **16개 Patch 전송**.
4. Pad 1–16을 순서대로·겹쳐서 연주하며 확인:
   - 모든 16음이 의도한 드럼 음색·음높이로 소리나는가
   - 동시에 울리는 pad 간 cross-release / voice steal 없음
   - 반복 연타 시 stuck note 없음
   - Note Off가 다른 pad의 음을 죽이지 않음

판정:
- **PASS**: identity-safe 해제 가능. Phase 2로 (펌웨어 변경 없이).
- **FAIL**: 실패 패턴을 기록(어느 pad 조합에서 어떤 증상) → Phase 1로.
  실패 패턴이 "trigger 범위 내 note"와 관련되면 Option A/B로 분리 전송.

### Phase 1 — 펌웨어 변경 (FAIL 시에만)

1. Option A(또는 B) 설계: map packet 포맷 정의, producer 분기, owned window
   재작성/신규 cave 위치 선정.
2. S1C6 빌드 스크립트 + validate.py + dry-run + exact_ota + rollback sector
   (S1C1~S1C5 확립 프로세스 그대로).
3. offline 게이트 통과 후 실기기 OTA (hash-locked token), live 검증.
4. all-C4 및 임의 map(0..127, 중복 포함) 검증 케이스 추가.

### Phase 2 — identity-safe 해제 (에디터)

1. FM drum manifest: `playbackNote`를 `requestedPlaybackNote` 값으로 복원,
   format `smk37-v15-s1c5-identity-safe-fm-drum-preset-v1` →
   `smk37-v15-s1c6-explicit-playback-fm-drum-preset-v1` (또는 v2)로 승격.
2. `FM-Drum-Kit-patches.fm.smkpatchset.json` 재생성.
3. `tests/drum-preset.test.mjs` 기대값 갱신 (playbackNote = 36..51, identity-safe
   정책 테스트 제거/교체).
4. `app.js` 로드 메시지·README·HANDOFF·PROTOCOL 문서 갱신.
5. 에디터 `npm test` 전체 통과 → Pages 재배포.

### Phase 3 — Release

1. 새 펌웨어(S1C6 또는 무변경 시 S1C5) 검증 로그·해시 재확인.
2. Release 생성 (내용 요약: 임의 Playback Note 허용, FM drum map 활성화).
3. FM kit identity-safe 문서(제약) 제거.

## 7. 위험 및 대응

| 위험 | 대응 |
|---|---|
| 중복 note cross-release (사용자가 중복 사용 시) | Option D까지 보류, 문서화. FM kit 기본은 one-to-one 유지 |
| 36..51 playback note의 allocator 혼동 | Phase 0에서 실측. 실패 시 map을 60+로 옮기거나 Option A |
| owned window 여유 부족 → 재작성 리스크 | cave 안전성 분리 검증(M09 교훈), exact hash 게이트, rollback 우선 |
| 휘발성 RAM (재부팅 시 소실) | 에디터 재전송 절차 유지 (변경 없음) |
| S1C5 회귀 | identity-safe 유지 시점 동안 기존 정책 보존, Phase 2에서만 전환 |

## 8. 열린 질문

1. requested map(36..51)을 그대로 쓸 것인가, 아니면 trigger 범위 밖(예: 60..75)으로
   옮길 것인가 — Phase 0 결과로 결정.
2. 중복 playback note가 필요한 사용 사례가 있는가 — 없으면 Option D 불필요.
3. FM kit의 Hi-Hat 2 voice 호환성 실패(`fm-drum-compatibility`)는 identity와
   무관한 별개 문제 — 해결은 별도 진행(단일 변경 진단 파일 사용).

## 참조

- `baselines/v15/analysis/playback-note/live-reanalysis/consumer/report.md`
- `baselines/v15/analysis/playback-note/live-reanalysis/producer/report.md`
- `baselines/v15/analysis/playback-note/abi/report.md`
- `baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv`
- `baselines/v15/analysis/playback-note/s1c5-independent-review(-v2)/`
- `baselines/v15/analysis/playback-note/s1c5-marked-review/`
- `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return(-S1C5-marked)/`
- `docs/fm-drum-plan.md`, `docs/v15-s1c-status.md`
