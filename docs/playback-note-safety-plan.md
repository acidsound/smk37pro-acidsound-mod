# 임의 Playback Note 안전 사용 계획

작성: 2026-08-13 · 갱신: 2026-08-14 · 상태: **Phase 1 완료 — S1C6(S16) 실기기 검증 PASS** (루트 원인: 프로듀서 리셋 시그니처 콜리전)

> **2026-08-14 정정**: 앞서 "장치가 S1C1"이라 보고했으나 잘못된 정보였습니다.
> 장치 표시가 `S1C5`의 마지막 글자가 잘려 `S1C`로만 보인 것입니다. 실제 장치는
> **S1C5 (marked)** — 아래 기록은 유효한 S1C5 실기기 결과입니다.

## 0. 루트 원인 확정 (2026-08-14)

### 증상 정리 (직접 USB libusb 센더 + 에디터 대조)

| 시도 | 경로 | byte 161 | 결과 |
|---|---|---|---|
| Bank D all-C4 | 직접 USB | 60 | ✅ 로드 |
| Bank D Original | 직접 USB | 36..51 | ✅ 로드 (패드별 다른 음높이) |
| FM Drum identity-safe | 직접 USB | 36..51 | ❌ 디폴트 복귀 |
| FM Drum identity-safe | 에디터(Web MIDI) | 36..51 | ❌ (세션 끊김 — 별개 문제) |

→ **byte 161 값(36..51 vs 60)은 원인이 아님**. 장치·패킷 포맷·USB 경로 모두
정상이며, FM 키트만 유일하게 실패합니다. (에디터 실패 전부는 OTA 시도 중
MIDIServer 재시작으로 끊긴 Web MIDI 세션 탓 — 문서 하단 참조.)

### 범인: 프로듀서 리셋 시그니처가 음성 데이터와 충돌

프로듀서 인그레스의 reset wrapper (`0x0201e228`)는 **모든 패킷**에 대해
`stage[0..1] == 0x62 0x63` (wire 바이트 6..7 = 보이스 데이터 첫 2바이트) 을
검사하고, 일치하면 lock/count/state를 클리어한 뒤 csync → producer를 호출합니다:

```
0x0201e22c  reset_sig0_load    lb.z r1,[r4]        ; stage[0]
0x0201e22e  reset_sig0_mismatch jne r1,#0x62,reset_skip
0x0201e232  reset_sig1_load    lb.z r1,[r4+1]      ; stage[1]
0x0201e234  reset_sig1_mismatch jne r1,#0x63,reset_skip
0x0201e238..  reset_metadata_pointer / zero
0x0201e240..  reset_lock_store / reset_count_store / reset_state_store
0x0201e246  reset_csync
0x0201e24a  reset_call_producer   ; 같은 stage를 producer로 처리 (보이스로 적재)
```

**시그니처 `62 63`은 Bank D 슬롯0 보이스(BUZZ BASS)의 실제 음성 데이터
바이트(EG rate)에서 차용**했습니다 — 빌더 주석 그대로
`"load BUZZ BASS reset signature byte 0"`. 즉 설계 의도는 **첫 패킷(슬롯0)이
리셋을 겸한다**는 것인데, 이 시그니처는 임의 보이스 데이터에 그대로 나타날 수
있습니다.

### FM 키트에서의 발화 (왜 유일하게 실패했는가)

전송 순서는 note 36..51 고정 → `slot = note − 36`. 번들 스캔 결과:

- **HITUN RIMS** (pad 6, note 49) → **slot 13 = 14번째 패킷**, bytes 6..7 = `62 63`
- **BUZZ BASS** (pad 9, note 36) → **slot 0 = 첫 패킷**, bytes 6..7 = `62 63`
- 그 외 번들 30개 보이스는 bytes 6..7에 `62 63` 없음

FM 키트 전송 시: 패킷 1..13(note 36..48)이 적재되어 count = 13 → 14번째
(HITUN RIMS)가 도착하면 **중간 슬롯에서 리셋 발화** → count/state 클리어 →
리셋 패킷 자체가 slot 0으로 재적재(count = 1) → 남은 패킷 2개만 → count = 3 →
**16 도달 불가 → ARMED 안 됨 → map은 EMPTY로 은닉 → 디폴트 상태**.

Bank D가 성공한 이유는 단순히 **유일한 `62 63` 보이스가 첫 패킷**이었기
때문입니다. 리셋이 발화해도 지울 게 없고, 그 패킷이 slot 0으로 적재된 뒤
나머지 15개로 count = 16 → ARMED. **운 좋게 동작한 것**입니다.

### 부차적 결함: 슬롯0이 62 63이 아니면 재로드 불가

슬롯0 보이스가 `62 63`이 아닌 키트(FM 키트의 LONG TOM = `63 63`)는,
이미 키트가 적재된 상태(count 16, ARMED)에서는 첫 패킷이 리셋을 발화하지 못해
producer의 count-full 게이트(`jge r3,#16,unlock`)가 **전 패킷을 거부**합니다.
→ "변화 없음"이라는 조용한 실패. (전원 켠 직후 count 0 상태에서는 리셋 불필요라
적재되지만, 재로드 시나리오는 항상 실패.)

### 함의

1. **identity-safe 제약의 실질 원인은 byte 161이 아니라 리셋 시그니처 결함** —
   byte 161은 이미 자유입니다 (36..51, 60 모두 로드 성공).
2. **Option A/B (map transport)는 불필요** — "byte 161 = trigger identity 유지"
   전제가 반증됨. 아래 "5. 펌웨어 변경 옵션"을 리셋 수정 중심으로 재구성.
3. FM 키트 자체(보이스 16개)는 정상 — `fm-drum-compatibility`의 Hi-Hat 2 voice
   이슈만 별개로 남음.
4. Phase 1 펌웨어 변경의 핵심 = **리셋 검출을 음성 데이터와 분리** + 호스트에
   명시적 리셋 전송 추가. 이것이 완료되면 임의 Playback Note(요청 map 36..51
   포함)가 안전해지고 identity-safe 해제로 직결됩니다.

## 1. 요약 (결론)

- 현재 설치 펌웨어 **S1-C5 Marked Playback** (`cfafa327…`)에서 임의 Playback
  Note 사용을 막는 실질 장벽은 **리셋 시그니처 콜리전** 하나로 좁혀졌습니다
  (byte 161 값 자체는 아님).
- **FM Drum preset identity-safe가 실패한 진짜 이유**: HITUN RIMS 보이스의
  bytes 6..7 = `62 63`이 프로듀서 리셋으로 오인 → 중간 슬롯에서 트랜잭션 소거
  → ARMED 미도달 → 디폴트 복귀.
- Bank D all-C4(60)·Original(36..51) 모두 직접 USB로 로드 성공 → "36..51이
  로드를 깨뜨린다"는 가설은 **폐기**.
- 남은 작업: 리셋 검출 수정(펌웨어 S16) → FM 키트 requested map(36..51)을
  explicit Playback Note로 live 검증 → PASS 시 identity-safe 해제.

## 2. 제약의 기원: byte 161의 이중 역할 (참고 — 원인 아님)

163바이트 DX7 single-voice 패킷에서 **byte 161**은 다음 세 가지를 동시에 겸합니다.

1. Yamaha 체크섬 자리(에디터 파일에서는 유효 체크섬 — `validateEditorSysEx`)
2. SMK 전송 시 **transport 바이트**: S1-C3 이전 `0x3F`(런타임 플래그),
   S1-C4+ Playback Note(0..127)
3. **firmware producer의 map source**: wire byte 161 → `0x01c46f20 + slot`

### producer (패킷 수신, `0x0201e196..0x0201e222`)

- slot은 **도착 순서**(`loaded_count`)로 배정됨 — note 36..51 순서 전송 전제.
- `staging[0x9b]`(wire byte 161) → `map[slot]`, staging은 0x3f로 복원 후 slot 복사.
- 16개 모두 수신 시 state = ARMED (map 공개는 ARMED가 마지막).
- **단, 모든 패킷은 먼저 reset wrapper(`0x0201e228`)를 통과** — 여기가 콜리전 지점.

### selector (Ch10 Note On/Off, `0x0201e13e..0x0201e194`)

- source slot = `trigger_note - 36` **만** (playback note로 source를 바꾸지 않음).
- ARMED·valid 게이트 통과 후 `map[trigger slot]` 로드 → `dest+0x9c`에 기록.
- S1-C4 v3까지는 post-hook window가 무력화(`mov r0,r0` ×3)되어 consumer의
  note 레지스터(r5/r6)가 갱신되지 않음 → **중복/비-trigger note에서 붕괴**.
- **S1C5 수정**: Note Off `0x0201c644 = lb.z r5,[r0]`, Note On
  `0x0201c682 = lb.z r6,[r0]` — consumer가 map 값을 일관되게 사용. velocity
  store(`0x0201c68c`) 보존.

### live 재분석 기록 (S1-C4 시점 — 참고, S1C5에서 해소)

`baselines/v15/analysis/playback-note/live-reanalysis/`:

> "Playback Original works when byte 161 remains trigger 36..51; all-C4 fails
> when byte 161 is 60 repeated. Therefore byte 161 must be treated as
> trigger/transaction identity, not a safe playback-note sideband."

S1C5의 register-return 수정이 이 붕괴를 해소했으며(producer는 S1-C4 v3와
byte-for-byte 동일), 이후 all-C4 live 검증이 통과했습니다. 오늘의 직접 USB
대조(Bank D original 36..51 로드 성공)도 이 결론과 일치합니다 — **byte 161은
identity-safe 유지 사유가 될 수 없습니다**.

## 3. 현재 코드 기준 안전 조건 (S1C5)

1. **리셋 시그니처 비충돌**: 어떤 보이스의 bytes 6..7도 `62 63`이 아니어야
   함 — **오늘 반증됨** (FM 키트 HITUN RIMS). → Phase 1에서 제거할 조건.
2. **one-to-one**: 동시 발음될 수 있는 trigger slot들 사이에서 playback note가
   중복되면 cross-release/voice-steal 위험
   (voice identity = stored synth note, 별도 trigger identity 필드 미검증 —
   `playback-note/abi` 보고서). FM kit는 전부 distinct라 해당 없음.
3. **Note On/Off 대칭**: 동일 trigger의 On/Off가 같은 playback note를 사용 —
   S1C5에서 충족.
4. **trigger identity 유지**: source slot = trigger_note - 36 — S1C5에서
   live 확인 (Bank D original 36..51 로드 성공).

## 4. FM Drum preset requested map 분석

| 관점 | 결과 |
|---|---|
| one-to-one | ✓ 16개 전부 distinct (36..51) |
| Note On/Off 대칭 | ✓ (S1C5 consumer 동일 map 사용) |
| byte 161 로드 안전성 | ✓ 직접 USB로 실증 (36..51 로드 성공) — **이전 "미검증" 항목은 해소** |
| identity-safe(현재) byte 161 | = trigger note 36..51 (slot 순서) |
| requested 적용 시 byte 161 | = {44,45,46,47,36,37,38,39,48,49,50,51,40,41,42,43} (전부 distinct) |

→ **FM 키트 자체는 로드 가능**. 남은 유일한 차단 요인 = 리셋 시그니처 콜리전
(HITUN RIMS) + 슬롯0 비충돌 키트의 재로드 제한. 둘 다 Phase 1 펌웨어 수정으로
해소됩니다.

## 5. 펌웨어 변경 옵션 (Phase 1 — 리셋 검출 분리로 재구성)

> 이전 Option A(identity-preserving map transport) / B(reset+map 확장) /
> C(static map) / D(voice cookie)는 "byte 161 = trigger identity가 안전하지
> 않다"는 전제 위에서 설계됐으나, 그 전제가 직접 USB 대조로 반증됨에 따라
> **불필요**합니다. 남은 실질 문제는 리셋 시그니처뿐입니다.

| 옵션 | 내용 | 난이도 | 비고 |
|---|---|---|---|
| **R-B (권장·구현 완료)**: 명시적 리셋 패킷 + 구조적 불가능 시그니처 | reset wrapper가 `stage[0..1]==64 65`를 검사하고, 일치 시 클리어 후 **producer를 호출하지 않고 반환**(리셋은 보이스가 아님). 호스트는 16개 보이스 전에 리셋 패킷 1개(17개) 전송 | 중 | **2026-08-14 S1C6(S16)로 구현 완료.** payload bytes 0..1 = OP1 EG rates 1..2(DX7 범위 0..99)라 `0x64/0x65`는 **구조적으로 불가능** (번들 32개 스캔 0건). 시그니처를 2바이트로 확정한 이유: 래퍼가 기존 44B owned tail에 in-place로 맞아 **callsite·core 무변경**(아래 §6.5). 중간 슬롯 보이스가 리셋을 발화할 수 없음 + 슬롯0 비충돌 키트도 재로드 가능 |
| **R-min (최소)**: count 게이트 추가 | reset 발화 조건에 `count == 0 || count == 16`(트랜잭션 시작/완료 시)만 허용 — 중간 슬롯(1..15)의 `62 63`은 무시 | 낮음 | 오늘의 실측 버그(중간 슬롯 소거)는 해결되지만, 슬롯0이 62 63이 아닌 키트의 재로드 제한은 남음 (전원 사이클 필요) |
| ~~A/B/C/D~~ | ~~byte 161 분리 transport~~ | — | **폐기** (전제 반증) |

**권장: R-B.** 리셋 패킷을 보이스와 완전히 분리하면 (1) 중간 슬롯 콜리전 원천
차단 (2) 슬롯0이 뭐든 재로드 가능 (3) byte 161은 순수 Playback Note로 해방 —
identity-safe 해제(Phase 2)의 전제가 모두 충족됩니다.

구현 제약(최초 설계 기준): owned window에는 2-byte tail만 여유가 있어 3바이트
시그니처 R-B는 window 재작성 또는 code cave + 호출부 재작성이 필요했습니다. 그러나
**2바이트 시그니처(0x64 0x65)로 확정하면서 이 제약이 해소**됐습니다 — r0=stage를
유지하는 재배치로 `mov r4/r0`·`mov r0/r4` 4바이트를 절약하고, 리셋 매치 시
producer 호출(10B) 대신 조기 반환(2B)으로 8바이트를 절약해, 새 래퍼는
`0x0201e228..0x0201e254`(44B) 안에 40B로 수용됩니다. 이로써 **callsite
(0x0201e468/0x0201e49c)과 selector/producer core(0x0201e13e..0x0201e228)는
byte-for-byte 보존**됩니다 (M09 교훈: cave 없음).

### 호스트 변경 (R-B 시)

- 에디터 `sendAll`: 16개 전송 전에 리셋 패킷 1개
  (`f0 43 00 00 01 1b 62 63 7f 00 … 00 f7`) 전송.
- C 센더(`send_packets.c` 등) 동일하게 리셋 선행.
- 리셋 패킷은 보이스로 적재되지 않으므로 count에 포함 안 됨 (producer 미호출).

### 빌드 게이트 (R-B/R-min 공통)

- 번들·신규 보이스 스캔: bytes 6..7 == `62 63` 및 제안 시그니처 충돌 0 확인.
- 기존 validate.py / dry-run / exact_ota / rollback 절차 유지.

## 6. 단계별 실행 계획

### Phase 0 — 실기기 대조 (완료 2026-08-14)

직접 USB 대조로 byte 161 값 범위 반증 및 리셋 콜리전 확정 — 기록은 아래
"Phase 0 시도 기록". **결론: byte 161 무관, 리셋 시그니처가 원인.**

### Phase 0.5 — (선택) 에디터 사전 경고

펌웨어 수정 전이라도, 전송 시 각 보이스의 bytes 6..7 == `62 63`을 검사해
경고를 표시(로드 차단은 아님). FM 키트 HITUN RIMS, Bank D BUZZ BASS가
감지 대상. 사용자가 실패를 조용히 겪지 않게 하는 즉효 대응.

### Phase 1 — 펌웨어 리셋 검출 수정 (S1C6 → 표시 S16)

1. R-B(또는 R-min) 설계: reset wrapper 수정, 호스트 리셋 패킷 정의.
2. S1C6 빌드 스크립트 + validate.py + 시그니처 충돌 스캔 게이트 + dry-run +
   exact_ota + rollback sector (S1C1~S1C5 확립 프로세스 그대로).
3. offline 게이트 통과 후 실기기 OTA (hash-locked token), live 검증:
   - Bank D 로드 → FM 키트 재로드(슬롯0 LONG TOM) — **재로드 성공 확인** (핵심)
   - FM 키트 + requested map(36..51) explicit → 16음 모두 드럼 음색
   - all-C4(60) 회귀 없음
4. 임의 map(0..127, 중복 포함) 검증 케이스 추가 (중복 note는 Option D
   범위로 보류해도 무방 — FM kit는 distinct).

### Phase 2 — identity-safe 해제 (에디터)

1. FM drum manifest: `playbackNote`를 `requestedPlaybackNote` 값으로 복원,
   format `smk37-v15-s1c5-identity-safe-fm-drum-preset-v1` →
   `smk37-v15-s1c6-explicit-playback-fm-drum-preset-v1` (또는 v2)로 승격.
2. `FM-Drum-Kit-patches.fm.smkpatchset.json` 재생성 (playbackNote = 36..51
   순열).
3. `tests/drum-preset.test.mjs` 기대값 갱신 (playbackNote = 36..51, identity-safe
   정책 테스트 제거/교체).
4. `app.js` 로드 메시지·README·HANDOFF·PROTOCOL 문서 갱신 (identity-safe 제약
   문구 제거).
5. 에디터 `npm test` 전체 통과 → Pages 재배포.

### Phase 3 — Release

1. 새 펌웨어(S16) 검증 로그·해시 재확인.
2. Release 생성 (내용 요약: 리셋 검출 분리, 임의 Playback Note 허용, FM drum
   map 활성화).
3. FM kit identity-safe 문서(제약) 제거.

## Phase 0 시도 기록 (2026-08-14) — 루트 원인 확정

장치는 **S1C5 (marked)** 였습니다. 초기에 "S1C1"이라 보고했으나, 표시 마커
`S1C5`의 마지막 글자가 잘려 `S1C`로만 보인 데서 비롯된 오독이었습니다.

| # | 시도 | 결과 | 해석 |
|---|---|---|---|
| 1 | 에디터 + FM identity-safe preset | ❌ 디폴트 복귀 | 에디터 세션 문제일 가능성 (아래 #7) |
| 2 | 에디터 + explicit-playback JSON | ❌ 디폴트 복귀 | 동일 |
| 3 | 에디터 + Bank D all-C4(60) | ❌ "변경 없음" | **에디터 Web MIDI 세션 끊김** (OTA 시도 중 MIDIServer 재시작 2회) |
| 4 | 직접 USB + all-C4(60) | ✅ 로드 | USB 경로·장치·byte 161=60 정상 |
| 5 | 직접 USB + Bank D Original(36..51) | ✅ 로드 | **byte 161=36..51도 정상** — 값 범위 가설 반증 |
| 6 | 직접 USB + FM identity-safe(36..51) | ❌ 디폴트 복귀 | **리셋 시그니처 콜리전 확정** (HITUN RIMS) |
| 7 | 에디터 로그 확인 | "Sent 16/16 PASS" | 전송은 성공 표시지만 장치 미도달 — 세션 끊김 방증 |

**확정 사실**: (a) byte 161 값은 원인 아님 (4·5번), (b) FM 키트만 실패 (6번),
(c) 실패 시점은 전송 직후 로드 단계, (d) 범인 = reset wrapper의
`stage[0..1] == 62 63` 검사가 HITUN RIMS 보이스 데이터와 충돌.

> 참고: 2026-08-14 S1C5 → S1C5-marked 재플래시 시도는 stage-1 검증 중단
> (request 9 = `0x0009b0d3/32`)으로 실패했고 **기기는 무변경**입니다. 버전
> 확인 문제가 해소된 현재 재플래시는 불필요합니다.
>
> 참고: 에디터 Web MIDI 세션은 MIDIServer 재시작으로 끊기며, "Web MIDI
> 재연결" 버튼만으로는 복구되지 않을 수 있습니다. 복구는 에디터 탭 완전
> 재오픈(새 MIDIAccess) 또는 Chrome 재시작. 이후 직접 USB 대조는 전부
> MIDIServer 재시작을 수반하므로 브라우저 세션과 병행 불가 — 테스트 간
> 순서를 정리해야 합니다.

## 6.5 Phase 1 진행 기록 (2026-08-14) — S1C6(S16) 구현 완료 + 실기기 검증 PASS

### 확정 설계 (R-B)

- **리셋 시그니처**: wire bytes 6..7 == `0x64 0x65` (둘 다 EG rate 최대 0x63 초과 →
  유효한 DX7 보이스에 구조적으로 불가능 — 번들 32개 스캔 0건 + DX7 포맷 범위 증명).
- **리셋 매치 시**: lock/count/state 클리어 → csync → **producer 미호출 조기 반환**
  (리셋 패킷은 보이스가 아니며 슬롯을 소비하지 않음).
- **미매치 시**: `r0 = stage` 그대로 producer(0x0201e196) 호출 — 기존 동작과 동일.
- **callsite·core 무변경**: 래퍼를 기존 owned tail에 in-place(40B)로 재작성.
  selector/producer core `0x0201e13e..0x0201e228` SHA `1f5ac42f…` 보존.
- **호스트 프로토콜**: 리셋 패킷 1개(`f0 43 00 00 01 1b 64 65 00…00 f7`) +
  보이스 16개 = 17개 전송. 첫 로드·재로드 모두 리셋 선행으로 동작.

### 아티팩트

`baselines/v15/analysis/flash-candidates/S1C6-reset-signature-isolation/`

- **fwsc**: `SMK37Pro-v15-S1C6-reset-signature-isolation-S16-marked.fwsc`
  SHA-256 `fd449b93afc2a9abe777cee10f810e3f4618b8a6b745391f73d8b7d5959fa886`
- **app**: SHA-256 `312790c080f6fcead69eccd84edf2c608ef3fa7e772455d781ab086dafed44b1`
- **OTA token**: `INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93`
- 표시 마커: `S16` (3자 버저닝 규칙 적용, `0x020572a2`에 `S16\0\0`)

### offline 게이트 (전부 PASS)

- `build_s1c6_reset_signature_isolation.py` — 결정적 재빌드, diff는 reset wrapper tail
  (0x0201e228..0x0201e254)과 마커만.
- `validate.py` — 해시 고정, core 보존, callsite 무변경, diff 범위, rollback sector,
  dry-run, OTA check 양성/음성(S1C5-marked 거부), sender dry-run + live 차단,
  SHA256SUMS 전수 검사.
- 시그니처 충돌 스캔: 번들 보이스(32) bytes 6..7 == `64 65` → **0건**.
- 전송 패킷 17개(리셋 1 + all-C4 16) framing·해시·순서 검증.

### 호스트 업데이트

- **에디터** (`apps/smk37-patch-set-editor/`): `sysex.mjs`에 `RESET_PACKET` export,
  `app.js` `sendAll`이 리셋 패킷을 선행 전송. 테스트 14/14 (리셋 패킷 프레이밍·
  시그니처·7-bit·보이스 검증기 거부 케이스 추가).
- **C 센더**: `exact_17_packet_sender.c` (리셋 선행, dry-run PASS, live 차단 기본).

### 실기기 검증 (2026-08-14, 장치 연결 상태에서 수행) — 전부 PASS

1. **S1C6 OTA**: exact_ota `check`(양성 PASS + S1C5-marked 음성 REJECT) →
   `upload … --confirm INSTALL-SMK37PRO-V15-S1C6-RESET-SIG-FD449B93` 성공.
   stage-1 검증 요청 1290개 완주(08-04 성공 패턴과 동일) + `completion
   0xf0000000 acknowledged` → 장치 정상 모드 복귀, identity `SMK-37 Pro_015`
   응답. (post-update identity 확인은 MIDIServer가 5초 대기 중 인터페이스를
   재점유해 읽기만 실패 — 플래시 자체는 정상 완료.)
2. **재로드 회귀**: 직접 USB 센더로 (1) all-C4 17패킷(리셋 + 16, byte 161=60)
   전송 → (2) **전원 사이클 없이** FM 키트 17패킷(리셋 + 16, byte 161 =
   requested map 36..51) 재전송. 둘 다 에러 0. FM 키트 재로드 성공.
3. **FM 키트 requested map**: Pad 1–16 전부 드럼 음색으로 소리남 (KICK DRUM,
   Kick, SNARE, Swissnare, HAND CLAPS, HITUN RIMS, tom 1, tom 2, LONG TOM,
   TOM TOMS, CL.HI-HAT, Open HiHat, CRASH CYMB, R.CYMBAL, COW BELL, Shaker).
   — HITUN RIMS(`62 63`), LONG TOM(`63 63`) 등 충돌 보이스 포함 전부 정상.
4. 표시 마커 `S16` 확인.

→ S1C6 핵심 회귀 3건(① 리셋 패킷 동작 ② 전원 사이클 없이 재로드 ③ 보이스
데이터의 `62 63`/`63 63` 충돌 해소) 모두 실기기 검증 완료. **Phase 2
(identity-safe 해제) 진행 가능.**

참고: 에디터 `RESET_PACKET`(wire 6..7 = `64 65`, byte 161 = 0x00, 163B)은
위 라이브 검증에 쓴 패킷과 바이트 단위로 동일하고, `sendAll`은 리셋 선행
17패킷으로 동작 — 에디터 경로는 별도 재검증 시 동일 프로토콜.

## 7. 위험 및 대응

| 위험 | 대응 |
|---|---|
| 리셋 시그니처 콜리전 (실측) | **S1C6에서 해소**: 구조적 불가능 시그니처 0x64 0x65 + 명시적 리셋 패킷, 빌드 게이트 충돌 스캔 0건 |
| 슬롯0 비충돌 키트 재로드 불가 (조용한 실패) | **S1C6에서 해소**: 명시적 리셋이 count/state를 클리어 → 전원 사이클 없이 재로드 |
| 중복 note cross-release (사용자가 중복 사용 시) | Option D까지 보류, 문서화. FM kit 기본은 one-to-one 유지 |
| owned window 여유 부족 → 재작성 리스크 | cave 안전성 분리 검증(M09 교훈), exact hash 게이트, rollback 우선 |
| 휘발성 RAM (재부팅 시 소실) | 에디터 재전송 절차 유지 (변경 없음) |
| S1C5 회귀 | R-B는 리셋 경로만 변경 — all-C4(60)·Bank D(36..51) 회귀 케이스를 live 게이트로 |
| 에디터 Web MIDI 세션 끊김 | MIDIServer 재시작 금지 절차 문서화, 재연결 = 탭 재오픈 |

## 8. 열린 질문

1. **R-B vs R-min**: R-B(명시적 리셋 + 구조적 시그니처, 재로드 전 시나리오
   해소) vs R-min(count 게이트, 최소 변경). owned window 여유 측정 후 결정 —
   R-min 선구현 → live 확인 → R-B 승격 2단계도 가능.
2. 중복 playback note가 필요한 사용 사례가 있는가 — 없으면 Option D 불필요.
3. FM kit의 Hi-Hat 2 voice 호환성 실패(`fm-drum-compatibility`)는 identity와
   무관한 별개 문제 — 해결은 별도 진행(단일 변경 진단 파일 사용).
4. 리셋 패킷의 byte 161 값: producer가 읽지 않으므로 자유 — 일관값(0x7F 등)
   고정 권장.

## 9. 버저닝 3자 전환 (2026-08-14)

4자 마커 `S1C5`가 표시에서 `S1C`로 잘려 버전 오독(→ S1C1)이 발생했습니다.
M-시리즈에서 이미 같은 교훈이 기록돼 있습니다 (`docs/firmware-versioning.md`:
4자 `M001` → 화면 `M00` 잘림 → 이후 `MNN` 3자 체계로 전환). S1C 시리즈가 이
교훈을 반복하지 않도록 규칙을 정립합니다:

- **표시 마커는 정확히 3자**: `S` + 2자리 빌드 번호 (M-시리즈 `MNN` 패턴과 동일).
  - S1C5 → 표시 `S15`, 이후 빌드는 `S16`, `S17`, … (번호는 재사용 금지).
- 전체 명칭(문서·아티팩트·토큰)은 기존 체계(S1C5 등) 유지 가능하되, 표시 마커와의
  대응을 문서에 명시.
- 다음 펌웨어(Phase 1 결과물, S1C6)부터 이 체계를 적용합니다 — 표시 `S16`.
  현재 설치된 S1C5의 마커는 `S1C5`(표시 `S1C`)를 유지합니다.

## 참조

- `baselines/v15/analysis/playback-note/live-reanalysis/consumer/report.md`
- `baselines/v15/analysis/playback-note/live-reanalysis/producer/report.md`
- `baselines/v15/analysis/playback-note/abi/report.md`
- `baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv`
- `baselines/v15/analysis/playback-note/s1c5-independent-review(-v2)/`
- `baselines/v15/analysis/playback-note/s1c5-marked-review/`
- `baselines/v15/analysis/flash-candidates/S1C5-playback-register-return(-S1C5-marked)/`
- `baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/inputs/producer/evidence.json`
  (reset_contract: "slot0 signature 62 63 clears lock/count/state…")
- `docs/fm-drum-plan.md`, `docs/v15-s1c-status.md`
