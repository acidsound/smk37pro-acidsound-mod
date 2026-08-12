# SysEx · 전송 프로토콜 상세

이 문서는 `public/sysex.mjs`의 동작을 기준으로 한 기술 참조입니다.
앱 로직을 수정할 때는 이 문서와 테스트(`tests/`)를 함께 갱신하세요.

## 1. 개별 패킷: Yamaha DX7 single voice (163 bytes)

| Offset | 길이 | 내용 |
|---:|---:|---|
| 0 | 1 | `F0` SysEx 시작 |
| 1 | 1 | `43` Yamaha |
| 2 | 1 | `0n` — 채널 (n = 0..15, `bytes[2] & 0x0f`) |
| 3–5 | 3 | `00 01 1B` — single-voice 포맷 헤더 |
| 6–160 | 155 | 보이스 파라미터 데이터 (모두 7-bit, `≤ 0x7F`) |
| 161 | 1 | 체크섬: `(-sum(bytes[6..160])) & 0x7F` |
| 162 | 1 | `F7` 종료 |

`validateEditorSysEx()`가 적용하는 검증 규칙:

1. 길이 163바이트.
2. 헤더 `F0 43 0n 00 01 1B` 일치 (채널 n은 무시).
3. 마지막 바이트 `F7`.
4. 1번째부터 161번째까지 모든 바이트가 7-bit (`≤ 0x7F`).
5. byte 161 체크섬 일치.

패치 이름은 ASCII 바이트 151–160 (10자)입니다 (`patchName()`).

## 2. SMK 런타임 변환 (`toSmkRuntimePacket`)

에디터 SysEx의 **byte 161**을 SMK 펌웨어가 읽는 "staged payload transport" 바이트로
교체합니다:

- **기본 (S1-C3 이전 동작)**: `0x3F` (`SMK_RUNTIME_FLAG`) — 패치 적재 명령으로만 사용.
- **Playback Note 인코딩 (`encodePlayback: true`, S1-C4/S1-C5)**: 해당 Pad의
  `Playback Note` 값 `0..127`. 이 값은 내부 **Ch10 신스**의 발음 음높이를 결정합니다.

보이스 데이터(byte 6–160)와 체크섬 위치를 제외한 나머지는 바뀌지 않습니다.
체크섬은 교체 후 재계산되지 않습니다 — byte 161은 원래 체크섬 자리이므로, SMK
펌웨어가 transport 값으로 해석합니다 (DX7 에디터용 체크섬 의미는 유지되지 않음).

## 3. Physical Pad ↔ Trigger Note 매핑

```js
PAD_TO_NOTE = [40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47]
```

| Pad | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 |
|---:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| Trigger Note | 40 | 41 | 42 | 43 | 48 | 49 | 50 | 51 | 36 | 37 | 38 | 39 | 44 | 45 | 46 | 47 |

`Trigger Note`는 SMK 물리 Pad의 **식별자**입니다. 앱은 이를 절대 변경하지 않습니다.
`Playback Note`(내부 신스 음높이)와는 별개입니다.

## 4. 전송 순서 (`transmissionOrder`)

전송은 MIDI note **36 → 51** 순서로 진행되며, Pad 순서로는
`[9, 10, 11, 12, 1, 2, 3, 4, 13, 14, 15, 16, 5, 6, 7, 8]`입니다.

```js
note 36..51 → slot = note - 36 → pad = NOTE_TO_PAD.get(note)
```

각 패킷은 100ms 간격으로 순차 전송됩니다. 16개 전송이 끝나면 로그에 완료를
남깁니다.

## 5. 휘발성 RAM transaction

현재 펌웨어(S1-C4 이후)는 **16개 패치 + Playback Note map 전체를 하나의 휘발성
RAM transaction**으로 적재합니다.

- 한 Pad만 바꿔도 **전체 16개를 재전송**해야 합니다.
- **장치 재부팅/펌웨어 업데이트 후에는 반드시 재전송**해야 합니다 (전원 꺼짐 시 소실).
- 이 앱의 `16개 Patch 전송` 버튼이 이 전송을 수행합니다.

### S1-C5 identity 결합 (중요)

S1-C5에서는 packet byte 161(transport/Playback Note 값)이 16-slot transaction의
**identity**에 관여합니다. 임의의 Playback Note를 넣으면 slot identity가 붕괴할 수
있습니다. 따라서:

- **FM Drum Preset**은 `playbackNote: null`(Original)만 사용하는
  **identity-safe** 정책으로 동작합니다 (`docs/HANDOFF.md` 참조).
- 임의의 drum-map Playback Note를 안전하게 쓰려면 펌웨어 쪽 변경이 선행되어야
  합니다.

## 6. Patch Set JSON 포맷

`createPatchSetDocument()` / `parsePatchSetDocument()`가 다루는 포맷:

- 현재: `smk37-v15-s1c3-web-patch-set-v2`
- import 호환: `smk37-v15-s1c3-web-patch-set-v1`, `smk37-v15-s1c5-identity-safe-patch-set-v1`

구조 (v2):

```json
{
  "format": "smk37-v15-s1c3-web-patch-set-v2",
  "title": "Set 이름",
  "createdAt": "ISO-8601",
  "physicalPadNoteSequence": [40, 41, 42, 43, 48, 49, 50, 51, 36, 37, 38, 39, 44, 45, 46, 47],
  "playbackNotes": [null | 0..127 × 16],
  "patches": [
    {
      "pad": 1,
      "note": 40,
      "playbackNote": null,
      "name": "BASS SLAP",
      "sourceFile": "pad01-note40-BASS_SLAP.syx",
      "syxBase64": "..."
    }
  ]
}
```

`parsePatchSetDocument()`은 16개 Pad 중복/누락, Pad↔note 불일치, base64→163-byte
검증 실패를 모두 거부합니다.

## 7. MIDI Learn

`midiNoteOnFromMessage()`는 **Note On(0x90) + velocity > 0** 메시지만 받아들입니다
(0x80 Note Off, velocity 0, CC 등 무시). 받은 note 번호를 포커스된 Pad의
`Playback Note`로 즉시 반영합니다.

## 8. 샘플 manifest 포맷

`public/samples/<name>/manifest.json`:

```json
{
  "format": "smk37-v15-s1c3-web-sample-v1",
  "title": "Bank D Demo",
  "patches": [
    { "pad": 1, "note": 40, "name": "BASS SLAP", "file": "pad01-note40-BASS_SLAP.syx", "sha256": "..." }
  ]
}
```

앱은 manifest의 `file`을 manifest와 같은 디렉터리 기준 **상대 경로**로 fetch합니다.
새 샘플을 추가할 때도 반드시 상대 경로를 유지하세요.
