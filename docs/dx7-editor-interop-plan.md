# 일반 DX7 에디터(Dexed 등) 연동 설계

작성: 2026-08-14 · 상태: 설계 검토 대기

목표: 사용자가 Dexed 같은 일반 DX7 에디터에서 음색을 편집한 뒤, 그 결과를
SMK-37 Patch Set Editor의 16개 Pad에 올려 S1C6(S16)로 전송하는 워크플로우를
정의합니다. SMK 장치는 자체 16-slot 트랜잭션 프로토콜을 쓰므로 Dexed가 직접
SMK로 보낼 수는 없고, **에디터가 브리지**가 됩니다.

## 1. DX7 SysEx 포맷 정리

| 포맷 | 크기 | 헤더 | 내용 | 쓰임 |
|---|---|---|---|---|
| 단일 보이스 (VCED) | 163B | `F0 43 0n 00 01 1B` | 155B 보이스 + 체크섬@161 + `F7` | 단일 패치 덤프 — **SMK 에디터가 이미 수용** |
| 32-voice 뱅크 (VMEM) | 4104B | `F0 43 00 09 20 00` | 32×128B packed + 체크섬 + `F7` | 뱅크/카트리지 덤프 — **변환 필요** |
| `.dx7` 카트리지 파일 | 파일 | `FDX7` 매직 | 4096B voices + 128B 이름 (SysEx 아님) | Dexed/라이브러리 파일 — **변환 필요** |

- **VCED ↔ VMEM**: 128B packed → 155B VCED 언팩(연산자당 17→21B 비트 확장).
  Dexed의 `Cartridge::unpackProgram`이 이 변환을 수행하며, 이 저장소
  `tools/dx7_vmem.py`(`unpack_voice`/`pack_voice`)에 동일 로직이 이미 있습니다.
- **SMK runtime 관계**: `unpack_voice`의 156B runtime에서 `runtime[0:155]` =
  VCED 155B, `runtime[155]` = SMK transport 바이트 자리(에디터의 byte 161,
  Playback Note/0x3F). 즉 **변환 파이프라인이 기존 `validateEditorSysEx`와
  정확히 맞물립니다.**

## 2. 워크플로우 옵션

### A. 단일 .syx 직접 로드 (무코드, 현재 가능)

Dexed에서 보이스 우클릭 → 단일 .syx 내보내기 → SMK 에디터의
**"16개 .syx 선택"** / 드래그드롭.

- 장점: 코드 0. Dexed의 단일 보이스 내보내기는 VCED 163B(유효 체크섬 포함)라
  `validateEditorSysEx`를 통과.
- 단점: 16번 반복. 뱅크 단위 편집 흐름과 안 맞음.

### B. 32-voice 뱅크 가져오기 (신규 기능 — 권장)

Dexed에서 뱅크(.syx VMEM 4104B) 내보내기 → SMK 에디터 **"뱅크 가져오기"** →
32개 보이스 중 16개 선택 → Pad 배치 → 전송.

- Dexed의 기본 워크플로우(뱅크 단위 편집·저장)와 정확히 일치.
- 구현 재료가 이미 있음: `tools/dx7_vmem.py`의 `parse_sysex_bank` +
  `unpack_voice` → JS 이식.

### C. MIDI 단일 보이스 캡처 (옵션)

Dexed(또는 실 DX7)가 단일 보이스 SysEx(`F0 43 0n 00 01 1B…`)를 MIDI로 보내면,
에디터의 Web MIDI 입력 리스너가 **포커스된 Pad에 자동 캡처**.

- 장점: 편집기에서 "재생→캡처" 흐름이 자연스러움.
- 단점: Web MIDI 입력 파이프라인 추가 필요 (현재 MIDI Learn은 Note On만 처리).

### D. `.dx7` 카트리지 직접 지원 (낮은 우선순위)

`FDX7` 매직 + 4096B voices + 128B 이름 파싱. Dexed가 .syx로도 내보내므로
우선순위 낮음 (B 구현 후 여유 시).

## 3. 권장 설계 — B (뱅크 가져오기)

### 파이프라인

```
VMEM 뱅크(4104B) → parse_bank(F0 43 00 09 20 00 + 체크섬 검증)
  → 32 × unpack_voice(128 → 156 runtime)
  → 각 보이스 163B 패킷: F0 43 00 00 01 1B + runtime[0:155] + yamahaChecksum + F7
  → 사용자가 16개 선택 → slots[]/playbackNotes[] 구성
```

### sysex.mjs 추가 (단위 테스트 대상)

- `parseBankSysEx(bytes)` — 4104B VMEM 검증·체크섬·32 보이스 분할.
- `bankVoiceToEditorPacket(packed128)` — unpack(128→156) 후 163B 패킷 생성
  (채널 0, 이름 = packed[118:128], 체크섬 재계산).
- (선택) `parseDx7Cartridge(bytes)` — `.dx7`용.

### UI (index.html + app.js)

- `#load-bank` 버튼 + `<input type="file" accept=".syx,.dx7">`.
- 뱅크 로드 → 32개 보이스 이름 리스트(팝업/패널) → 체크박스로 16개 선택 →
  Pad 1–16 순서로 배치. Trigger Note는 `PAD_TO_NOTE` 고정(편집 불가 유지).
- Playback Note 기본값 = Original(또는 원하면 일괄 C4 버튼 재사용).

### 검증

- JS 이식 시 `dx7_vmem.py` `self_test` 대응 왕복 테스트: 128→155→128, 뱅크
  체크섬, 패킷 체크섬.
- 실제 Dexed 내보내기 뱅크 파일로 smoke test (사용자 제공 또는 공개 뱅크).
- 기존 14개 테스트 유지 + 신규 케이스.

## 4. 구현 단계 (제안)

1. `sysex.mjs`에 bank parse/unpack 추가 + 단위 테스트 (dx7_vmem 왕복 대조).
2. app.js/index.html에 "뱅크 가져오기" UI + 16개 선택 흐름.
3. 에디터 `npm test` 전체 통과 → Pages 재배포 (캐시버스트 갱신).
4. Dexed 뱅크 실파일 검증 → README/HANDOFF에 워크플로우 문서화.

## 5. 참고

- Dexed 128→155 변환: `asb2m10/dexed` `Cartridge::unpackProgram` (discussion
  #444). 외부 변환 도구: dxconvert (martintarenskeen).
- 이 저장소 `tools/dx7_vmem.py`가 정확한 128↔155/156 비트 매핑을 이미 갖고
  있어 JS 이식은 기계적입니다.
