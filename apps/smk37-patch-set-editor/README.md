# SMK-37 Patch Set Editor

Windows/macOS Desktop Chrome용 무의존성 Web MIDI patch-set 편집기입니다. Electron, SwiftUI, npm 패키지가 필요하지 않습니다.

## 요구사항

- Node.js 20 이상
- Desktop Chrome 또는 Chromium 계열 브라우저
- Playback Note 지원 펌웨어가 설치된 SMK-37 Pro
- 브라우저의 Web MIDI SysEx 권한 허용

`localhost`는 Web MIDI가 허용되는 secure context로 취급됩니다.

## 실행

```bash
cd apps/smk37-patch-set-editor
npm start
```

Chrome에서 다음 주소를 엽니다.

```text
http://127.0.0.1:3737
```

`node_modules`나 `npm install`은 필요하지 않습니다.

## 주요 기능

- 실제 2×8 Physical Pad 1–16 배치
- Pad별 `.syx` 파일 선택 및 drag/drop
- Pad별 내부 신스 `Playback Note` 선택 (`Original` 또는 MIDI Note `0..127`)
- Playback Note control 또는 Pad에 포커스한 뒤 선택된 MIDI Input에서 Note On을 받아 즉시 지정하는 MIDI Learn
- 전체 Playback Note를 `Original` 또는 `C4 (60)`로 일괄 설정
- Yamaha DX7 163-byte single-voice header/checksum 검증
- 검증된 Bank D demo 16개 내장
- patches.fm 기반 FM Drum Preset 16개 내장
- Pad별 `.syx` 다시 저장
- 전체 세트를 `.smkpatchset.json`으로 저장하고 복원
- SMK 런타임 플래그 `0x3F` 자동 변환
- MIDI note 36→51 순서 자동 변환
- Web MIDI를 통한 100ms 간격 16개 일괄 전송

## 사용 순서

1. `검증 세트 불러오기`, `FM Drum Preset 불러오기` 또는 Pad별 `.syx` 선택
2. `Web MIDI 연결`을 누르고 SysEx 권한 허용
3. 단일 `SMK MIDI Device` 선택
4. Playback Note를 바꿀 Pad 또는 드롭다운을 클릭하고 건반에서 원하는 Note 입력
5. `16개 Patch 전송`
6. Pad 1–16 청취 확인

현재 S1-C4는 16개 Patch와 Playback Note map을 하나의 휘발성 RAM transaction으로 적재합니다. 한 Pad만 교체하더라도 전체 16개를 전송하며, 장치 재부팅 후 다시 전송해야 합니다.

`Trigger Note`는 Physical Pad 식별과 MIDI OUT을 위해 변경하지 않습니다. `Playback Note`는 Patch Set JSON에 별도 저장되며 내부 Ch10 신스의 발음 음높이만 바꾸기 위한 값입니다. 각 163-byte packet의 마지막 staged payload byte에 Playback Note `0..127`을 넣으므로 대응 펌웨어가 필요합니다.

## 테스트

```bash
npm test
```

테스트는 내장 16개 파일의 checksum, editor→SMK 변환, Physical Pad↔Trigger Note 불변, Playback Note 저장·복원, v1 Set 호환성, patch-set JSON 왕복, 손상 파일 거부를 확인합니다.

## 저장 공간

앱 전체가 정적 HTML/CSS/JavaScript와 약 2.6KB의 SysEx sample로 구성됩니다. 외부 런타임 또는 프레임워크를 복사하지 않습니다.
