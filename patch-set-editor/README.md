# SMK-37 Patch Set Editor · GitHub Pages

SMK-37 Pro 내장 **Ch10 드럼 신스**에 Yamaha DX7 single-voice SysEx 16개를 실제 2×8 Pad에 배치하고
Chrome Web MIDI로 전송하는 **무의존성 정적 웹 앱**입니다. 백엔드·빌드·런타임 없이
HTML/CSS/JS만으로 동작하므로 GitHub Pages에 그대로 호스팅할 수 있습니다.

- **호스팅**: GitHub Pages (HTTPS secure context → Web MIDI SysEx 허용)
- **브라우저**: Desktop Chrome / Chromium 계열만 (Web MIDI 지원 브라우저)
- **대상 장치**: S1C5 Playback Note 펌웨어가 설치된 SMK-37 Pro
- **의존성**: 없음 (`npm install` 불필요)

> 이 프로젝트는 `smk37pro-acidsound-mod` 저장소의 `patch-set-editor/` 하위 경로로
> 호스팅됩니다. 저장소 루트의 `.github/workflows/deploy-pages.yml`이 main push 시
> `public/`을 **https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/**
> 에 자동 배포합니다. 이 폴더만 별도 저장소로 분리해 독립 배포할 수도 있습니다
> ([docs/DEPLOY.md](docs/DEPLOY.md)).

---

## 실행 (로컬 개발)

```bash
npm start          # 또는 node server.mjs
```

Chrome에서 `http://127.0.0.1:3737`를 엽니다. `localhost`는 secure context이므로
Web MIDI 권한이 허용됩니다. 로컬 서버의 `/__diagnostics` 엔드포인트는 개발 진단
로그용이며, GitHub Pages에서는 자동으로 비활성화됩니다.

## 테스트

```bash
npm test
```

테스트는 내장 16개 파일의 checksum·헤더 검증, editor→SMK 변환, Physical Pad↔Trigger
Note 불변, Playback Note 저장·복원, v1 Set 호환성, patch-set JSON 왕복, 손상 파일
거부, FM Drum preset identity-safe 정책을 확인합니다.

## 주요 기능

- 실제 2×8 Physical Pad 1–16 배치
- Pad별 `.syx` 파일 선택 및 drag/drop (163-byte DX7 single-voice 검증)
- Pad별 내부 신스 `Playback Note` 선택 (`Original` 또는 MIDI Note `0..127`)
- MIDI Learn: Playback Note control 또는 Pad 포커스 후 MIDI Input에서 Note On 즉시 지정
- 전체 Playback Note를 `Original` / `C4 (60)`로 일괄 설정
- Yamaha DX7 163-byte single-voice header/checksum 검증
- 검증된 Bank D demo 16개 + patches.fm 기반 FM Drum Preset 16개 내장
- Pad별 `.syx` 다시 저장, 전체 세트 `.smkpatchset.json` 저장·복원
- SMK 런타임 플래그 `0x3F` 자동 변환, MIDI note 36→51 순서 자동 변환
- Web MIDI를 통한 100ms 간격 16개 일괄 전송

## 사용 순서

1. `검증 세트 불러오기` / `FM Drum Preset 불러오기` 또는 Pad별 `.syx` 선택
2. `Web MIDI 연결` 클릭 후 SysEx 권한 허용
3. 단일 `SMK MIDI Device` 선택
4. Playback Note를 바꿀 Pad 또는 드롭다운을 클릭하고 건반에서 원하는 Note 입력
5. `16개 Patch 전송`
6. Pad 1–16 청취 확인

> 현재 펌웨어는 16개 Patch와 Playback Note map을 **하나의 휘발성 RAM transaction**으로
> 적재합니다. 한 Pad만 바꿔도 전체 16개를 다시 전송해야 하며, 장치 재부팅 후에는
> 반드시 재전송해야 합니다.

`Trigger Note`는 Physical Pad 식별·MIDI OUT용으로 변경하지 않습니다. `Playback Note`는
내부 Ch10 신스의 발음 음높이만 바꾸는 값으로, 각 163-byte packet의 마지막 staged
payload byte(byte 161)에 `0..127`로 실려 전송됩니다. 기술 상세는 [docs/PROTOCOL.md](docs/PROTOCOL.md).

## 프로젝트 구조

```
├── public/                 # GitHub Pages에 배포되는 사이트 루트 (전부 정적)
│   ├── index.html
│   ├── styles.css
│   ├── app.js              # Web MIDI / UI 로직
│   ├── sysex.mjs           # SysEx 검증·변환·전송 순서 (테스트 대상 코어)
│   ├── .nojekyll           # Jekyll 처리 방지
│   └── samples/
│       ├── bank-d-demo/    # 검증된 Bank D 16개 + manifest.json
│       └── fm-drum-kit/    # patches.fm FM Drum 16개 + manifest.json + README
├── server.mjs              # 로컬 개발 서버 (GitHub Pages에는 미사용)
├── tests/                  # node:test 기반 단위 테스트
├── .github/workflows/deploy-pages.yml
└── docs/
    ├── DEPLOY.md           # GitHub Pages 배포 가이드
    ├── PROTOCOL.md         # SysEx/전송 프로토콜 상세
    └── HANDOFF.md          # 핸드오프 문서 (컨텍스트·제약·유지보수)
```

## 제약 사항

- **Web MIDI는 Chrome/Edge 등 Chromium 계열에서만 동작**합니다. Safari/iOS는 미지원.
- HTTPS 또는 localhost의 secure context가 필요합니다 (GitHub Pages는 HTTPS).
- Web MIDI SysEx는 사용자 동의가 필요하며, Chrome에서 한 번 허용하면 유지됩니다.
- 모든 자산 경로는 상대 경로이므로 프로젝트 페이지 하위 경로
  (`https://<user>.github.io/<repo>/`)에서도 정상 동작합니다.
