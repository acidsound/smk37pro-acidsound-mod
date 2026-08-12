# 핸드오프 문서 (HANDOFF)

> 대상: 이 프로젝트를 인수받아 유지보수할 사람 (또는 미래의 나)
> 날짜: 2026-08-13 · 버전: 1.0.0-ghpages

## 1. 무엇을 넘기는가

SMK-37 Pro(10채널 드럼 머신 계열) 내부 **Ch10 드럼 신스**에 Yamaha DX7 single-voice
SysEx 16개를 실어 보내는 웹 앱 **SMK-37 Patch Set Editor**를, **GitHub Pages에서
바로 돌릴 수 있는 독립 프로젝트**로 정리한 것입니다.

원본은 별도 펌웨어 연구 저장소의 `apps/smk37-patch-set-editor/`에 있었습니다.
이 디렉터리는 그 앱을 **완전히 분리·독립**시켜, 자신의 GitHub 저장소로 push하면
그대로 배포·운영되는 형태입니다.

### 핸드오프 범위

- [x] 앱 전체 소스 (`public/`) — 정적 HTML/CSS/JS, 외부 런타임·프레임워크 없음
- [x] 내장 샘플 32개 (Bank D Demo 16 + patches.fm FM Drum 16) + manifest
- [x] 단위 테스트 (`tests/`) 및 로컬 개발 서버 (`server.mjs`)
- [x] GitHub Pages 자동 배포 워크플로우 (`.github/workflows/deploy-pages.yml`)
- [x] 문서: README, DEPLOY, PROTOCOL, HANDOFF (본 문서)
- [x] GitHub Pages 호환화 코드 변경

### GitHub Pages 호환을 위해 바꾼 것

1. **`/__diagnostics` POST 가드** (`public/app.js`):
   로컬 개발 서버(`server.mjs`) 전용 진단 엔드포인트입니다. GitHub Pages에는 서버가
   없으므로 `localhost`/`127.0.0.1`에서만 활성화되고, 그 외 호스트에서는 no-op이
   됩니다. 정적 호스팅에서 404 요청이 발생하지 않습니다.
2. **`.nojekyll`** (`public/` 및 저장소 루트): Jekyll 처리를 막아 `.syx`·`.mjs` 등이
   원본 그대로 서빙되도록 합니다.
3. **상대 경로 유지**: 모든 자산(`styles.css`, `app.js`, `samples/...`)과
   manifest fetch가 상대 경로이므로 프로젝트 페이지 하위 경로
   (`https://<user>.github.io/<repo>/`)에서도 동작합니다. **절대 경로로 바꾸지 말 것.**
4. **버전 표기**: `app.js` 상단 `APP_VERSION`, 로그 시작 메시지에서 실행 모드
   (로컬/GitHub Pages)를 표시합니다.

## 2. 컨텍스트 (왜 이런 앱인가)

- SMK-37 Pro는 내부에 **Ch10 전용 드럼 신스**가 있으며, 16개 보이스를 물리 Pad
  (2×8)에 배치합니다.
- 보이스 데이터는 **Yamaha DX7 single-voice SysEx**(163바이트, 헤더
  `F0 43 0n 00 01 1B`) 형태로 주고받습니다.
- 펌웨어는 16개 패치 전체를 **하나의 휘발성 RAM transaction**으로 적재합니다.
  → 한 개만 바꿔도 전체 재전송, 재부팅 후 재전송 필요.
- `Trigger Note`는 물리 Pad 식별자로 **불변**이고, `Playback Note`는 내부 신스의
  발음 음높이만 바꿉니다. Playback Note는 각 패킷의 **byte 161**에 실려 전송됩니다.
- 펌웨어 버전에 따라 byte 161 해석이 다릅니다:
  - S1-C3 이전: `0x3F`(런타임 플래그)만 사용.
  - S1-C4 이후: `0..127` Playback Note 인코딩.
  - **S1-C5**: byte 161이 16-slot transaction identity에 결합 → 임의 Playback Note는
    identity 붕괴 위험. FM Drum Preset은 identity-safe(Original) 정책 사용.

이 내용은 `docs/PROTOCOL.md`에 기술 기준으로 정리되어 있습니다.

## 3. 운영 제약 (반드시 전달할 것)

| 항목 | 제약 |
|---|---|
| 브라우저 | **Desktop Chrome/Chromium 계열만** (Web MIDI 지원). Safari/iOS 미지원 |
| 보안 컨텍스트 | HTTPS 또는 localhost 필요 → GitHub Pages는 충족 |
| SysEx 권한 | Chrome에서 사용자 동의 필요 (`chrome://settings/content/midiDevices`) |
| 대상 펌웨어 | S1-C5 Playback Note 펌웨어 (그 이상에서 Playback Note byte 161 해석 필요) |
| 전송 특성 | 16개 일괄·100ms 간격·휘발성 RAM → 재부팅마다 재전송 |
| 백엔드 | 없음. 모든 로직은 클라이언트. `server.mjs`는 로컬 개발 전용 |
| 진단 | `/__diagnostics`는 로컬 전용. GitHub Pages에서는 비활성 |

## 4. 파일 맵

| 경로 | 역할 | 수정 시 주의 |
|---|---|---|
| `public/index.html` | UI 골격 | `app.js?v=...` 캐시 버전 쿼리 갱신 |
| `public/app.js` | UI·Web MIDI 로직 | 진단 가드(`DIAGNOSTICS_ENABLED`) 유지 |
| `public/sysex.mjs` | SysEx 검증·변환·순서 (코어) | **테스트와 함께 수정** |
| `public/styles.css` | 스타일 | — |
| `public/samples/` | 내장 샘플 + manifest | 상대 경로 유지, sha256 기록 |
| `tests/` | node:test 단위 테스트 | 배포 workflow가 실행 |
| `server.mjs` | 로컬 개발 서버 (:3737) | `/__diagnostics` 엔드포인트 포함 |
| `.github/workflows/deploy-pages.yml` | 테스트 + Pages 배포 | main push 트리거 |
| `docs/` | README·DEPLOY·PROTOCOL·HANDOFF | 동작 변경 시 함께 갱신 |

## 5. 유지보수 가이드

### 샘플(패치) 추가/교체
1. 163바이트 DX7 single-voice `.syx`를 준비하고 `public/samples/<set>/`에 배치.
2. `manifest.json`에 `pad`, `note`(PAD_TO_NOTE 고정), `name`, `file`, `sha256` 기록.
   `sha256sum file`로 계산.
3. `npm test`로 전체 검증. FM Drum 키트를 바꿀 때는 identity-safe 정책
   (`playbackNote: null`)을 유지.

### 코어 로직 변경
`sysex.mjs`의 검증/변환/순서를 바꾸면 `tests/`의 기대값(체크섬, pad 순서,
transport byte)도 반드시 함께 갱신하세요. 배포 workflow가 테스트 실패 시 배포를
막습니다.

### 배포
main push만 하면 자동. 수동 트리거는 Actions 탭의 **workflow_dispatch**.
상세: `docs/DEPLOY.md`.

### 버전/캐시
`index.html`의 `app.js?v=...` 쿼리와 `app.js`의 `APP_VERSION`을 함께 올리세요.
GitHub Pages는 강한 캐싱을 하므로 쿼리를 바꾸지 않으면 구버전 JS가 남을 수 있습니다.

## 6. 알려진 이슈 / 열린 질문

1. **S1-C5 identity 결합**: 임의 drum-map Playback Note를 안전하게 쓰려면
   펌웨어 변경이 선행되어야 합니다. FM Drum Preset은 Original만 사용 중
   (manifest에 `requestedPlaybackNote` 메타데이터로 원래 의도는 보존).
   해제 연구·단계별 계획은 저장소 루트 `docs/playback-note-safety-plan.md`를
   참고하세요.
2. **Safari**: Web MIDI 미지원. Chrome 안내 문구만 존재.
3. **MIDI Learn**: Note On만 인식. (채널 필터링, CC 매핑 등은 미구현.)
4. **진단**: GitHub Pages에서 진단 수집 불가. 오류는 로그에만 남습니다.
5. **동시 편집**: 다중 탭/사용자가 같은 장치로 전송하면 상태가 꼬일 수 있습니다
   (휘발성 RAM 특성상 어쩔 수 없는 부분).

## 7. 다음 단계 제안

- 임의 Playback Note 허용을 위한 펌웨어 side 변경 후 앱의 "identity-safe" 경고 제거.
- PWA(service worker)로 오프라인/설치형 동작 추가 (선택).
- 커스텀 도메인 연결 (DEPLOY.md 참조).
- 샘플 세트를 저장소 외부(별도 데이터 URL)로 분리해 저장소 크기 관리.
- 다국어(i18n) 또는 영어 UI 추가.

## 8. 원본 저장소와의 관계

이 프로젝트는 원본 펌웨어 연구 저장소(`apps/smk37-patch-set-editor/`)에서
**추출·독립**된 것입니다. 원본 쪽 변경사항이 생기면 이 디렉터리로 다시
포팅해야 하며, 반대 방향도 마찬가지입니다. 원본과의 공통 코어는
`public/sysex.mjs`와 `tests/`입니다.
