# SMK-37 Pro Acidsound Mod

SMK-37 Pro 드럼 머신의 펌웨어 개조(mod) 연구 프로젝트입니다. 공식 펌웨어의 USB
OTA 경로를 직접 분석하고, 내부 **Ch10 드럼 신스**에 임의의 Yamaha DX7 드럼 보이스를
적재할 수 있도록 펌웨어를 개조해 왔습니다. 모든 작업은 실기기에서 검증된 기록을
남기며 진행됩니다.

> ⚠️ **개인 연구용 프로젝트입니다.** 실기기 플래시는 벽돌 위험이 있으며, 모든
> 플래시는 hash-locked OTA 게이트와 rollback 절차를 거친 경우에만 수행하세요.

## 현재 상태 (2026-08)

- **설치된 펌웨어**: 공식 v15(015) 기반 **S1-C5 Marked Playback Note** — 최근
  실기기 flashing 성공(2026-08-04, `post-update=SMK-37 Pro_015 verified`).
- **기능**: 16개 Pad 각각에 DX7 single-voice SysEx를 적재하고, 내부 Ch10 신스의
  발음 음높이(Playback Note)를 Pad별로 지정할 수 있습니다.
- **배포**: 최근 성공한 펌웨어만 [Releases](https://github.com/acidsound/smk37pro-acidsound-mod/releases)에 올립니다.
- **웹 앱**: [Patch Set Editor (GitHub Pages)](https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/) —
  Chrome Web MIDI로 16개 패치를 실기기에 전송하는 무의존성 정적 앱.

## 저장소 구성

```
├── docs/                # mod 작업 문서 (runbook, versioning, 계획, 사고 기록)
├── src/                 # 호스트측 USB OTA 툴 C 소스 (libusb)
├── scripts/             # smk37-fw-direct 래퍼 (MIDIServer 충돌 회피)
├── tools/               # mod 빌드/검증/롤백 스크립트
├── patch-set-editor/    # 웹 에디터 (Pages 호스팅 대상, public/이 사이트 루트)
├── Makefile
└── .github/workflows/   # Pages 배포 (patch-set-editor 하위 경로)
```

개발·분석 과정의 중간 산출물(OTA 로그, flash 덤프, 후보 분석, rollback 재료 등)은
이 저장소에 포함하지 않으며, 로컬 워크스페이스에 보존합니다. 저장소에는 **최종
기록(문서·소스·도구)과 최근 flashing에 성공한 펌웨어만** 올립니다.

## 빌드 (호스트 툴)

요구사항: C11 컴파일러, `pkg-config`, libusb 1.0.30+.

```sh
make
make test
```

실기기 명령은 macOS에서 `MIDIServer`가 USB-MIDI 인터페이스를 점유하지 않도록
래퍼를 사용합니다.

```sh
scripts/smk37-fw-direct device-info
scripts/smk37-fw-direct dump backups/live.bin
```

## 웹 에디터

[`patch-set-editor/`](patch-set-editor/)의 에디터는 main push 시 GitHub Actions가
자동으로 Pages에 배포합니다.

- 사이트: <https://acidsound.github.io/smk37pro-acidsound-mod/patch-set-editor/>
- 사용: Desktop Chrome에서 열고 **Web MIDI 연결** → SysEx 권한 허용 → 패치 로드 →
  **16개 Patch 전송**. (재부팅 후에는 반드시 재전송)
- 상세: [`patch-set-editor/README.md`](patch-set-editor/README.md)

## 안전 규칙 (핵심)

- OTA 업로더는 **정확한 SHA-256 매칭 게이트**만 허용합니다. 임의 스위치로
  대체하지 마세요.
- 실기기 쓰기 전 read-only `device-info`/dump로 기준선을 확보하고, 실패 시
  rollback 절차를 준비한 뒤 진행하세요.
- 이전 실패 사례(M09/M10 부팅 실패, S1C7 live 실패)는 `docs/`에 기록되어
  있습니다. 반복하지 마세요.

## 문서

| 문서 | 내용 |
|---|---|
| [`docs/firmware-runbook.md`](docs/firmware-runbook.md) | 실기기 OTA 절차·안전 경계 |
| [`docs/firmware-versioning.md`](docs/firmware-versioning.md) | 커스텀 빌드 ID 체계·불변 ledger |
| [`docs/fm-drum-plan.md`](docs/fm-drum-plan.md) | Ch10 FM 드럼 확장 계획 |
| [`docs/v15-s1c-status.md`](docs/v15-s1c-status.md) | v15 S1C 시리즈 타임라인·현황 |
| [`docs/m09-brick-incident.md`](docs/m09-brick-incident.md) | M09 부팅 실패 분석 |
| [`docs/forced-recovery-plan.md`](docs/forced-recovery-plan.md) | 강제 복구 계획 |
| [`docs/research-notes.md`](docs/research-notes.md) | 연구 노트·하드웨어 조사 |

## 라이선스·면책

이 저장소는 공식 펌웨어 이미지·플래시 덤프를 포함하지 않습니다(개조 결과물과
문서만 포함). 개조된 펌웨어 사용으로 인한 손상·데이터 손실·보증 상실에 대한
책임은 사용자에게 있습니다. 관련 상표는 각 소유자에게 있습니다.
