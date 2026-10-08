# v15 baseline analysis

공식 v15 펌웨어를 독립적으로 역공학한 결과만 저장한다.

## Evidence rules

- v12의 함수 주소, 구조체, ABI, 전역 변수, 코드·데이터 영역 가정을 v15에
  이식하지 않는다.
- 다른 버전과의 유사성은 검색 힌트로만 사용할 수 있으며 패치 근거가 될 수
  없다.
- 함수 경계와 호출 규약은 v15 내부의 호출자, 피호출자, 레지스터 사용 및
  메모리 교차참조로 입증한다.
- 데이터 구조는 v15의 실제 읽기·쓰기 지점과 범위 검사로 입증한다.
- 각 분석 결과에는 입력 SHA-256, 주소 범위, 재현 명령, 반증 가능 조건을
  기록한다.
- 설명 가능한 C 수준 의사코드와 독립적인 검증이 확보되기 전에는 Flash
  패치를 만들거나 설치하지 않는다.

## Current status

추정 기반 v15 M01~M08 실험은 폐기되었다. 공식 v15 패키지와 장치 기준선,
원본 추출·검증 도구 및 복구 수단만 유효한 출발점으로 취급한다.

메모리 영역, 실행 공간, RAM/저장 객체 및 placement 판정의 기준 문서는
[`MEMORY-MAP.md`](MEMORY-MAP.md)이다. 새 분석에서는 먼저 이 문서를 읽고,
`OCCUPIED`, `BLOCKED`, `REFUTED`, `PARTIAL`, `UNREVIEWED` 상태를 구분한다.
특히 listing gap을 free space로 승격하려면 문서의 code/data boundary,
branch reach, xref, lifecycle hook 및 byte-fit 조건을 모두 다시 입증해야 한다.

현재 mod 가능 범위와 정적·빌드·실기 검증 상태는
[`mod-capability-matrix.md`](mod-capability-matrix.md)에서 추적한다. 문서의
주소, SHA-256, R01 manifest, 보호 영역과 체크 상태는 다음 명령으로 대조한다.

```sh
python3 tools/validate_v15_mod_capabilities.py
```

UI, MIDI, FM, PCM 재생과 실시간 synthesis의 공개 자료 조사 및 가능성 비교는
[`subsystem-feasibility/matrix.md`](subsystem-feasibility/matrix.md)에 통합했다.
분야별 근거 문서와 `smk-37-pro-docs` 계보는 같은 디렉터리에 있으며 다음 명령으로
revision, 필수 근거, 상태 표시와 링크를 검증한다.

```sh
python3 tools/validate_v15_subsystem_feasibility.py
```

장치 연결 전 UI renderer, event/state, Patch selection과 persistence 정적 분석은
[`ui-preflash/README.md`](ui-preflash/README.md)에 통합했다. 공식 v15 입력에서
분석 script와 JSON evidence를 다시 생성하고 핵심 주소 및 미확정 상태를 확인하려면:

```sh
python3 tools/validate_v15_ui_preflash.py
```

The current clean-room PI32 and USB MIDI result is documented in
[`evidence.md`](evidence.md). Reproduction artifacts are:

- [`analyze_v15.py`](analyze_v15.py): exact-image hash guard, package layout,
  runtime-base derivation, and USB MIDI byte-pattern evidence.
- [`run_ghidra_upstream.sh`](run_ghidra_upstream.sh): pinned upstream Ghidra
  processor setup and headless invocation.
- [`V15Pi32Xrefs.java`](V15Pi32Xrefs.java): heuristic PI32 disassembly, call
  accounting, and USB/MIDI xref probe.

초기 clean-room PI32 분석만으로는 receive/dispatch entry point를 방어적으로
식별하지 못했다. 이후 공식 SDK signature와 공식 v15 내부 데이터 흐름을 별도로
교차검증해 R01 정적 후보를 만들었지만, R01은 아직 실제 장치에 Flash하지 않았다.

2026-08-15 SDK 앱 브릭 이후, "무엇이 참이어야 다시 USB로 플래싱할 수 있는가"를
기준으로 메모리 맵을 확장한 결과는
[`usb-flash-readiness/`](usb-flash-readiness/README.md)에 있다. 물리 플래시
1 MiB 전체 타일링, 런타임 `0x02000000` 창의 UI→Synth 소유권, 미해독 256 KiB,
그리고 SDK 기본 레이아웃이 요구하는 SDRAM 창(`0x04000000`)의 BLOCKED 판정을
포함한다. 링크 맵 게이트는 `tools/check_sdk_app_layout.py`이고, 운영 절차는
[`docs/usb-flash-safety-case.md`](../../../docs/usb-flash-safety-case.md)이다.
