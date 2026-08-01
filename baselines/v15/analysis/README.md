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

The current clean-room PI32 and USB MIDI result is documented in
[`evidence.md`](evidence.md). Reproduction artifacts are:

- [`analyze_v15.py`](analyze_v15.py): exact-image hash guard, package layout,
  runtime-base derivation, and USB MIDI byte-pattern evidence.
- [`run_ghidra_upstream.sh`](run_ghidra_upstream.sh): pinned upstream Ghidra
  processor setup and headless invocation.
- [`V15Pi32Xrefs.java`](V15Pi32Xrefs.java): heuristic PI32 disassembly, call
  accounting, and USB/MIDI xref probe.

No receive/dispatch entry point was identified defensibly. No patch or flash
artifact was produced.
