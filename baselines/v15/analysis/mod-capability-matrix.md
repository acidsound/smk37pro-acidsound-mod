# Official v15 mod capability matrix

이 문서는 공식 SMK-37 Pro v15에서 **현재 근거를 가지고 수정할 수 있는 요소**와
아직 검증되지 않은 요소를 구분한다. 과거 v12 주소나 폐기된 v15 M01~M08의
추정은 패치 근거로 사용하지 않는다.

## 판정 기준

각 항목은 다음 세 단계를 독립적으로 표시한다.

- **정적 근거**: 공식 v15 앱 내부의 바이트, 호출자, 레지스터, 데이터 흐름 또는
  공식 SDK와의 독립 대조로 구조를 입증했다.
- **빌드 검증**: exact-SHA 입력 제한, 예상 원본 바이트 확인, 출력 manifest,
  보호 영역 불변 및 OTA dry-run을 코드로 검사했다.
- **실기 검증**: 해당 기능을 포함한 바로 그 산출물을 실제 장치에 Flash하고
  청취·조작·회귀 시험까지 통과했다.

`[x]`는 완료, `[ ]`는 미완료다. **정적 근거와 빌드 검증만 완료된 항목을 실제
장치에서 동작한다고 해석하면 안 된다.**

검증 명령:

```sh
python3 tools/validate_v15_mod_capabilities.py
```

## 현재 capability matrix

| ID | 수정 가능한 요소 | 정적 근거 | 빌드 검증 | 실기 검증 | 현재 확실한 범위 |
|---|---|:---:|:---:|:---:|---|
| `PKG-01` | 공식 v15 앱만 변경해 FWSC 재패키징 | [x] | [x] | [x] | 앱과 CRC 필드만 변경하고 boot/config/resources를 동일하게 유지한 R01 계열 패키지의 설치·부팅과 공식 v15 복원을 실기 확인했다. |
| `MIDI-01` | MIDI 채널 번호 판별 | [x] | [x] | [x] | dispatcher `0x0201c5ec`의 `r9 == 9` 분기가 물리 Pad의 human Ch10 입력에서 실제로 도달하며 Ch1과 다른 경로를 선택함을 청취 확인했다. |
| `VOICE-01` | Ch10 Note On의 음색 소스 경로 분리 | [x] | [x] | [x] | Note On 복사 지점 `0x0201c67c`에서 Ch10만 stock Ch1과 다른 source로 라우팅할 수 있다. 단, 그 source에 의도한 factory 음색을 설정하는 방법은 아직 실패 상태다. |
| `VOICE-02` | Ch1 및 비-Ch10 채널의 현재 UI Patch 유지 | [x] | [x] | [x] | R01 계열에서 Ch1은 현재 UI Patch 음색을 유지하고 Ch10은 다른 소리를 냈다. 채널별 음색 경로 분리 자체는 실기 입증됐다. |
| `VOICE-03` | 공식 factory voice를 dispatcher runtime source로 변환 | [ ] | [x] | [ ] | 128-byte factory entry를 156-byte로 확장하는 코드는 재현되지만, HAND DRUM·BUZZ BASS·Mooger #1 실기 비교가 모두 의도한 음색과 불일치했다. 직접 snapshot 주입 가설은 폐기했다. |
| `NOTE-01` | Ch10 Note On/Off에 동일한 음색 source 사용 | [x] | [x] | [x] | R01은 Note Off 불일치로 고착음이 발생했다. R01b/R01c에서 `0x0201c67c`와 `0x0201c63e`를 같은 Ch10 source로 라우팅하자 Note Off가 정상화됐다. |
| `NOTE-02` | 원래 note number와 velocity 사용 | [x] | [x] | [ ] | R01은 음색 복사 원본만 바꾸며 Note On 이벤트의 note/velocity 처리 코드는 바꾸지 않는다. HAND DRUM이 입력 음정에 따라 transpose되는 결과는 아직 청취하지 않았다. |
| `UI-01` | 펌웨어 버전 표시 문자열 변경 | [x] | [ ] | [x] | 과거 v15 marker-only M01/M02에서 화면 표시 변경과 정상 부팅을 사용자가 확인했다. 현재 R01 빌더에는 이 변경이 포함되지 않으며, 재사용 가능한 v15 UI 패치 API로 정리되지 않았다. |
| `OTA-01` | exact-hash 전용 사용자 패키지 OTA 경로 | [x] | [x] | [ ] | `upload-v15-r01`은 R01 SHA와 확인 token만 허용하고 packet/bounds dry-run을 통과한다. R01 실전 OTA는 미실행이다. |

## R01에서 실제로 변경되는 범위

R01은 다음 네 앱 주소 범위만 직접 수정한다.

- `0x0201c67c`: Note On의 원본 memcpy 호출을 Ch10 wrapper 호출로 교체
- `0x0201e13e`: wrapper와 `HAND DRUM ` runtime snapshot 저장
- `0x0201e468`, `0x0201e49c`: 교체된 SysEx routine의 기존 직접 호출자 중립화

결과 앱 SHA-256:
`e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7`

결과 FWSC SHA-256:
`292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462`

상세 변경 바이트와 protected-region hash는
[`flash-candidates/R01/app-manifest.json`](flash-candidates/R01/app-manifest.json)과
[`flash-candidates/R01/package-manifest.json`](flash-candidates/R01/package-manifest.json)에
기록되어 있다.

## 명시적으로 미검증 또는 제어 불가능한 항목

| ID | 항목 | 상태 | 필요한 추가 근거 또는 시험 |
|---|---|---|---|
| `DRUM-01` | note별 16개 드럼 음색 매핑 | [ ] 미구현 | 먼저 하나의 알려진 factory Patch를 Ch10에 정확히 선택하는 runtime 객체 생성 경로를 입증해야 한다. 그 뒤 note number별 객체/sample 선택과 동시발음 비용을 검증한다. |
| `PAD-01` | 물리 패드의 Ch10 MIDI 및 분기 도달 | [x] 실기 확인 | 물리 문제 해결 후 Pad가 `99 24 66`을 출력했고 R01의 Ch10 분기에서 Ch1과 다른 소리를 냈다. Pad scan callback 주소 자체는 여전히 정적 미확정이다. |
| `FM-01` | 156-byte voice 내부 FM 파라미터의 의미별 편집 | [ ] 부분 확인 | packed-to-runtime 변환은 재현했지만 각 operator/envelope 필드의 runtime 의미와 범위는 완전히 검증하지 않았다. |
| `UI-02` | 화면 renderer, 메뉴, Patch 이름, 상태 갱신 | [ ] 미조사 | 렌더링 함수, UI 객체, 호출자와 갱신 트리거를 v15 내부에서 교차 입증해야 한다. |
| `UI-03` | 버튼 이벤트 및 LED 제어 | [ ] 미조사 | 후보로 보인 SDK 구조는 operation size가 달라 폐기됐다. 현재 주소나 ABI를 주장하지 않는다. |
| `CTRL-01` | Program Change, CC, pitch bend의 채널별 음색 제어 | [ ] 미검증 | 일부 ingress와 16-slot pitch-bend state는 확인했지만 R01 적용 후 controller 회귀와 채널별 라우팅은 실기 검증하지 않았다. |
| `POLY-01` | Ch1/Ch10 동시 발음과 voice allocation 격리 | [ ] 미검증 | 겹치는 Note On/Off, release 순서, voice stealing을 실제 장치에서 검사해야 한다. |
| `SYSEX-01` | Yamaha single-voice SysEx pack/save 보존 | [ ] R01에서 의도적으로 비활성 | R01 code/snapshot 공간이 해당 routine을 대체한다. 이 기능이 필요하면 별도 안전한 코드 저장 공간을 입증해야 한다. |
| `STAB-01` | 재부팅·고착음 없는 장시간 안정성 | [ ] 미검증 | 실제 R01 Flash 후 반복음, 동시발음, controller, UI, 10분 이상 soak test가 필요하다. |

## 실기 검증 체크리스트

R01을 Flash할 수 있는 장치가 연결되면 아래 순서로 체크한다.

- [ ] `device-info`가 `SMK-37 Pro_015`를 반환한다.
- [ ] R01 `upload-check`와 exact SHA gate가 통과한다.
- [x] R01 OTA 설치 후 정상 모드로 재부팅한다.
- [x] Ch1 세 음이 현재 UI Patch로 들린다.
- [ ] Ch10 세 음이 의도한 알려진 factory 음색으로 들리고 Ch1과 구별된다. Ch1과의 분리만 통과했고 음색 지정은 실패했다.
- [x] R01b/R01c에서 Ch1과 Ch10 모두 Note Off가 정상이며 고착음이 없다. 원 R01은 실패했다.
- [ ] Ch1/Ch10 겹침 발음과 양쪽 release 순서가 정상이다.
- [ ] note number와 velocity 변화가 발음에 반영된다.
- [ ] Program Change, CC, pitch bend가 재부팅을 유발하지 않는다.
- [ ] Patch UI, 건반, 노브, 페이더와 USB MIDI 입출력이 회귀하지 않는다.
- [ ] 10분 반복 재생에서 재부팅, 음 고착, 음색 교차 오염이 없다.
- [ ] 실패 시 exact official v15 패키지로 복원되고 identity `015`를 확인한다.

실기 결과는 기능별로만 승격한다. 채널 분기와 Note Off 수정의 성공을
factory 음색 선택 성공으로 확대 해석하지 않는다.

## 근거 문서

- [`sdk-signatures/evidence.md`](sdk-signatures/evidence.md): 공식 SDK 대조와 v15 MIDI ingress 근거
- [`quarkslab/evidence-report.md`](quarkslab/evidence-report.md): PI32v2 decoder 범위와 한계
- [`evidence.md`](evidence.md): runtime base와 USB MIDI 구조
- [`flash-candidates/R01/app-manifest.json`](flash-candidates/R01/app-manifest.json): R01 앱 변경 바이트
- [`flash-candidates/R01/package-manifest.json`](flash-candidates/R01/package-manifest.json): 패키지 변경 범위와 보호 영역 불변
