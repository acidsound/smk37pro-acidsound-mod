# FM Drum SysEx 추가 사례 비교

## 결론

추가 사례를 비교하면 원인 후보를 크게 좁힐 수 있다. 현재 확인된 사실은 다음과 같다.

- `HH/Hi-Hat 1.syx`는 장비에서 정상.
- `HH/Hi-Hat 2.syx`는 장비에서 실패.
- 두 파일 모두 163바이트 Yamaha DX7 single-voice SysEx이며 header, terminator, checksum이 정상.
- `~/Downloads/fmDrumSet`의 26개 파일을 읽기 전용으로 검사한 결과 모두 같은 163바이트 형식과 유효 checksum을 가진다.
- 따라서 현재 증거는 전송 형식 오류보다 SMK 음원 엔진과 특정 voice parameter 조합의 호환성 문제를 가리킨다.

## 추가 비교에서 얻은 강한 단서

### Hi-Hat 1과 Hi-Hat 2

155바이트 voice payload 중 **16개 음색 파라미터 byte**가 다르고, 10바이트 이름 필드 중 한 byte도 다르다. checksum까지 포함한 원본 SysEx 차이는 18바이트다.

주요 차이는 다음과 같다.

| Runtime offset | 의미 모델 | Hi-Hat 1 | Hi-Hat 2 |
|---:|---|---:|---:|
| `3` | OP1 EG rate 4 | 11 | 10 |
| `24` | OP2 EG rate 4 | 20 | 19 |
| `37` | OP2 output level | 94 | 97 |
| `42..45` | OP3 EG rates 1..4 | 77,64,96,60 | 72,55,90,61 |
| `64..65` | OP4 EG rates 2..3 | 28,99 | 24,91 |
| `85,87` | OP5 EG rates 2,4 | 28,20 | 26,19 |
| `100` | OP5 output level | 91 | 92 |
| `105,106,108` | OP6 EG rates 1,2,4 | 76,60,60 | 64,50,58 |
| `135` | feedback | 0 | 7 |

Algorithm은 두 파일 모두 `10`, transpose도 둘 다 `24`다. 그러므로 algorithm 또는 transpose 자체가 원인이라는 근거는 없다. `feedback=7`은 유력한 단일 후보지만, 다른 16개 payload 차이와 분리되지 않았으므로 아직 확정할 수 없다.

### Hi-Hat 1과 Open HiHat

이 비교가 특히 유용하다. 두 파일은 음색 파라미터 영역에서 **runtime offset 68과 106, 두 바이트만** 다르고, 나머지는 10바이트 이름 필드 차이다.

- Hi-Hat 1 runtime `68`: `99`, Open HiHat: `0`
- Hi-Hat 1 runtime `106`: `60`, Open HiHat: `48`
- runtime `68`은 현재 map에서 OP4 EG level 2, `106`은 OP6 EG rate 2로 해석된다.
- 두 파일 모두 algorithm `10`, feedback `0`, transpose `24`다.

따라서 Open HiHat을 장비에서 시험하면 다음을 빠르게 분리할 수 있다.

1. Open HiHat이 정상이라면, SMK가 feedback 7 자체를 거부한다는 가설은 약해지고 Hi-Hat 2의 여러 EG/output 조합 중 하나를 의심하게 된다.
2. Open HiHat도 실패한다면, OP4 EG level 2와 OP6 EG rate 2 조합 또는 해당 voice family의 특정 envelope 조건을 우선 조사한다.

## 생성한 단일 변경 진단 파일

원본 Downloads 파일은 수정하지 않았다. 분석 디렉터리의
`controlled-variants/`에 다음 host-side SysEx를 생성했다.

1. `Hi-Hat-1-feedback-7.syx`
   - Hi-Hat 1에서 runtime `135` feedback만 `0 -> 7`로 변경.
   - checksum 재계산.
2. `Hi-Hat-1-open-hihat-byte68.syx`
   - Hi-Hat 1에서 runtime `68`만 `99 -> 0`으로 변경.
   - checksum 재계산.
3. `Hi-Hat-1-open-hihat-byte106.syx`
   - Hi-Hat 1에서 runtime `106`만 `60 -> 48`로 변경.
   - checksum 재계산.

이 파일들은 firmware가 아니며 자동 전송하지 않았다. 장비 테스트 시 Patch Set Editor에 개별 파일로 넣어 수동 비교하면 된다.

## 권장 수동 테스트 순서

1. `Hi-Hat-1-feedback-7.syx`
2. `Hi-Hat-1-open-hihat-byte68.syx`
3. `Hi-Hat-1-open-hihat-byte106.syx`
4. `Open HiHat.syx`
5. 필요하면 `CL.HI-HAT.syx`

`Hi-Hat 1`과 `Open HiHat`의 차이는 두 음색 파라미터로 좁혀져 있으므로, 두 번째와 세 번째 단일 변경 파일은 각각 하나씩 분리하는 진단용이다. 각 테스트는 한 파일만 전송하고, 패드에서 해당 음을 눌러 소리가 나는지 확인한다. Chrome/Web MIDI 상태와 무관하게 사용자가 이미 확인한 CoreMIDI 경로를 사용하면 된다.

## 판단 범위

이 비교는 원인 후보를 좁히지만, 특정 byte 하나가 반드시 문제라고 증명하지는 않는다. 실제 음향 결과가 필요한 항목은 장비에서 수동으로 확인해야 한다. 현재 단계에서는 `Hi-Hat 2`를 Drum Preset에 사용하지 않고, `Hi-Hat 1` 또는 사용자가 정상으로 확인한 별도 음색을 사용하는 것이 안전하다.

검사 스크립트: `compare_fm_drum_cases.py`
검사 결과: `inventory.json`
