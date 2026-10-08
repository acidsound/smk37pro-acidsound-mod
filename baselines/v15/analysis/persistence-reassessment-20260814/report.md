# Persistence 재검증 (2026-08-14, S1C6 이후)

범위: 휘발성 RAM persistence의 모든 기존 시도(S1C6-raw, raw17, S1C7, S1C8,
S1C9, S2)를 S1C6(S16) 설치 이후 기준으로 재검증하고, 새로 열린 경로가 있는지
확인. 장치 작업·플래시 없음 — 오프라인 재검증.

## 1. 기존 시도 요약 (기록 확인)

| 시도 | 상태 | 핵심 |
|---|---|---|
| S1C6-raw-record-persistence | firmware BLOCK | raw fallback 최소 32B vs owned window 여유 2B |
| S1C6-raw17-persistence-block | BLOCK | SAVE dead slice 44B, fallback helper 최소 54B |
| **S1C7** | **live 실패** | 무게이트 — 미시드(전부 0) 스토리지를 신뢰 → 무음. S1C5로 복원 |
| S1C8 (manifest-gated) | BLOCK | 양성 게이트 floor 104B vs SAVE window 84B; CRC ABI 없음 |
| S1C9 (min-budget) | BLOCK | 같은 floor 계산 — CRC 20B 초과; CRC32 테이블은 있으나 callable ABI 없음 |
| S2 (persistent default) | BLOCK | exact-stock fit 실패(266/278, 12B 부족), 불변 소스 테이블 없음 |

## 2. 재검증 결과 (S1C6 app 기준, 오프라인)

| 항목 | 결과 | 근거 |
|---|---|---|
| CRC32 테이블 `0x02059210` (1024B) | **진짜 IEEE CRC32 테이블** — 그러나 **참조 0건** | entry[1]=`0x77073096`(표준 반사 테이블). 32비트 LE 상수 `0x02059210` 앱 전체 스캔 0건, `mov32` 즉시값 패턴(`ff cX` + `10 92 05 02`) 0건, low half `0x9210` 4건은 모두 명령어 내부(홀수 정렬) 우연 일치 |
| callable CRC ABI | **없음 (변함 없음)** | 테이블은 죽은 데이터 — S1C9 결론 유지 |
| S1C6 tail window `0x0201e228..0x0201e254` | 40B reset wrapper + 4B inert tail — **여유 0** | S1C5(42B+2B) 대비 2B 늘었지만 코드 배치에 의미 없음 |
| SAVE dead region `0x02026d80..0x02026dd4` | 84B, 70 nonzero, **호출자 0건** | 유일한 독립 배치 후보. 게이트 floor(104B)에 20B 부족 — S1C8/S1C9 결론 유지 |
| memcpy-like `0x02048cce` | OBSERVED (146 callsites) | 복원 루프에 쓸 수 있으나 게이트+배치 문제를 해결하지는 않음 |

## 3. 결론

**장치측 persistence는 여전히 차단입니다.** S1C6 설치는 배치 수학을 바꾸지
않았고(40B wrapper, tail 여유 없음), callable CRC가 없어 양성 게이트의 핵심
요구(매니페스트 magic/CRC 검증)를 84B SAVE 영역에 맞출 수 없습니다. S1C7
실패 교훈(조용한 무음) 때문에 "magic 없이 raw 복원"은 재고 대상이 아닙니다.

### 참고 — 이론상 축소 게이트 여지 (권장 아님)

4-byte magic + committed flag만 검사하는 **축소 게이트**(CRC 없음)는 84B에
맞을 여지가 있습니다 (read setup 20 + 4-byte magic ~28 + committed ~8 ≈ 56).
그러나 ① CRC가 없어 bit-flip 손상 검출 불가 ② writer(WebMIDI 업데이트 영속화)는
여전히 불가 ③ "읽기 전용 복원"만 가능하면 raw17이 지적한 대로 현재 세션 업데이트를
영속화하지 못해 Release 자산으로 오해 소지. 따라서 권장하지 않습니다.

## 4. 새 실용 경로: 호스트 측 자동 복원 (리스크 0)

S1C6의 **명시적 리셋 + 17패킷 프로토콜**은 "적재된 키트 위 재로드"를 전원
사이클 없이 안전하게 만들었습니다. 이는 **호스트 측 persistence**를 실용적으로
만듭니다:

- 에디터가 마지막으로 전송한 패치 세트(playbackNotes 포함)를 브라우저
  (localStorage/IndexedDB)에 저장.
- 장치가 부팅/재연결되면(또는 사용자가 "재전송" 클릭) 리셋 1 + 보이스 16을
  자동 재전송 — S1C6 안전 재로드 덕에 항상 성공.
- 펌웨어 리스크 0, 기존 S1C6 동작 불변, 실사용 목표("재부팅 후에도 패치
  유지")를 달성. 단점: 호스트(에디터)가 필요 — 독립형 장치 사용에는 해당 없음.

이 프로젝트의 실제 사용 패턴(데스크톱 에디터 + USB)에서는 이 경로가
"장치측 영속화"의 사용자 목표를 리스크 없이 충족합니다.

## 5. 검증 명령 (재현)

```sh
# CRC32 테이블 존재 확인 (entry[1] == 0x77073096)
python3 - <<'PYEOF'
import struct
app = open('baselines/v15/analysis/flash-candidates/S1C6-reset-signature-isolation/app.bin','rb').read()
off = 0x02059210 - 0x02000000
print('entry[1] =', hex(struct.unpack_from('<I', app, off+4)[0]))
print('direct 32-bit refs =', app.count(struct.pack('<I', 0x02059210)))
PYEOF

# SAVE 영역 호출자 0건 (call32/short_call 스캔) — 본 보고서 §2 항목
```

## 6. 상태 문서 반영

- `docs/handoff.md` §7 "휘발성 RAM persistence 미해결" — 재검증 결과 +
  호스트 측 autoload 권장 추가 (2026-08-14).
