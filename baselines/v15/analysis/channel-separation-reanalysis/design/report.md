# 공식 v15 Ch10 별도 음색 설계 A/B/C 비교

Date: 2026-08-02 UTC
Status: **design-ready, patch-ready 아님**
Scope: official v15 app와 R01/R01b/R01c live evidence만 패치 판단 근거로 사용한다. v12 주소와 추정 RAM/code-cave 주소는 사용하지 않는다.

## 1. 결론

| 설계 | 현재 판정 | 핵심 이유 |
|---|---|---|
| **A. UI Patch/runtime object 완전 clone 후 loader 호출** | **거부** | object 경계와 deep-copy 대상이 닫히지 않았고, loader와 네 helper가 live 전역 object에 고정되어 있다. clone을 만들기만 해서는 loader가 clone을 사용하지 않는다. |
| **B. factory bank entry를 기존 loader로 로드한 별도 RAM object** | **문자 그대로는 불가, B′도 반증 해소 전 보류** | 기존 loader에는 caller-supplied destination ABI가 없다. loader output의 첫 `0x9c`만 clone하는 B′도 clean Mooger #1에서 R01c source와 byte-equal했는데 목표 음색은 live 실패했다. tail/helper 외부 상태 의존성을 먼저 분리해야 한다. |
| **C. Note On 시 current object pointer/state 전환** | **전역 state 전환은 거부** | R01이 Note On만 다른 source를 사용해 stuck voice를 냈다. Note Off도 동일 source를 써야 한다. bank/preset/loader를 Note hot path에서 전환하면 UI, helper state, 동시 채널, release 순서에 전역 race가 생긴다. |

권고는 특정 구현 채택이 아니라 **producer side-effect 분리 검증**이다.

1. actual live loader 직후의 full `0xa3` current object와 helper가 갱신한 외부 state를 capture한다.
2. clean/simulated `0x9c` 및 R01c source와 byte 비교한다.
3. target timbre에 필요한 최소 state가 `0x9c` 안에 완전히 포함되는 경우에만 B′ + 제한된 C-source-dispatch를 재검토한다.
4. 그 경우 `r9 == 9`일 때 Note On **및 Note Off**가 같은 immutable source를 복사하고 non-Ch10은 stock `0x01c34c74`를 유지한다.
5. loader, UI selection, storage, helper 호출은 Note path에서 수행하지 않는다.

현재는 dedicated RAM ownership, preload hook, safe code cave가 하나도 확정되지 않았다. 따라서 이 문서는 실행 주소를 갖는 patch spec을 승인하지 않는다.

## 2. 현재 live evidence가 바꾼 전제

[R01 live validation](../../flash-candidates/R01/live-validation-20260802.md)은 다음을 직접 입증했다.

- physical Pad의 human Ch10 입력이 `r9 == 9` 분기에 도달했다.
- Ch10과 non-Ch10이 서로 다른 memcpy source를 선택할 수 있다.
- R01은 Note On만 별도 static 156-byte source를 사용해 Ch10 Note Off가 실패하고 stuck voice가 남았다.
- R01b/R01c는 Note On `0x0201c67c`와 Note Off `0x0201c63e`를 같은 Ch10 source로 보내 Note Off를 복구했다.
- 그러나 HAND DRUM, BUZZ BASS, Mooger #1을 수동 확장한 static 156-byte source는 해당 stock UI Patch와 일치하지 않았다. R01b/R01c에서는 hold 중 pitch가 계속 내려가는 의도하지 않은 소리가 났다.

[`factory-loader/report.md`](../factory-loader/report.md)는 clean Mooger #1에 대해 더 강한 경계를 제공한다.

- pure 128→156 expansion hash: `e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275`
- simulated loader의 first `0x9c` hash: 같은 값
- R01c embedded source hash: 같은 값
- loader는 그 밖에 tail `0x9c..0xa2`, four helper calls, `*(+0x15c)` writes, flag-dependent `+0x86/+0x87` 교환을 수행한다.

즉 clean Mooger에서 “official loader의 첫 `0x9c`만 얻으면 R01c보다 정확하다”는 주장은 성립하지 않는다. actual live RAM readback은 아직 없으므로 외부 state dependency를 확정할 수는 없지만, B′의 self-contained snapshot 전제에는 직접적인 부정 근거다.

따라서 다음 두 가설은 폐기하고 하나는 보류한다.

1. factory의 128-byte record만 수동 확장하면 canonical runtime object가 된다는 가설
2. Ch10 Note On source만 바꾸고 Note Off는 current UI source를 사용해도 된다는 가설
3. **보류:** first `0x9c` clone만으로 stock factory timbre 전체가 self-contained된다는 가설

## 3. 공식 v15에서 닫힌 데이터 흐름

### 3.1 loader destination과 Note source는 같은 물리 주소다

[`runtime-source/report.md`](../runtime-source/report.md)가 공식 listing에서 writer와 consumer를 연결했다.

```text
0x01c33260 + 0x1a14 = 0x01c34c74
```

- `0x02005660`은 selected bank/preset을 읽는다.
- backing record에서 `0xa3` bytes를 `0x01c33260+0x1a14`로 먼저 복사한다.
- 같은 current object 안에서 operator/global fields를 expand/normalize한다.
- `+0x1ab0`의 flag를 읽어 `0x0200552e`, `0x0200558e`, `0x020055f8`, `0x0200562c`를 호출한다.
- dispatcher `0x0201c5ec`는 이 current object의 앞 `0x9c` bytes를 Note On/Off record로 복사한다.

과거 문서의 “direct xref가 consumer에만 있다”는 말은 writer가 base-plus-offset alias로 나타난다는 뜻이다. 두 주소가 별도 object라는 뜻이 아니다.

### 3.2 loader ABI는 전역 current-state 전용이다

공식 v15 listing의 `0x02005660`은 entry에서 인자를 소비하지 않고 다음을 직접 수행한다.

```c
obj = (uint8_t *)0x01c33260;
bank = obj[0x3a4];
preset = obj[0x3a0 + bank];
backing = *(uint8_t **)(obj + 0x164);
memcpy(obj + 0x1a14,
       backing + 0x4000 + (bank * 32 + preset) * 0xa3,
       0xa3);
/* in-place expansion, helper calls, SAVE/SAVED-related update */
```

중요한 경계는 다음과 같다.

- destination pointer argument가 없다.
- object base `0x01c33260`은 loader 안의 immediate다.
- helper들도 같은 live object, 그 object의 포인터 fields, 별도 global synth state를 갱신한다.
- loader function range는 `0x02005660..0x020057de`, 약 `0x180` bytes다. 이는 helper clone 비용을 제외한 크기다.

따라서 “기존 loader를 별도 object에 호출”하는 ABI는 공식 v15에 존재한다고 말할 수 없다.

### 3.3 Note source/destination lifetime

공식 dispatcher의 두 경로는 같은 모양이다.

| Event | copy call | source | destination | length |
|---|---:|---:|---|---:|
| Note Off class | `0x0201c63e` | stock `0x01c34c74` | dispatcher context + indexed `0xa0` stride + `0xa2` | `0x9c` |
| Note On class | `0x0201c67c` | stock `0x01c34c74` | dispatcher context + indexed `0xa0` stride + `0xa2` | `0x9c` |

- **Source lifetime:** 한 번의 `memcpy` 동안 읽을 수 있어야 하는 것만으로는 부족하다. 같은 고정 Ch10 음색의 future Note Off와 future Note On도 같은 object identity를 사용해야 하므로, mapping이 활성화된 동안 immutable이어야 한다.
- **Stock source lifetime:** `0x01c34c74`는 patch selection, bulk patch load, single-parameter write로 갱신되는 live current object다. UI Patch 변경 뒤에도 보존되는 Ch10 고정 음색 source로 직접 사용할 수 없다.
- **Destination lifetime:** `0xa0 = 0x9c + 4` record는 indexed slot에 복사된 뒤 note/velocity/event metadata가 붙는다. listing의 4-bit index와 16-slot bound는 event/voice-record queue의 구조를 보여 주지만, slot이 active oscillator 전체 lifetime을 소유한다는 사실까지 입증하지 않는다.
- **Dynamic Ch10 program change:** Ch10 source를 note hold 중 교체하려면 어떤 generation을 Note Off에 사용할지 active-note별 추적이 필요하다. 현재 근거는 하나의 immutable Ch10 timbre만 다룬다.

## 4. 설계별 평가

## A. UI Patch/runtime object 완전 clone 후 loader 호출

### 필요한 실제 clone 범위

`0x01c33260`은 `+0x1a14` snapshot만 담는 작은 voice struct가 아니다. selection, SAVE/SAVED flags, UI state와 다음 포인터 fields를 포함한다.

- `+0x15c`: loader가 display/control-related fields를 쓰는 object
- `+0x160`: storage image 관련 pointer
- `+0x164`: packed/backing voice banks pointer
- `+0x16c`, `+0x174`, `+0x17c`: helper가 갱신하는 pointed objects

따라서 raw byte copy는 shallow clone일 뿐이다. 포인터가 live UI/synth/storage object를 계속 가리키므로 source와 destination lifetime이 분리되지 않는다. object의 전체 끝, 각 pointee 크기, callback ownership, lock/reentrancy contract도 미확정이다.

### lifetime와 polyphony

- clone을 truly independent하게 만들려면 object graph 전체가 mapping lifetime 동안 살아 있어야 한다.
- immutable `0x9c`만 최종 source로 쓰면 polyphony 위험은 낮아질 수 있지만, full clone 상태에서 loader/helper를 다시 호출하면 shared pointee가 변할 수 있다.
- 16 indexed slots는 16-note polyphony 증거가 아니다. product의 claimed 12-note polyphony와 allocator/stealing은 여전히 별도 미검증 항목이다.

### Note Off

full clone이 있더라도 Note On/Off가 clone의 같은 `0x9c` source를 선택해야 한다. Note On만 clone을 사용하면 R01 failure를 반복한다.

### UI 영향

이론적으로 완전한 deep clone은 UI 격리를 제공할 수 있다. 그러나 현 loader/helper는 clone base를 받지 않고 live global을 직접 사용한다. loader clone과 모든 helper/global access의 parameterization 없이는 live UI와 synth helper state가 바뀐다.

### 필요한 code cave

최소한 loader 본체 약 `0x180` bytes의 clone/rewrite, helper adaptation, object graph용 RAM이 필요하다. 공식 v15에서 이 크기의 safe executable cave와 deep-clone RAM은 입증되지 않았다.

**판정: 거부.** 현재 근거에서 최소 패치가 아니며, full object ABI를 새로 설계하는 작업이다.

## B. factory bank entry를 기존 loader로 로드한 별도 RAM object

### literal B

기존 loader는 별도 destination을 받지 않는다. 항상 live `0x01c34c74`를 덮고 UI/helper side effect를 실행한다. 따라서 literal B는 ABI 차원에서 성립하지 않는다.

### 가능한 변형 B′: loader output을 hot path 밖에서 clone

가장 보수적인 변형은 다음과 같지만, clean Mooger의 first-`0x9c` equality 때문에 아직 유효성이 입증되지 않았다.

1. 공식 UI/loader 경로가 목표 factory Patch를 live `0x01c34c74`에 materialize한다.
2. 그 뒤의 정확한 `0x9c`를 owned Ch10 buffer 또는 검증된 immutable image로 clone/capture한다.
3. Ch10 Note On/Off는 clone만 읽는다.
4. 이후 UI가 다른 Patch를 로드해 stock source를 바꾸어도 Ch10 clone은 바뀌지 않는다.

이 방식은 수동 128→156 converter를 신뢰하지 않고 actual live loader 결과를 사용하려는 시도다. 그러나 clean Mooger의 simulated loader first `0x9c`가 R01c source와 이미 byte-equal하므로, mere `0x9c` clone은 known failure를 개선하지 못할 가능성이 높다.

### 남은 lifetime blocker

- actual live RAM의 `0xa3` readback과 helper 외부 state capture가 없다.
- clean Mooger의 loader-simulated first `0x9c`와 R01c source가 byte-equal하므로 first-`0x9c` self-containment에는 강한 부정 근거가 있다.
- dedicated RAM의 owner, 주소, 초기화 시점, reset lifetime이 미확정이다.
- preload 중 bank/preset을 임시 변경하고 다시 복구하는 방식은 snapshot 외 helper/global side effect를 완전히 복원하지 못한다.
- boot/UI-safe hook과 loader reentrancy가 미확정이다.
- capture한 `0x9c`만으로 target timbre가 self-contained한지, loader helper가 설정한 외부 global state도 필요한지 live A/B 비교가 필요하다.

### polyphony와 Note Off

- clone이 immutable이고 Note hot path가 copy만 하면 모든 Note record는 독립 destination을 사용한다. 이는 A/C global mutation보다 안전하다.
- allocator, maximum polyphony, voice stealing은 수정하지 않지만, R01b/R01c는 exhaustive overlap/release-order test가 아니므로 여전히 live stress가 필요하다.
- Note On과 Note Off의 Ch10 source pointer는 반드시 같아야 한다.

### UI 영향

preload가 끝난 뒤에는 loader/UI를 건드리지 않으므로 낮다. 그러나 preload를 위해 live selection을 임시 변경하는 구현은 높은 UI/synth side effect를 가지므로 승인하지 않는다.

### 필요한 code cave

steady-state에는 channel source wrapper와 `0x9c` source storage만 필요하다. 그러나 preload/capture writer와 RAM ownership이 없으므로 현재 exact 주소나 cave를 제안할 수 없다.

**판정: literal B는 거부. B′는 producer side-effect 분리 실험용 후보일 뿐이며 patch 후보로 승격하지 않는다.**

## C. Note On 시 current object pointer/state 전환

C는 두 의미를 분리해야 한다.

### C1. dispatcher의 memcpy source pointer만 전환

이미 유효하고 self-contained한 Ch10 source가 있다는 조건에서 `r9 == 9`일 때 memcpy source만 전환하는 것은 현재 evidence와 가장 잘 맞는다. R01 계열이 channel branch 도달을 live-prove했다. 다만 clean Mooger 결과 때문에 그 source가 first `0x9c`만으로 구성될 수 있는지는 현재 부정적이다.

그러나 **Note On만** 전환해서는 안 된다. R01 failure 때문에 Note Off에도 동일한 rule과 동일한 source가 필요하다. 따라서 C1은 독립 producer 설계가 아니라 B′의 dispatch half다.

### C2. current bank/preset/object state를 전환하고 loader 호출

- loader object base는 pointer indirection이 아니라 hardcoded immediate다.
- bank/preset을 바꾸면 live current source, expanded UI fields, helper state, SAVE/SAVED display path가 함께 바뀐다.
- Note On 뒤 즉시 복구하면 Note Off는 복구된 stock source를 보게 되어 R01 mismatch를 반복한다.
- Note Off 때 다시 전환해도, overlapping Ch1/Ch10 notes와 UI task 사이에서 global state race가 생긴다.
- loader 호출 시간, interrupt/task context, critical section, rollback behavior가 미확정이다.

### polyphony와 UI

C2는 event마다 전역 current object를 덮으므로 세 설계 중 cross-channel polyphony와 UI 오염 위험이 가장 높다. 동일 음정의 overlapping notes, 역순 release, sustain/all-notes-off에서 어떤 source generation을 복원할지 정의되어 있지 않다.

### 필요한 code cave

source-only C1은 작을 수 있지만 B′ source가 먼저 필요하다. state save/load/restore C2는 loader 호출, selection save/restore, helper side-effect rollback, 동기화를 모두 요구하므로 작은 trampoline으로 끝나지 않는다.

**판정: C1은 B′와 결합할 때만 채택. C2는 거부.**

## 5. code cave와 최소 패치 경계

### 공식 주소로 말할 수 있는 것

- dispatcher: `0x0201c5ec`
- Note Off memcpy call: `0x0201c63e`
- Note On memcpy call: `0x0201c67c`
- memcpy callee: `0x02048cce`
- factory loader: `0x02005660`
- current source: `0x01c34c74`
- current object base: `0x01c33260`

### safe cave로 말할 수 없는 것

R01의 `0x0201e13e`는 빈 cave가 아니었다. Yamaha single-voice bulk pack/save 계열 routine을 덮었고 기존 callers `0x0201e468`, `0x0201e49c`를 neutralize했다. 따라서 그 범위는 기능 보존형 후속 patch의 safe cave로 재사용할 수 없다.

R01 wrapper의 code-only lower bound는 `0x0201e162 - 0x0201e13e = 0x24` bytes였고 embedded source는 별도 `0x9c` bytes였다. 이는 필요한 논리의 크기 근거일 뿐, 같은 주소를 다시 써도 된다는 근거가 아니다.

공식 v15에는 현재 다음이 없다.

- audited free executable cave
- proven-owned mutable RAM buffer
- safe preload/init hook
- loader reentrancy contract

따라서 추정 주소를 포함한 buildable patch spec은 제안하지 않는다.

## 6. 조건부 최소 패치 계약

다음 prerequisite가 모두 닫힌 뒤에만 최소 패치를 만들 수 있다.

1. **Actual live producer proof**: stock UI에서 목표 factory Patch를 선택한 직후 `0x01c34c74..+0xa2`와 helper external state의 exact 값을 capture한다.
2. **Difference proof**: actual live first `0x9c`를 R01c/simulated hash와 비교한다. 같다면 `0x9c`-only B′를 폐기하고 external per-voice dependency를 추적한다.
3. **Self-contained proof**: 다른 UI Patch가 current인 상태에서도 후보 source/state만으로 목표 Ch10 timbre가 유지되는지 확인한다.
4. **Storage proof**: 필요한 state가 immutable flash image 또는 owned RAM buffer로 독립 가능한 경우 그 lifetime과 writer를 확정한다.
5. **Cave proof**: 기존 기능을 희생하지 않는 executable region과 call reach/ABI를 확정한다.
6. **Matched release proof**: Note On/Off가 같은 Ch10 source/state generation을 사용한다.

위 1~6이 모두 통과하고 필요한 per-event state가 `0x9c` source로 완결된 경우에만, 최소 semantic diff를 다음으로 제한한다.

```c
source = (channel_nibble == 9) ? ch10_canonical_source
                               : (const uint8_t *)0x01c34c74;
memcpy(event_record_tone, source, 0x9c); // Note On
memcpy(event_record_tone, source, 0x9c); // Note Off
```

- 원본 note number, velocity, channel metadata, queue index 계산은 바꾸지 않는다.
- loader/UI/storage를 Note path에서 호출하지 않는다.
- source object를 note hold 중 변경하지 않는다.
- exact hook 주소는 위의 두 공식 call site만 후보로 유지한다. trampoline/cave/data 주소는 proof 전까지 지정하지 않는다.

## 7. 필수 검증 matrix

### static/build

- official app SHA-256 exact gate
- 두 hook의 original 6-byte call 확인
- non-Ch10 stock path가 original `memcpy` semantics를 유지하는지 확인
- Ch10 Note On/Off가 byte-for-byte 동일 source address를 고르는지 확인
- code/data placement의 owner와 xref/caller 충돌 확인
- SysEx, UI Patch load/save, protected package regions 불변 확인

### live

1. Ch1 현재 UI Patch와 Ch10 고정 Patch의 청취 A/B identity
2. Ch1/Ch10 overlapping chord, 동일 음정 overlap, 교차 release order
3. Note On velocity 0, explicit Note Off, sustain, all-notes-off/all-sound-off
4. UI Patch를 연속 변경하는 동안 held Ch10 및 새 Ch10 notes의 음색 유지
5. 12-note claim 전후 stress와 voice stealing 관찰
6. 최소 10분 soak, stuck note, pitch drift, UI 표시/SAVE/SAVED 회귀
7. Program Change, CC, pitch bend, SysEx 회귀

R01b/R01c의 “Note Off 정상화”는 2~7 전체를 통과했다는 뜻이 아니다.

## 8. 재현과 문서 검증

```sh
python3 baselines/v15/analysis/channel-separation-reanalysis/runtime-source/trace_runtime_source.py
python3 baselines/v15/analysis/channel-separation-reanalysis/design/validate.py
```

검증기는 official app/listing hash, 주소 alias, loader의 fixed-global ABI, clean Mooger first-`0x9c` equality, Note On/Off original bytes, R01b/R01c matched hooks, live PASS/FAIL 문구와 이 문서의 absolute-address allowlist를 확인한다.

산출물:

- [`report.md`](report.md)
- [`decision-matrix.json`](decision-matrix.json)
- [`validate.py`](validate.py)
- [`validation.txt`](validation.txt)
