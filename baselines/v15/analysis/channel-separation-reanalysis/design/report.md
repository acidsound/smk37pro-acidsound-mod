# v15 Ch10 factory timbre 공급 설계 비교

Date: 2026-08-02 UTC  
Scope: 공식 v15 산출물과 공식 v15에서 생성된 direct evidence만 사용한다. 이 문서는 설계 비교이며 firmware patch를 제안하거나 적용하지 않는다.

## 결론

정상 factory timbre를 Ch10에 공급하는 최소 방향은 **Note hot path에서 loader와 UI selection을 호출하지 않고, official loader가 materialize한 0x9c/156-byte current snapshot을 별도 Ch10 buffer로 pre-load/clone한 뒤 Note On/Off wrapper가 같은 source pointer를 쓰는 구조**다.

다만 현재 direct evidence로는 “어느 시점에, 어느 RAM에, 재진입 없이 clone을 만들 수 있는지”가 아직 확정되지 않았다. 따라서 현 단계의 결정은 **patch-ready가 아니라 design-ready**다. 근거 없이 `0x02005660`을 Note path에 호출하거나 `0x1c33260+0x3a4/+0x3a0` selection을 임시 변경하는 patch는 금지한다.

## 사용한 direct evidence

| Evidence | 확정 내용 | 설계 영향 |
|---|---|---|
| `baselines/v15/analysis/ui-preflash/state-persistence/report.md` | `0x02005660`은 `0x1c33260+0x3a4` bank와 `+0x3a0+bank` preset을 읽고, `*(+0x164)+0x4000+(bank*32+preset)*0xa3`에서 `0x1c33260+0x1a14`로 0xa3 bytes를 복사한 뒤 expanded fields를 갱신한다. | loader는 caller-supplied destination ABI가 아니라 global UI/current snapshot ABI다. |
| 같은 report | `0x1c34c74`는 `0x0201c5ec`에서만 직접 참조되며 Note voice slot으로 0x9c bytes를 복사하는 source다. | Ch10 timbre 교체의 안전한 개입점은 loader가 아니라 Note On/Off의 memcpy source pointer다. |
| `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz` listing snippet | `0x0201c5ec`에서 status low nibble이 `r9`에 보존되고, `r8=#0x1c34c74`, Note Off `0x0201c63e`, Note On `0x0201c67c` 모두 `r2=#0x9c`, `r1=r8`, `call 0x02048cce` 형태다. | channel nibble branch와 matched Note On/Off source 교체는 같은 ABI 표면을 공유한다. |
| `baselines/v15/analysis/flash-candidates/R01/live-validation-20260802.md` | R01 설치 후 Ch10 branch와 non-Ch10 branch가 다른 runtime timbre source를 선택함이 실기 확인됐다. | r9 branch와 Note source switch는 실제 device path에 도달한다. |
| `baselines/v15/analysis/flash-candidates/R01b/app-manifest.json`, `R01c/app-manifest.json` | Note On `0x0201c67c`와 Note Off `0x0201c63e` 모두 wrapper source로 바꾸는 matched design이 산출물에 반영됐다. | stuck note root cause는 양쪽 source 불일치로 모델링해야 하며, 향후 설계도 On/Off source identity를 유지해야 한다. |
| `baselines/v15/analysis/ui-preflash/final-pass/events/report.md` | `0x1c0de20`은 product RAM base로 94 mov hits가 있고, encoder enclosing routines에서 `0x1c0de20 + idx*0x49e3 + 0xa7e/0xa7f` 관계가 보인다. physical dispatcher proof는 아니다. | `0x1c0de20`를 Ch10 voice object source로 직접 승격하면 안 된다. 현재 근거로는 bank/default image 또는 product-state 구조다. |
| `baselines/v15/analysis/ui-preflash/followup/persistence-direction.md` | `0x02004b02`는 RAM->storage write wrapper이며, `0x02024e5c`는 `0x1c0de20 + bank*0x49e3` bank image를 storage에 쓰는 caller다. | `0x1c0de20`의 0x49e3 structures는 storage/default-bank image 관련 근거가 강하며, Note source 0x9c snapshot과 동형이라고 볼 수 없다. |

## 주소별 설계 해석

### `0x1c34c74` Note source

- `0x0201c5ec` 내부에서 `r8=#0x1c34c74`로 잡힌다.
- Note Off path `0x0201c63e`와 Note On path `0x0201c67c`는 둘 다 `r2=#0x9c`로 `0x02048cce`를 호출한다.
- 이 주소는 loader destination이 아니라 already-current voice snapshot consumer다.

설계상 Ch10은 `0x1c34c74` 자체를 바꾸기보다, wrapper에서 `r9==9`일 때 `r1` source만 dedicated Ch10 snapshot으로 바꾸는 쪽이 direct evidence와 맞다.

### `0x02005660` factory loader

- 입력은 register argument가 아니라 global UI state다.
- source는 `*(0x1c33260+0x164)+0x4000+record*0xa3`다.
- destination은 고정된 `0x1c33260+0x1a14`다.
- 이후 `+0x1a90`, `+0x1aa0`, helper `0x0200552e/0x0200558e/0x020055f8/0x0200562c`, SAVE/SAVED 표시 관련 bytes를 건드린다.

따라서 `0x02005660`은 “dedicated buffer에 직접 load하는 ABI”로 사용할 수 없다. 그런 설계는 loader clone 또는 loader 내부 patch를 요구하므로 현 단계에서 근거 없는 patch다.

### `0x1c33260` UI/current state

- `+0x3a4`, `+0x3a0+bank`, `+0x129c`, `+0x1a14`는 patch selection/current snapshot/data-flow 근거가 강하다.
- 하지만 이 state는 UI와 persistence가 공유한다. Note hot path에서 임시 selection을 바꾸면 화면, SAVE/SAVED flag, current patch, helper side effect가 같이 움직일 수 있다.

### `0x1c0de20` existing RAM bank structures

- product RAM base로 다수 접근되고, `idx*0x49e3` bank/default image 단위가 반복된다.
- `0x02024e5c`는 `0x1c0de20+bank*0x49e3`를 storage write source로 사용한다.
- encoder helper caller도 `+0xa7e/+0xa7f` fields를 사용하지만 physical event producer로 승격되지 않았다.

현 direct evidence만으로는 `0x1c0de20` 내부의 어느 offset도 0x9c Note voice snapshot source라고 판정할 수 없다. preloaded pointer 설계가 이 영역을 쓰려면 별도 write/provenance proof가 필요하다.

## 설계별 위험 비교

### 1. Preloaded expanded record pointer

정의: Ch10 전용 source pointer가 이미 loader-equivalent 0x9c/156-byte expanded snapshot을 가리키고, Note On/Off wrapper는 그 pointer만 사용한다.

- ABI 위험: 낮음-중간. Note path의 ABI는 이미 source pointer 교체와 0x9c memcpy로 확인됐다. 다만 preloaded buffer의 소유권과 lifetime은 미확정이다.
- 동시발음 위험: 낮음. immutable snapshot이면 여러 Note slots가 같은 source에서 copy만 하므로 per-voice slot은 분리된다.
- reentrancy 위험: 낮음. Note hot path에서 loader/UI/storage를 호출하지 않는다.
- factory timbre fidelity: loader가 만든 bytes를 preload한다면 가장 높다. static converter bytes를 그대로 두는 방식은 현재 목표와 불일치한다.
- 판정: **선호 설계, 단 buffer/provenance proof 필요**.

### 2. Loader call into dedicated buffer

정의: Ch10 Note On 또는 preload code가 `0x02005660`을 호출해 dedicated Ch10 buffer를 직접 채운다.

- ABI 위험: 높음. loader는 caller destination을 받지 않고 `0x1c33260+0x1a14`에 고정 write한다.
- 동시발음 위험: 중간-높음. Note path에서 loader를 호출하면 global current patch가 변하고, 이미 sounding voices와 release matching에 영향을 줄 수 있다.
- reentrancy 위험: 높음. loader는 UI expanded fields와 helper calls를 수행한다.
- factory timbre fidelity: loader output 자체는 좋지만 dedicated destination ABI가 없다.
- 판정: **거부**. loader clone이나 내부 rewrite 없이는 evidence와 맞지 않는다.

### 3. Existing patch object clone

정의: official loader가 `0x1c33260+0x1a14`에 만든 current Patch object를 Ch10 dedicated buffer로 0x9c/156 bytes clone하고, Note On/Off는 clone을 source로 쓴다.

- ABI 위험: 중간. clone 자체는 memcpy와 same-size object라 간단하지만, desired factory object를 만드는 trigger와 destination RAM ownership이 미확정이다.
- 동시발음 위험: 낮음. clone 이후 immutable buffer를 쓰면 Note slots는 기존 path처럼 copy된다.
- reentrancy 위험: 낮음 if clone is outside Note path, 높음 if selection/load/clone is run during Note On.
- factory timbre fidelity: 높음. static converter가 아니라 firmware loader가 만든 current object를 사용한다.
- 판정: **현실적인 최소 구현 형태**. 단 pre-load phase가 안전하다는 direct evidence가 추가되어야 patch-ready가 된다.

### 4. Temporary selection

정의: Ch10 event 때 `0x1c33260+0x3a4/+0x3a0`를 목표 factory patch로 바꾸고 loader를 호출한 뒤 source를 쓰고 selection을 복구한다.

- ABI 위험: 높음. selection fields는 확정이지만 current UI state와 SAVE/SAVED state까지 side-effect가 있다.
- 동시발음 위험: 높음. Note On/Off 사이에 current snapshot이 바뀌면 stuck-note 또는 wrong-release 재발 가능성이 있다.
- reentrancy 위험: 높음. Note hot path에서 global UI state와 helper calls를 재진입시킨다.
- factory timbre fidelity: 순간적으로는 loader output을 얻을 수 있지만, side effect가 커서 정상 동작을 보장하지 못한다.
- 판정: **거부**. hot path 임시 selection patch 금지.

## 최소 설계 결정

1. Note On/Off wrapper는 계속 matched source identity를 유지한다.
2. Ch10 source는 static hand-written expanded bytes가 아니라 firmware loader가 만든 0x9c/156-byte object의 clone이어야 한다.
3. loader 호출, selection mutation, storage wrapper 호출은 Note hot path 밖으로 밀어낸다.
4. dedicated buffer 주소와 writer/provenance가 direct evidence로 확정되기 전에는 patch하지 않는다.

Recommended next proof before patch:

- `0x1c34c74` writer/producer를 확정하거나, boot/UI-safe time에 `0x1c33260+0x1a14` clone을 둘 RAM ownership을 확정한다.
- clone source가 target factory selection에서 `0x02005660`이 만든 bytes임을 runtime watch 또는 static caller proof로 고정한다.
- matched Note On/Off wrapper가 same pointer를 쓰고 Ch1/non-Ch10 path는 stock source를 유지함을 binary diff와 live Note On/Off stress로 검증한다.
