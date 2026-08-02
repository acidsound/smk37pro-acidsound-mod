# v15 UI preflash reverse-engineering checkpoint

Date: 2026-08-02 UTC

## Status

이 checkpoint는 공식 v15 UI를 장치 연결 전에 정적으로 조사한 결과다. 패치, OTA,
Flash는 수행하지 않았다. 분석 입력은 app SHA-256
`36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`, runtime
base `0x02000000`로 고정한다.

현재 결론은 **UI 구조의 핵심 상태와 Patch 데이터 흐름, 저장 방향과 bounds/return
규약은 상당 부분 확보했지만, 안전한 UI patch를 작성할 정도로 renderer/LCD/button
ABI가 모두 닫히지는 않았다**는 것이다.

## 요구사항 상태

| Requirement | 상태 | 현재 근거 | 남은 차단점 |
|---|---|---|---|
| REQ-01 주소 provenance | 완료 | 모든 분석 script가 official app SHA와 runtime base를 확인 | 없음 |
| REQ-02 renderer entry | 부분 | `0x02020376 -> 0x0201a67c`에서 `Keys Channel-` descriptor `0x02058314` 전달을 직접 확인. `0x0200ea9a` text parser, `0x0200f74c` render traversal 후보 | setter에서 traversal/redraw까지 직접 caller/data-flow chain 미확보 |
| REQ-03 same-length text/color | 정적 완료, 과거 실기 있음 | 문자열/색상 위치와 v15 M01/M02 표시 관찰 | 재사용 가능한 exact-SHA UI builder 미작성 |
| REQ-04 menu state | 부분-강함 | RAM base `0x01c33260`, screen/submode와 grid state field 확인 | 각 state value와 실제 화면 이름의 대응 미확정 |
| REQ-05 button/input ABI | 부분 | 11-entry vector `0x02058248`, encoder enclosing entry/caller, pending event consumer 확인 | exhaustive listing에도 vector base/index dispatcher와 pending producer가 없어 실제 물리 button ID 미확정 |
| REQ-06 LCD/update | 미완료 | ST7789-like bytes는 존재 | overlapping halfword-table 사용이 있어 LCD table로 확정 불가, write/framebuffer 경로 없음 |
| REQ-07 RAM ownership | 미완료 | 주 UI object base와 여러 field access 확인 | free RAM, callback context, reentrancy, scratch ownership 미확정 |
| REQ-08 persistence | 정적 완료 | `0x02004b02` ABI와 모든 decoded caller에서 RAM→storage 방향, bounds, count-style return, 별도 read wrapper를 확인 | `0x02063260` 내부 command 이름과 실제 전원차단/매체 오류 동작은 runtime 검증 필요 |
| REQ-09 callable ABI | 부분 | 여러 후보의 argument/register/field access 정리 | semantic name과 clobber/reentrancy를 모두 확정하지 못함 |
| REQ-10 listing provenance | 완료 | raw byte, recursive, exhaustive 근거를 분리 | 없음 |

## 새로 확보한 핵심 구조

### Main UI/Patch state object

Base: `0x01c33260`

| Field | 현재 해석 | 등급 |
|---:|---|---|
| `+0x200` | screen/page state byte | 후보 |
| `+0x302` | submode/grid state, `0x02029528`이 값 2..6 dispatch | 강한 후보 |
| `+0x309..+0x30f` | one-shot pending input bytes | 강한 후보 |
| `+0x3a4` | selected factory bank, 0..3 | 확정 |
| `+0x3a0 + bank` | bank별 selected preset, 0..31 | 확정 |
| `+0x129c + bank*32+preset` | per-preset dirty/saved flag | 확정 |
| `+0x1a14` | current expanded Patch record/snapshot base | 확정 |
| `+0x1a90`, `+0x1aa0` | expanded/display-related Patch fields | 강한 후보 |

현재 Note event 소비 버퍼 `0x01c34c74`는 loader destination 자체와 구분된다.
`0x0201c5ec`가 해당 버퍼에서 156 bytes를 per-note/voice slot으로 복사한다.

### Function map

| Address | 역할 | 등급 |
|---:|---|---|
| `0x02005660` | selected bank/preset factory record loader 및 UI field expansion | 확정 |
| `0x02029290` | UI state-machine/render-update | 강한 후보 |
| `0x02029528` | `+0x302` 기반 grid/submode dispatch | 강한 후보 |
| `0x0201e06c` | dirty/redraw/event trigger | 후보 |
| `0x0202439e` | centered `0x3f` delta를 처리하는 encoder handler | 강한 후보 |
| `0x02058248` | 11-entry internal callback vector | table 존재 확정. 정적 listing에서 dispatcher/caller 미발견, physical event ID로 승격 금지 |
| `0x0201a67c` | object field `+0x24` C-string setter | 기능 형태 확정. `0x02020376`에서 `Keys Channel-` descriptor 전달 직접 확인 |
| `0x0200ea9a` | text extent/markup parser | 후보 |
| `0x0200f74c` | object render traversal/computed callback dispatch | 후보 |
| `0x02026d6c` | current Patch record save writer | 강한 후보 |
| `0x02004b02` | bounded RAM→storage write wrapper | ABI, 방향, bounds, count-style success return 정적 확정 |
| `0x0202553c` | bank-level load/commit preparation | 후보 |

## Drum Set UI C-level design, current safe interpretation

아래 코드는 구현물이 아니라 현재 근거에 맞춘 설계 모델이다.

```c
struct V15UiState {
    uint8_t opaque_0000[0x200];
    uint8_t page;                 // +0x200, semantic values unresolved
    uint8_t opaque_0201[0x101];
    uint8_t submode;              // +0x302, observed dispatch values 2..6
    uint8_t opaque_0303[0x6];
    uint8_t pending_event[7];     // +0x309..+0x30f
    uint8_t opaque_0310[0x90];
    uint8_t selected_preset[4];   // +0x3a0..+0x3a3
    uint8_t selected_bank;        // +0x3a4
};

struct DrumSlotRef {
    uint8_t bank;                 // 0..3
    uint8_t preset;               // 0..31
    int8_t transpose;
    uint8_t level;
};

struct DrumSet {
    char name[12];
    struct DrumSlotRef slot[16];
};
```

### Proposed interaction model

1. 기존 16-slot grid code path를 재사용한다.
2. slot 선택은 기존 low/high nibble highlight state를 사용하되, 실제 field 의미가
   확정된 후에만 연결한다.
3. bank/preset은 이미 입증된 `+0x3a4`, `+0x3a0+bank` 선택 모델과 동일한 범위를
   사용한다.
4. encoder는 `0x0202439e` 또는 callback vector의 clamp/update idiom을 재사용하되
   dispatcher caller와 event ID를 먼저 확정한다.
5. label 갱신은 object string setter 후보 `0x0201a67c`의 caller 중 known UI string을
   전달하는 call site를 찾아 ABI를 확정한 뒤에만 사용한다.
6. persistence는 기존 163-byte (`0xa3`) Patch record를 변경하지 않는다. Drum Set은
   별도 versioned record로 저장해야 하며 storage direction, bounds, failure recovery를
   확인하기 전에는 VM/USRFLASH write를 추가하지 않는다.

### Why existing grid reuse is preferred

- `0x02029528` 아래에 여러 16-slot grid path가 이미 존재한다.
- 새 page, font, bitmap 또는 framebuffer를 만들 필요가 줄어든다.
- 현재 renderer와 LCD write가 미확정이므로 기존 object/widget graph를 재사용하는
  것이 새로운 graphics path보다 훨씬 안전하다.

## 반드시 추가로 해결할 항목

1. `0x02058248` vector를 읽는 computed dispatcher와 실제 physical event ID. exhaustive
   listing과 raw-byte search에서 base/index access가 나오지 않아 runtime trace 또는 더 완전한
   PI32 decoder가 필요하다.
2. descriptor pointer에서 setter까지는 `Keys Channel-` 경로로 확인했다. setter 이후
   `0x0200f74c` traversal 또는 `0x0201e06c` redraw까지의 직접 경로가 더 필요하다.
3. `0x0201e06c`의 정확한 redraw/event 의미와 argument ID `0x14`, `0x19`의 의미.
4. `0x02063260` 내부 command 이름과 실제 storage failure/power-loss 동작. 상위 wrapper의
   RAM→storage 방향, bounds, short/failure→0 반환은 정적으로 확정했다.
5. boot/default load path의 실기 결과와 save failure 후 UI 상태.
6. renderer callback context, stack/clobber, RAM scratch ownership.
7. LCD write/framebuffer path. 기존 grid/widget를 그대로 재사용한다면 R06 초기 버전에
   필수는 아닐 수 있지만 custom graphics에는 필수다.

## Reproduction

```sh
python3 baselines/v15/analysis/ui-preflash/renderer/analyze_renderer.py
python3 baselines/v15/analysis/ui-preflash/events/analyze_ui_events.py
python3 baselines/v15/analysis/ui-preflash/state-persistence/analyze_state_persistence.py
python3 baselines/v15/analysis/ui-preflash/followup/analyze_renderer_xref.py
python3 baselines/v15/analysis/ui-preflash/followup/analyze_event_dispatcher.py
python3 baselines/v15/analysis/ui-preflash/followup/analyze_persistence_direction.py
python3 tools/validate_v15_ui_preflash.py
```

## Files

- [`renderer/evidence-report.md`](renderer/evidence-report.md)
- [`events/report.md`](events/report.md)
- [`state-persistence/report.md`](state-persistence/report.md)
- [`followup/renderer-xref.md`](followup/renderer-xref.md)
- [`followup/event-dispatcher.md`](followup/event-dispatcher.md)
- [`followup/persistence-direction.md`](followup/persistence-direction.md)
- [`review/requirements.md`](review/requirements.md)
