# v15 event dispatcher follow-up: 0x02058248

Status: 공식 v15 listing/raw bytes 정적 추적 전용. Patch/flash/commit 미수행.

## 입력

- App: `build/v15-official-app.bin`
- SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Listing: `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz`
- Runtime base: `0x02000000`

## 결론

- `0x02058248`의 11-entry code pointer run은 raw table 자체로는 재확인했다.
- 그러나 caller/dispatcher는 공식 v15 exhaustive listing/raw bytes에서 재현 가능한 증거로 발견되지 않았다.
- physical event IDs 승격: **불가**. slot ordinal만 유지한다.
- `0x0202439e`는 vector slot 10의 mid-function delta-update entry다. 정확히 `0x0202439e`를 직접 call/goto하는 listing caller는 없고, 정상 encoder entry `0x02024368`/`0x0202443e`만 `0x02025dea`/`0x02025e06`에서 직접 호출된다.
- `+0x309..+0x30f` pending fields는 state path에서 소비되지만, 이번 exact-offset search에서는 pending field write/caller를 발견하지 못했다.

## 0x02058248 vector entries

- Address: `0x02058248`
- File offset: `0x58248`
- Raw bytes: `129902023699020274990202ce990202f2990202169a02022e9a0202469a0202789a0202aa9a02029e430202`

| slot | table VA | target | raw xrefs to target | direct listing flow to target |
|---:|---:|---:|---|---|
| 0 | `0x02058248` | `0x02029912` | `0x02058248` | none |
| 1 | `0x0205824c` | `0x02029936` | `0x0205824c` | none |
| 2 | `0x02058250` | `0x02029974` | `0x02058250` | none |
| 3 | `0x02058254` | `0x020299ce` | `0x02058254` | `0x020299bc` goto goto 0x020299ce |
| 4 | `0x02058258` | `0x020299f2` | `0x02058258` | none |
| 5 | `0x0205825c` | `0x02029a16` | `0x0205825c` | none |
| 6 | `0x02058260` | `0x02029a2e` | `0x02058260` | none |
| 7 | `0x02058264` | `0x02029a46` | `0x02058264` | none |
| 8 | `0x02058268` | `0x02029a78` | `0x02058268` | none |
| 9 | `0x0205826c` | `0x02029aaa` | `0x0205826c` | none |
| 10 | `0x02058270` | `0x0202439e` | `0x02058270` | none |

Note: target raw xref가 각 table word 자신뿐인 것도 dispatcher 미발견을 뒷받침한다. slot 3의 `0x020299bc -> 0x020299ce`는 같은 local control-flow 내부 goto이며 table caller가 아니다.

## Dispatcher/caller search coverage

| Search class | Coverage/result | 판정 |
|---|---:|---|
| raw 32-bit table base `0x02058248` | 0 hits | 없음 |
| raw 32-bit table file offset `0x58248` | 0 hits | 없음 |
| raw 24-bit file offset `0x58248` | 0 hits | 없음 |
| copied full 44-byte table | ['0x02058248'] | self only |
| copied first 2-entry / 3-entry chunks | ['0x02058248'] / ['0x02058248'] | self only |
| listing text table-range immediates/targets | 1 hit | one false-positive branch into data |
| raw low 16-bit fragment `0x8248` | 4 hits | all unrelated byte/instruction fragments |
| computed call windows | 428 computed calls, 0 table-evidence windows | 없음 |
| indexed memory / word-or-addldw windows | 1976 indexed accesses, 121 word/addldw candidates, 0 table-evidence windows | 없음 |

### Relative/control-flow blocker

- `0x02055b32` `je r0,#0x38f,0x02058258`

The only table-range flow target lands at `0x02058258`, which is the data word for slot 4 (`0x020299f2`) inside the vector. It is not a load/call/jump-table dispatch sequence and is treated as disassembly/data false-positive evidence, not as a dispatcher.

## Adjacent byte run after the vector

Range `0x02058274`..`0x020582d0` is not promoted to physical event IDs.

| address | len | type | subtype | note | raw |
|---:|---:|---:|---:|---|---|
| `0x02058274` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402010120` |
| `0x0205827a` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403020201010120` |
| `0x02058283` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402010321` |
| `0x02058289` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403020401030121` |
| `0x02058292` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402010522` |
| `0x02058298` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403020601050122` |
| `0x020582a1` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403010801070120` |
| `0x020582aa` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402020720` |
| `0x020582b0` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403010a01090121` |
| `0x020582b9` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402020921` |
| `0x020582bf` | 9 | `0x24` | `0x3` | 0x24 is USB CS_INTERFACE; USB_MIDI_IN_JACK | `092403010c010b0122` |
| `0x020582c8` | 6 | `0x24` | `0x2` | 0x24 is USB CS_INTERFACE; USB_MIDI_MS_HEADER | `062402020b22` |
| `0x020582ce` | 0 | | | terminator | |

The repeated `06/09 24 02/03 ...` structure matches USB class-specific MIDI descriptors. It is an explicit blocker against interpreting the adjacent bytes as physical button IDs.

## 0x0202439e caller relation

- Vector slot: `10` -> `0x0202439e`
- Direct flow to exact mid-entry: `[]`
- Enclosing entry `0x02024368` direct flow: `0x02025dea` call 0x02024368
- Enclosing entry `0x0202443e` direct flow: `0x02025e06` call 0x0202443e

Caller context summary: `0x02025dea` calls `0x02024368` after computing `r1 = 0x1c0de20 + index*0x49e3 + 0x0a7e`; `0x02025e06` calls `0x0202443e` with `+0x0a7f`. This confirms encoder relation for the enclosing routines but not a caller for vector slot `0x0202439e` itself.

## Pending fields +0x309..+0x30f

| field | exact listing hits | role seen |
|---:|---:|---|
| `0x309` | `0x020291b6` | consumer/read only in this search |
| `0x30a` | `0x020291a2` | consumer/read only in this search |
| `0x30b` | `0x02029166` | consumer/read only in this search |
| `0x30c` | `0x02029152` | consumer/read only in this search |
| `0x30d` | `0x0202918e` | consumer/read only in this search |
| `0x30e` | `0x0201a308`, `0x0201a4ec`, `0x0202917a` | consumer/read only in this search |
| `0x30f` | `0x02029612` | long-hold/timeout consumer then writes live +0x3f and calls 0x020291f8 when it underflows |

- Writes to pending fields found: `[]`
- `0x02029152..0x020291cc` reads `+0x30c,+0x30b,+0x30e,+0x30d,+0x30a,+0x309`, increments/copies into live `+0x3c,+0x3b,+0x3e,+0x3d,+0x3a,+0x39`, and calls helper `0x02028e46/64/86/a6/c8/ea` when the pending value exceeds `0x13`.
- `0x02029612` reads `+0x30f`, decrements to live `+0x3f`, and calls `0x020291f8` on underflow.
- Sibling wrappers `0x0202a270..0x0202a3ac` write live fields and call the same helpers, but direct callers/xrefs to those wrappers were not found. They do not prove pending `+0x309..+0x30f` producers.

## 반증 가능 blocker

- No raw 32-bit, 24-bit file-offset, or listing immediate xref to 0x02058248.
- No copied 44-byte table sequence outside 0x02058248 itself, and no duplicate first two/three entry run outside the table.
- No computed-call or base+index word-load window in the exhaustive listing carries table-base/table-range evidence.
- The only listing control-flow target into 0x02058248..0x02058273 is 0x02055b32 -> 0x02058258, which lands in the data word for slot 4 and is treated as a false-positive/disassembly artifact, not a dispatcher.
- No direct caller to the exact 0x0202439e mid-entry is present outside the vector word. Only enclosing function entries are called directly.

## 재현

```sh
python3 baselines/v15/analysis/ui-preflash/followup/analyze_event_dispatcher.py
python3 - <<'PY'
import json
from pathlib import Path
data=json.loads(Path('baselines/v15/analysis/ui-preflash/followup/event-dispatcher.json').read_text())
print(data['promotion_decision']['physical_event_ids_promoted'])
PY
```

Generated artifacts:

- `baselines/v15/analysis/ui-preflash/followup/analyze_event_dispatcher.py`
- `baselines/v15/analysis/ui-preflash/followup/event-dispatcher.json`
- `baselines/v15/analysis/ui-preflash/followup/event-dispatcher.md`
