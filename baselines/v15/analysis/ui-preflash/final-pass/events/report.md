# v15 UI/event final pass: pending/live fields and dispatcher search

Status: 공식 v15 static-only final pass. Patch/flash/package/hardware access 없음.

## Inputs and SHA gate

- App: `build/v15-official-app.bin`
- SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Listing: `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz`
- Runtime base: `0x02000000`

## Conclusion

- Physical input dispatcher/event ID proof: **not proven**.
- Pending producer proof for `0x1c33260 + 0x309..0x30f`: **not found** in official v15 static listing/raw bytes.
- Static impossibility is stronger than the prior vector-only pass because this pass follows the consumer/state-machine side and checks RAM-base aliases, absolute field xrefs, copy/call windows, task/callback strings, and relocation encodings.

- +0x309..+0x30f pending bytes are read in the 0x02028f0c/0x02029152 consumer path and copied/decremented into live +0x39..+0x3f.
- 0x02029290 state frame reconstructs r11=0x1c33260 and branches at 0x02029528 from +0x302, then uses +0x1639/+0x168a/+0x203 and render helpers.
- 0x020299xx vector targets write logical UI state fields such as +0x1672, +0x03a6/+0x03a7, +0x1636/+0x1637, not the +0x309..+0x30f pending bytes.
- 0x02025dea/e06 call enclosing encoder routines 0x02024368/0x0202443e with PRODUCT_RAM index*0x49e3 + 0x0a7e/0x0a7f; they do not statically link to physical event IDs or the pending byte producer.
- The 0x02058248 code-pointer run remains self-referenced only in raw bytes; it does not prove dispatcher or physical IDs.
- Producer/consumer boundary is therefore fixed statically at the pending-byte interface: consumers begin at 0x02028f0c/0x02029152 and 0x02029612. The upstream physical producer/ID dispatcher is outside the recoverable static evidence and requires runtime write/watch tracing of 0x1c33260+0x309..0x30f plus queue/callback instrumentation.

## RAM absolute base reconstruction

| base | name | listing mov hits |
| --- | --- | --- |
| 0x01c33260 | ui_ram | 411 |
| 0x01c34894 | alt_ram | 2 |
| 0x01c0de20 | product_ram | 94 |

Target-area base loads:

| address | base | register | text |
| --- | --- | --- | --- |
| 0x02025ddc | product_ram | r1 | `mov r1,#0x1c0de20` |
| 0x02025df8 | product_ram | r1 | `mov r1,#0x1c0de20` |
| 0x02025e4a | product_ram | r1 | `mov r1,#0x1c0de20` |
| 0x02028f0e | ui_ram | r4 | `mov r4,#0x1c33260` |
| 0x02028f9e | product_ram | r1 | `mov r1,#0x1c0de20` |
| 0x02029296 | ui_ram | r11 | `mov r11,#0x1c33260` |
| 0x02029348 | product_ram | r4 | `mov r4,#0x1c0de20` |
| 0x02029902 | ui_ram | r2 | `mov r2,#0x1c33260` |
| 0x0202991a | ui_ram | r2 | `mov r2,#0x1c33260` |
| 0x0202992c | ui_ram | r6 | `mov r6,#0x1c33260` |
| 0x0202995e | ui_ram | r6 | `mov r6,#0x1c33260` |
| 0x02029990 | ui_ram | r1 | `mov r1,#0x1c33260` |
| 0x020299a4 | ui_ram | r1 | `mov r1,#0x1c33260` |
| 0x020299de | ui_ram | r1 | `mov r1,#0x1c33260` |
| 0x02029a20 | alt_ram | r5 | `mov r5,#0x1c34894` |
| 0x02029a56 | alt_ram | r5 | `mov r5,#0x1c34894` |
| 0x02029a92 | ui_ram | r1 | `mov r1,#0x1c33260` |
| 0x02029ab2 | product_ram | r4 | `mov r4,#0x1c0de20` |

## Pending -> live field flow

| pending | live | consumer read | producer write found |
| --- | --- | --- | --- |
| 0x309 | 0x39 | yes | no |
| 0x30a | 0x3a | yes | no |
| 0x30b | 0x3b | yes | no |
| 0x30c | 0x3c | yes | no |
| 0x30d | 0x3d | yes | no |
| 0x30e | 0x3e | yes | no |
| 0x30f | 0x3f | yes | no |

Observed consumer pattern: `0x02029152..0x020291cc` reads `+0x30c,+0x30b,+0x30e,+0x30d,+0x30a,+0x309`, increments/copies to live `+0x3c,+0x3b,+0x3e,+0x3d,+0x3a,+0x39`, and calls `0x02028e46/64/86/a6/c8/ea` on overflow cases. `0x02029612` decrements `+0x30f` into live `+0x3f` and triggers `0x020291f8/0x02029244` when it underflows.

## Dispatcher, memcpy/queue/task callback search

| target | word xrefs | odd word xrefs | file-offset xrefs |
| --- | --- | --- | --- |
| 0x02028f0c | none | none | none |
| 0x02029290 | none | none | none |

Pending-related call windows found: `7`. None contains a confirmed memcpy/queue producer into `+0x309..+0x30f`; the hits are consumer/helper contexts or non-UI-base aliases.

## 0x02058248 vector relocation check

- Table: `0x02058248`
- Base raw xrefs: `[]`
- Whole-table copies: `['0x02058248']`
- First-two-entry copies: `['0x02058248']`

| slot | target | raw xrefs | flow refs |
| --- | --- | --- | --- |
| 0 | 0x02029912 | 0x02058248 | 0 |
| 1 | 0x02029936 | 0x0205824c | 0 |
| 2 | 0x02029974 | 0x02058250 | 0 |
| 3 | 0x020299ce | 0x02058254 | 1 |
| 4 | 0x020299f2 | 0x02058258 | 0 |
| 5 | 0x02029a16 | 0x0205825c | 0 |
| 6 | 0x02029a2e | 0x02058260 | 0 |
| 7 | 0x02029a46 | 0x02058264 | 0 |
| 8 | 0x02029a78 | 0x02058268 | 0 |
| 9 | 0x02029aaa | 0x0205826c | 0 |
| 10 | 0x0202439e | 0x02058270 | 0 |

## Address-specific backward-slice notes

| area | finding |
| --- | --- |
| 0x02029152 | pending consumer chain for `+0x30c..+0x309`; direct flow refs only from local gates `0x020290c8` and `0x020290d4`. |
| 0x02029528 | state-machine computed branch after `+0x302 > 1`; uses `+0x1639`, `+0x168a`, `+0x203`, render helper `0x02004e8e`. |
| 0x020299xx | logical UI callback targets mutate state fields, redraw timers, selection bytes, and alt block `0x1c34894`; no pending producer writes. |
| 0x02025dea/e06 | enclosing encoder calls use `0x1c0de20 + idx*0x49e3 + 0xa7e/0xa7f` and call `0x02024368/0x0202443e`; this is not physical dispatcher proof. |

## Reproduction

```sh
python3 baselines/v15/analysis/ui-preflash/final-pass/events/analyze_final_pass_events.py
python3 - <<'PY'
import json
from pathlib import Path
p=Path('baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json')
d=json.loads(p.read_text())
print(d['conclusion']['physical_input_dispatcher_or_id_proven'])
print(len(d['field_offset_aliases']['pending_writes_reconstructed']))
PY
```

Generated artifacts:

- `baselines/v15/analysis/ui-preflash/final-pass/events/analyze_final_pass_events.py`
- `baselines/v15/analysis/ui-preflash/final-pass/events/final-pass-events.json`
- `baselines/v15/analysis/ui-preflash/final-pass/events/report.md`
