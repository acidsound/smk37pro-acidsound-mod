# 공식 v15 UI preflash event/static analysis

Status: 정적 분석 전용. Patch/flash/commit 미수행.

## 입력

- App: `build/v15-official-app.bin`
- SHA-256: `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`
- Runtime base: `0x02000000`
- Listing: `baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz`

## 확정
- Official app identity is fixed by SHA-256 and runtime base 0x02000000.
- 0x02058248 is an 11-word table of internal v15 code pointers, not a plain UI text pointer table.
- The target cluster 0x020297f2..0x02029aaa and 0x0202439e mutates RAM bases 0x1c33260 and 0x1c34894, proving these are internal UI/state callees rather than SDK-only hints.
- 0x02029290 is a state-machine/render-update candidate using RAM base 0x1c33260, with screen/submode byte [0x302], screen byte [0x200], timers [0xc0]/[0xbe], and pending event bytes [0x309]..[0x30f].
- 0x02029528 dispatches [0x302]-2 through a tbh jump table for values 2..6, producing separate 16-slot grid/render paths.
- 0x0201e06c is called from UI/event paths with small IDs such as 0x19 and 0x14 after dirty flags/timers are set, making it an internal redraw/event-trigger candidate.

## 후보
- 0x02058248 is a button/encoder callback vector candidate. It has no raw direct pointer xref to the table base, so the dispatcher/caller remains unresolved.
- 0x0202439e is the strongest encoder handler candidate because it interprets a centered 0x3f delta, clamps 0..0x7f, stores 0x00c6, and raises redraw/timer fields.
- Short press appears to enter through one-shot bytes [0x309]..[0x30f] copied to [0x39]..[0x3f] with helper calls at 0x02028e46/64/86/a6/ec8/eea.
- Long press/hold candidate uses [0xbe] countdown gated by [0xb4] bit mask and 0x1c08b10+1, then sets [0x1fc]=1 and calls 0x0201e06c(0x14).
- Pad Bank/SAVE labels are confirmed in app-resident string pools and pointer tables, but exact physical button-to-screen transition labels require caller resolution.

## 미확정
- No literal 'Patch' or mixed-case 'Para/Fx' screen names were found. 'PARA' exists at 0x0205729d, and FX-like parameter labels exist, but screen names are not confirmed by string evidence.
- The caller of the 0x02058248 vector and exact physical short/long button IDs are not resolved by current static evidence.
- The renderer ABI for mid-string/markup pointers around 0x02057c00 and 0x02058300 remains unresolved. These tables are evidence for state/UI labels, not safe patch schemas.
- Public SDK key/ui APIs were not used as proof. No public-SDK function name is promoted without v15 caller/callee/RAM evidence.

## 0x02058248 callback/vector 후보

Classification: **candidate button/encoder callback vector, internally proven code-pointer run, caller unresolved**
Raw xrefs to table base: `[]`. Absence of a raw word xref is why the dispatcher/caller is not confirmed.

| slot | table VA | target | classification | RAM evidence / semantic |
|---:|---:|---:|---|---|
| 0 | `0x02058248` | `0x02029912` | candidate | entry inside 0x0202990e clears UI flag [0x1c33260+0x1672] to 0 |
| 1 | `0x0205824c` | `0x02029936` | candidate | cycles byte [0x1c33260+0x03a6] through 0..0x18, mirrors through pointer [0x1c33260+0x15c]+0x40, starts 0xc8 timer |
| 2 | `0x02058250` | `0x02029974` | candidate | mid-function/goto entry associated with sibling [0x03a7] path and state-machine branch; decoder boundary not stable |
| 3 | `0x02058254` | `0x020299ce` | candidate | increments/decrements coarse selector [0x1636] in range 0..2 and clears fine selector [0x1637] |
| 4 | `0x02058258` | `0x020299f2` | candidate | bounded increment of fine selector [0x1637], max read from table 0x0205dda0 indexed by [0x1636] |
| 5 | `0x0205825c` | `0x02029a16` | candidate | bounded decrement of fine selector [0x1637] |
| 6 | `0x02058260` | `0x02029a2e` | candidate | edits RAM block 0x1c34894 byte +1 with clamp 0..0x0b and calls 0x02005152 to apply selection |
| 7 | `0x02058264` | `0x02029a46` | candidate | mid-body entry in 0x1c34894 renderer/update path; pfetch boundary makes callback start uncertain |
| 8 | `0x02058268` | `0x02029a78` | candidate | edits RAM block 0x1c34894 byte +0 with clamp 0..0x09 and calls 0x02005152 to apply selection |
| 9 | `0x0205826c` | `0x02029aaa` | candidate | mid-entry into 0x02029a8c grid/state synchronizer using [0x1639], [0x1642], [0x168a] |
| 10 | `0x02058270` | `0x0202439e` | confirmed-internal-callee-candidate-ui-encoder | encoder-like delta handler around center 0x3f; clamps 0..0x7f, stores [0x00c6], raises dirty bytes [0x16e7]/[0x16e9], sets timer [0x00c4]=0x0a |

## 화면 state machine 및 event timing

Primary candidate: `0x02029290` with RAM base `0x01c33260`.
Redraw/event trigger candidate: `0x0201e06c`. Cell render/update candidate: `0x02004e8e`.

| `[0x1c33260+0x302]` | target | current interpretation |
|---:|---:|---|
| `2` | `0x0202953e` | case with [0x1639]/[0x168a] mask rendering, exact screen unresolved |
| `3` | `0x02029642` | 16-slot grid renderer case, selected low-nibble path candidate |
| `4` | `0x020296ea` | 16-slot grid renderer case, selected upper/uextra nibble path candidate |
| `5` | `0x0202953c` | falls/defaults back toward common render/update path |
| `6` | `0x0202974e` | 16-slot grid renderer case, low-nibble highlight path candidate |

Short/long/encoder 후보:
- **short_press**: [0x1c33260+0x309..0x30f] pending bytes are copied to [0x39..0x3f] and invoke helpers 0x02028e46/64/86/a6/c8/ea. Exact button IDs unresolved.
- **long_press**: [0xbe] countdown plus [0xb4] bit mask and 0x1c08b10+1 gate sets [0x1fc]=1 and calls 0x0201e06c(0x14). Candidate hold/long-press trigger.
- **encoder**: 0x0202439e centered-delta path around 0x3f, clamp 0..0x7f, dirty flag/timer writes. Strongest encoder event candidate.

## Patch/Para/Fx/Pad Bank/SAVE 분류

| 화면 | 분류 | 근거 |
|---|---|---|
| Patch | unresolved | literal Patch/PATCH not found in official app string scan; patch/preset selection may be icon/abbrev/resource-coded |
| Para | candidate | PARA at 0x0205729d, parameter labels Cut Off-/Distortion-/Algorithm-/Feedback- in text pool, but no caller-confirmed screen transition |
| Fx | candidate | FX-like parameter labels exist, no literal Fx screen string and no physical event mapping |
| Pad Bank | confirmed-string-candidate-screen | Pad Bank- at 0x0205d9c5, direct pointer at 0x02058304, state-machine grid paths candidate |
| SAVE | confirmed-string-candidate-screen | SAVE at 0x02057298 and colored #D9D9D9 SAVE#/#f5bc27 SAVED# in UI text pool; save-bank prompt at 0x02057f84; exact button transition unresolved |

## 재현

```sh
python3 baselines/v15/analysis/ui-preflash/events/analyze_ui_events.py
```

스크립트는 공식 v15 app hash를 확인한 뒤 `ui_events.json`과 이 보고서를 재생성한다. Hash가 다르면 실행을 거부한다.
