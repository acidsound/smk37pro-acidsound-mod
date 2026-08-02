# v15 UI preflash final pass: AC79 SDK match

## Scope

This pass used only:

- official SMK37 v15 `build/v15-official-app.bin`, SHA-256 `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`;
- public Jieli AC79 SDK `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK`, branch `release/AC79NN_SDK_V1.2.0`, commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`;
- existing `baselines/v15/analysis/sdk-signatures` and `baselines/v15/analysis/ui-preflash` evidence.

No v12 artifact was used. No device write path was used.

## Reproduce

```sh
python3 baselines/v15/analysis/ui-preflash/final-pass/sdk-match/match_ui_sdk.py \
  /absolute/path/to/fw-AC79_AIoT_SDK \
  build/v15-official-app.bin \
  --repo-root . \
  --output baselines/v15/analysis/ui-preflash/final-pass/sdk-match/ui-sdk-match.json
```

The script refuses a non-v15 app hash or a non-pinned SDK commit.

## Result

Accepted official/public AC79 SDK UI/input/LCD/display/widget matches in v15: **0**.

- exact accepted count: **0**;
- relocation-aware accepted count: **0**.

Three broad-term exact body hits were found but rejected as non-UI evidence:

| SDK symbol | v15 VA | reason |
|---|---:|---|
| `sync_window` | `0x0202d108` | filesystem window function, not UI/window widget code |
| `move_window` | `0x0202d116` | filesystem window function, not UI/window widget code |
| `icache_flush` | `0x02004336` | CPU instruction-cache flush, not LCD flush |

The pinned SDK source and headers do contain official UI/display/input names and constants, including UI headers under `include_lib/utils/ui`, LCD drivers under `apps/common/ui/lcd_driver`, event/key headers under `include_lib/utils/event` and `include_lib/driver/device/key`, and task APIs under `include_lib/system/task.h`. These are recorded as search evidence in `ui-sdk-match.json`, but none are promoted to product-v15 identities without exact or relocation-aware match support.

## Product-side candidates retained only as candidates

Existing v15 static evidence remains useful but not SDK-promoted:

- LCD/ST7789-like command table candidate near `0x02058aec`/`0x02058b10` remains candidate-only because no SDK LCD init/flush function matched.
- Text/widget renderer candidates such as `0x0200ea9a`, `0x0200f74c`, and `0x0201a67c` remain product-side candidates only.
- Key/event task queue and redraw/event-trigger candidates including `0x02058248`, `0x02029290`, `0x0201e06c`, and `0x0201e100` remain product-side candidates only.

## Files

- `match_ui_sdk.py`: reproducible, hash-guarded scanner.
- `ui-sdk-match.json`: machine-readable evidence and accepted/rejected match sets.
- `report.md`: this summary.
- `SHA256SUMS`: hashes for this evidence set.
