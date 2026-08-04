# S1C9 minimum-budget S1C5 persistence: BLOCK with exact helper inventory

## Decision

**BLOCK.** No `app.bin`, FWSC, exact OTA wrapper, rollback flasher, writer, device action, or MIDI action is emitted.

The 17-record data layout is viable offline, but a manifest-gated restore that treats absent/invalid seed as exact stock S1C5 and lets runtime SysEx `ARMED` RAM override cannot be placed with exact helper ABI evidence.

## Exact callable helper inventory

| Need | Result | Exact evidence |
|---|---|---|
| CRC/checksum | BLOCK_NO_CALLABLE_ABI | IEEE CRC32 table data exists at `0x02059210` (1024 bytes), but direct table refs count is `0` and no callable ABI is proven. |
| Bounded memcmp | BLOCK_NOT_LOCATED | Closest exact helper is `strcmp` at `0x02048dbc`, which has no length argument and is unsafe for binary records. |
| Storage read | PASS_FULL_LENGTH_READ_WRAPPER | `0x02004870` ABI: `r0=ram_destination, r1=storage_offset, r2=requested_length; returns requested_length on complete read, else 0`. |
| Storage write | PASS_FULL_LENGTH_WRITE_WRAPPER_BUT_WRITER_UNPLACED | `0x02004b02` ABI: `r0=ram_source, r1=storage_offset, r2=requested_length; returns requested_length on complete write, else 0`. |
| Bounds | PASS_STOCK_GLOBAL_BANK_PRESET_ONLY | Callable stock loader `0x02005660` bounds global bank/preset only, not manifest fields. |
| State publication | PASS_STOCK_CURRENT_STATE_AND_S1C5_ARMED_POLICY_IDENTIFIED | Stock loader `0x02005660`, initializer `0x020057e0`, and exact S1C5 producer `0x0201e196..0x0201e254`. |

## One manifest record plus 16 prefixes

Generated under `data-package/`:

- Combined prefixes: `candidate-prefixes-096-112.bin`, SHA-256 `7eae0faf19fdf4b9bfb2a276aef75622b176ae64d3498c0a404d56923c852d3d`.
- Manifest prefix: `manifest-prefix-record-112.bin`, SHA-256 `c24c583b092d65f1d2f0777fcc75b4c3634f77fc2e8cc25f32eba3d33859aba4`.
- Payload CRC32 `0xa400dfab`, notes CRC32 `0xc772e2f8`, header CRC32 `0xd9e23a2a`.
- Records `96..112`. Only bytes `0x00..0x9b` are represented. Tails `0x9c..0xa2` are not written.

Absent, all-zero, uncommitted, wrong-layout, short-read, corrupt, or CRC-failing seed must do nothing and return through exact S1C5 stock fallback.

## Fit blocker

| Budget | Bytes |
|---|---:|
| Proven disabled SAVE helper region | 84 |
| Manifest read setup floor | 20 |
| Inline 8-byte magic compare floor | 48 |
| Six core field checks floor | 36 |
| Floor before any CRC or payload restore | 104 |
| Overflow before CRC | 20 |

The exact S1C5 owned window has `0` free bytes if the selector/producer behavior is preserved byte-for-byte. The only standalone helper region is `84` bytes. The positive manifest gate floor is already `104` bytes before CRC, payload reads, publication, or rollback repair.

## Split-helper and boot/lazy result

- Split across proven regions fails: the active S1C5 selector/producer has no free budget, and the disabled SAVE helper overflows before CRC.
- Boot-only validation remains blocked: `0x02005f9c` was a design point, not a current promotable hook, and wrapper placement/register continuation are not proven for this successor.
- First-note lazy validation remains blocked by the same code placement and helper ABI limits. It is the preferred lifecycle if future placement is proven because runtime SysEx `ARMED` RAM can win first.

## Reproduce

```sh
python3 baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block/analyze.py --check
python3 baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block/validate.py
(cd baselines/v15/analysis/flash-candidates/S1C9-min-budget-persistence-block && shasum -a 256 -c SHA256SUMS)
```
