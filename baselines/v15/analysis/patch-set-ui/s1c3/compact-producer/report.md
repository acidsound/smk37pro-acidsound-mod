# S1-C3 compact sequential 16-packet producer PASS

Date: 2026-08-03 UTC  
Status: **PASS for exact offline PI32 producer bytes; BLOCK for firmware package/live send**

## Decision

**PASS:** the compact producer/stub is exact PI32, independently decoded byte-for-byte, and fits the owned range `0x0201e1a2..0x0201e254`.

**BLOCK:** this artifact is offline only. It does not build an app/FWSC, open MIDI/USB, flash, reset, or authorize a live send.

## Exact bytes and range

- Producer/stub range: `0x0201e1a2..0x0201e24e`.
- Owned limit: `0x0201e254`.
- Bytes used: `172` of `178`.
- Spare bytes: `6`.
- Minimal overrun: `0` bytes. No alternative placement is needed.
- Segmented no-mutation entry: `0x0201e220`.
- SHA-256: `5c0ec6675c29b8f20d055938425ceb12c356513c29b79b761f1a469eaa068a75`.

```text
790404169016e020f03d80f83700c0ffbd65c4012000b00040e8300020000516584280f807005b4183f824004021d8422000048380f81e025b4103fd1b203616e6e1a060c7ff2065c401671806e19c704020e84070164116623c80ffccaa020020004021e840c321db4183f8032020004022d84220004020d840200059047904590479040416494081f80bc4494181f808c6c5ffbd65c4014020d840d841d8422000401680ff56ffffff5904
```

## Call route reach

- Direct product callsite `0x0201e468` bytes `bfeadcfe` target `0x0201e224`.
- Segmented product callsite `0x0201e49c` bytes `bfeac0fe` target `0x0201e220`.
- Direct reload remains `0x0201e46c bfeaf838`.
- Segmented reload remains `0x0201e4a0 bfeade38`.

## Contract summary

- Direct entry preserves the S1-C2 frame shape: `push {rets,r9..r4}` and `pop {pc,r9..r4}`.
- `r9 == 0xa3` is checked at `0x0201e1a6..0x0201e1ac`; the reject target is the return at `0x0201e21e`, before `testset` or any store.
- Lock is `0x01c465bd`; `testset` is nonblocking and failed acquisition returns without unlock.
- `loaded_count` is `0x01c465be`; `state` is `0x01c465bf`.
- Slot pointer is `0x01c46520 + loaded_count * 0xa0`; valid byte is `slot + 0x9c`.
- For slots `0..15`, host order is note `36..51`; publication is valid-last, count-after-valid, and ARMED-last for slot 15.
- Segmented entry `0x0201e220` is only `push; pop`, so it has no mutation path.
- Direct entry now targets reset wrapper `0x0201e224`; slot0 payload signature `62 63` clears stale lock/count/state before the original producer runs.

## Branch/call proof

| Address | Bytes | Op | Target | Reach |
|---|---|---|---|---|
| `0x0201e1ac` | `80f83700` | `jne_imm7` | `0x0201e21e` | **PASS** |
| `0x0201e1ba` | `40e83000` | `ifeq` | `0x0201e21e` | **PASS** |
| `0x0201e1c4` | `80f80700` | `jne_imm7` | `0x0201e1d6` | **PASS** |
| `0x0201e1ca` | `83f82400` | `jne_imm7` | `0x0201e216` | **PASS** |
| `0x0201e1d4` | `0483` | `goto` | `0x0201e1dc` | **PASS** |
| `0x0201e1d6` | `80f81e02` | `jne_imm7` | `0x0201e216` | **PASS** |
| `0x0201e1dc` | `03fd1b20` | `jge_imm7` | `0x0201e216` | **PASS** |
| `0x0201e1fc` | `80ffccaa0200` | `call32` | `0x02048cce` | **PASS** |
| `0x0201e20c` | `83f80320` | `jne_imm7` | `0x0201e216` | **PASS** |
| `0x0201e22a` | `81f80bc4` | `jne_imm7` | `0x0201e244` | **PASS** |
| `0x0201e230` | `81f808c6` | `jne_imm7` | `0x0201e244` | **PASS** |
| `0x0201e246` | `80ff56ffffff` | `call32` | `0x0201e1a2` | **PASS** |

All branches stay inside the owned blob. The two `call32` targets are stock `memcpy` at `0x02048cce` and the original sequential producer at `0x0201e1a2`.

## Artifacts

- `producer.bin` and `producer.hex`: exact PI32 bytes.
- `decode.tsv`: builder-emitted instruction table.
- `independent-decode.tsv`: separate byte-pattern decoder over every byte.
- `evidence.json`: structured proof data.
- `validation.txt`: validation transcript.

## Reproduction

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c3/compact-producer/validate.py
(cd baselines/v15/analysis/patch-set-ui/s1c3/compact-producer && shasum -a 256 -c SHA256SUMS)
```
