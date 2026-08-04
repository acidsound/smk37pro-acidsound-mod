# v15 S1C5 host-side raw-prefix persistence investigation

Date: 2026-08-04 UTC

Scope: exact repository evidence, `docs/V15-RESTORE-HANDOFF.md`, current S1C5 artifacts, persistence-s2 storage/restore reports, and offline regular-file tooling only. No device, flash, USB, MIDI, OTA, reset, or physical-drive path was opened.

## Decision

**Normal-firmware wrapper writer: BLOCK for current S1C5.**

`0x02004b02` and `0x02004870` are exact v15 storage wrappers with the right primitive contracts, but there is no current exact S1C5 host command, helper placement, return path, and readback/status channel that can safely reserve and seed the 16 raw-record prefixes through normal firmware.

**Forced-sector path: fallback-only guarded writer provided.**

`prepare_s1c5_raw_prefix_seed.py` is a deterministic offline read-modify-write package builder and validator. It requires two identical **regular-file** 1 MiB pre-dumps, emits only target-specific sectors and rollback sectors, and validates later readback dumps. It refuses device paths and does not itself write flash.

No live write package is emitted in this repository because no current target dump was supplied and the task forbids device/flash access.

## Exact raw-prefix reservation

The 16 reserved records are Bank D presets 1..16, stock raw-record indices `96..111`:

```text
raw_table_physical_base = 0x0f8000
record_stride           = 0x00a3
record_index(slot)      = 96 + slot
record_offset(slot)     = 0x0f8000 + (96 + slot) * 0xa3
prefix_written          = record[0x00..0x9b] = 0x9c bytes
tail_preserved          = record[0x9c..0xa2] = 7 bytes
```

Per slot, the writer derives exactly the S1C5 accepted transport payload prefix:

```text
record[0x00..0x9a] = packet[0x06..0xa0]      # 155 voice bytes
record[0x9b]       = packet[0xa1]            # Playback Note, C4/60 for current input set
record[0x9c..0xa2] = unchanged pre-dump tail
```

For the current all-C4 S1C5 packet set, the affected physical range is `0x0fbd20..0x0fc748`, so any sector fallback package is expected to be limited to the `0x0fb000` and `0x0fc000` 4 KiB sectors unless the pre-dump already contains identical prefixes.

## Wrapper path analysis

Proven wrapper contracts from `persistence-s2/storage/report.md`:

- `0x02004b02(r0=RAM source, r1=storage address, r2=length)` returns requested length only on full write success, else `0`.
- `0x02004870(r0=RAM destination, r1=storage address, r2=length)` returns requested length only on full read success, else `0`.
- Current S1C5 disables stock SAVE at `0x02026da6` by branching to `0x02026dd4` and neutralizes the following stock packer call. Restoring the stock SAVE path is unsafe because `0x0201e13e` is now the S1C5 selector, not the stock packer.

Explored placement candidates:

1. **Disabled SAVE UI region `0x02026d6c..0x02026dd8`**
   - The live UI can still enter the early guard/calculation block.
   - The dead tail after the S1C5 branch is too small for a guarded 16-record writer with scratch construction, wrapper calls, return checks, readback compare, and status reporting.
   - A direct helper here would still need a proven host ingress ABI and a way to surface per-record readback failure. Neither is present.

2. **Producer call-after-slot publication**
   - The producer publishes each slot valid last and only then updates count/state.
   - Inserting storage I/O after publication would require extra producer bytes or an exact helper callout while preserving the product-message ABI, volatile registers, locking, publication order, and Note On/Off behavior.
   - Current S1C5 has no assigned spare executable budget for this. The only audited owned window is occupied by selector/producer code with a 2-byte inert tail.
   - There is no proven live behavior for doing flash/storage writes inside the SysEx product handler, and no host readback/status response path.

Therefore the normal-firmware route is blocked until a new exact child candidate proves helper placement, host ingress, readback/status semantics, and rollback.

## Guarded fallback artifact

Tool:

```text
baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py
```

Commands:

```sh
# Offline self-test, uses synthetic regular-file dumps only.
python3 baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py self-test

# Build a target-specific fallback package from two identical regular-file dumps.
python3 baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py build \
  --pre-dump-a pre-a.bin \
  --pre-dump-b pre-b.bin \
  --output-dir out/s1c5-prefix-seed

# Check package files and hashes.
python3 baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py check-artifacts \
  --manifest out/s1c5-prefix-seed/manifest.json

# Validate two post-write readback dumps against the exact package.
python3 baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py validate-readback \
  --manifest out/s1c5-prefix-seed/manifest.json \
  --pre-dump-a pre-a.bin \
  --pre-dump-b pre-b.bin \
  --post-dump-a post-a.bin \
  --post-dump-b post-b.bin

# Validate rollback readback equals the exact original pre-dump.
python3 baselines/v15/analysis/persistence-s2/host-prefix-seed/prepare_s1c5_raw_prefix_seed.py validate-rollback \
  --manifest out/s1c5-prefix-seed/manifest.json \
  --pre-dump pre-a.bin \
  --rollback-readback-dump rollback-readback.bin
```

The generated manifest records:

- exact input dump SHA-256;
- exact packet and prefix hashes;
- exact record offsets and tail hashes;
- exact expected pre-sector hashes;
- exact patched-sector hashes;
- original rollback-sector hashes;
- full post-dump SHA-256 if patched sectors are applied.

## Hard stop rules

1. Do not use the old 148-sector v012 emergency restore flow for this persistence seed. `docs/V15-RESTORE-HANDOFF.md` says future v15 recovery must be target-specific and must not touch package-external user/settings tail without evidence.
2. Do not write a full 1 MiB image.
3. Do not touch package-managed `0x00000..0x9bfff` for this persistence seed.
4. Do not touch the seven raw tail bytes `0x9c..0xa2` in any reserved record.
5. Do not use the fallback sector package unless the live pre-dump sector hashes exactly match the package manifest.
6. If exact normal-firmware wrapper persistence is pursued next, it must be a new reviewed S1C5 child candidate with exact helper placement, `0x02004b02` full-length return checks, `0x02004870` readback comparison, host-visible failure reporting, and rollback.
