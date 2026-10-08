# R02 controlled-checkpoint review

Date: 2026-08-02

Scope: newly added R02 offline artifacts only: `tools/build_v15_r02_sysex_staging.py`, `tools/smk37_v15_r02_sysex_send.c`, `tools/validate_v15_r02.py`, `baselines/v15/analysis/flash-candidates/R02/*`, `build/SMK37Pro-v15-R02-sysex-staging.fwsc`, `build/v15-R02-mooger1-runtime.syx`, and `build/SMK37Pro-WL82-v15-R02-rollback-20260802-v1.zip` / directory. No firmware modification, flashing, or device access was performed.

## Decision

**PASS, conditional controlled checkpoint.**

R02 is defensible as a narrow live checkpoint **only if no other SysEx or bulk/preset traffic is sent after staging and before every relevant Pad Ch10 Note On/Off pair**, and only if the exact generated packet is sent after each boot before touching pads. It is not a production channel-separation design and is not a live functional success claim.

No artifact-level blocker was found for that constrained checkpoint. The same evidence becomes **BLOCK** outside the constraint because `0x01c37fd0` is official transient SysEx workspace, not durable Ch10-owned storage.

## Precise blockers / hard stop conditions

These are not blockers to the constrained PASS above, but they are hard blockers to proceeding outside that exact order:

1. **Intervening SysEx blocker:** any SysEx, segmented bulk, preset/bulk traffic, or other host message that can overwrite `0x01c37fd0` between staging and Pad Note On/Off invalidates Note Off consistency.
2. **Pad-before-stage blocker:** pressing a pad before the exact R02 runtime packet is accepted can make Ch10 read stale or unrelated staging bytes.
3. **Reboot blocker:** staging RAM is not persistent. After any reboot, the exact packet must be sent again before pad tests.
4. **SAVE blocker:** R02 disables the direct `0x0201e13e` SAVE caller at `0x02026dac`. Pressing SAVE while R02 is installed is outside the checkpoint.
5. **Production-design blocker:** no per-channel/per-note ownership, generation flag, durable copy, or concurrent SysEx protection exists. R02 cannot graduate to final channel separation without replacing the transient global staging dependency.
6. **Host-build prerequisite:** this machine lacks `libusb.h`, so I could not compile the C sender here. I independently verified the packetization and did not access the device. A live host must have libusb development headers/libraries installed before using `send` mode.
7. **Live-handler-state uncertainty:** prior exact-v15 static analysis still leaves the handler state gates (`obj+0x206`, `obj+0x104`) as live-observation concerns. Failure to audibly stage Mooger #1 should be treated as checkpoint failure and rolled back, not debugged by sending arbitrary additional SysEx.

## Checks requested by prompt

### PI32 wrapper equivalence

**PASS.** R02 builds a 36-byte wrapper at `0x0201e13e..0x0201e162`. Its instruction shape matches the live-booted R01c prefix exactly except for the 32-bit source immediate:

- diff offsets versus R01c wrapper prefix: `[12, 13, 14, 15]`
- R01c source immediate bytes: `62 e1 01 02` = `0x0201e162` embedded snapshot
- R02 source immediate bytes: `d0 7f c3 01` = `0x01c37fd0` official staging
- wrapper structure remains: preserve destination, branch on `r9` channel nibble, Ch10 copies `0x9c` bytes from source, non-Ch10 falls back to original `memcpy` call, Note On/Off return through `pop {pc,...}`.

This keeps R02 within the previously live-booted event-path primitive. It does not reuse the R01d early preload body.

### Handler message length and framing

**PASS.** The generated packet is exactly the complete single-voice product packet shape proven by `sysex-staging/report.md`:

- header: `f0 43 00 00 01 1b`
- payload: 156-byte runtime Mooger #1 voice
- terminator: `f7`
- total length: `0xa3` / 163 bytes
- SHA-256: `6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27`

The prior exact-v15 report states the direct complete-message path copies `message+6` to `0x01c37fd0`, verifies final `F7`, then calls the packer and reload in stock firmware. R02 neutralizes the packer callsites so the handler can populate staging without invoking the replaced wrapper as if it were the stock packer.

### All `0x0201e13e` callers

**PASS.** The exact-v15 SysEx staging trace lists three direct callers:

- `0x0201e468`, one-shot product packet
- `0x0201e49c`, fragmented/final product packet
- `0x02026dac`, UI SAVE path

R02 zeros all three call instructions. The manifest records all three in `disabled_packer_callers`, and `tools/validate_v15_r02.py` checks the three `PACKER_CALLS`. This avoids accidental entry into the R02 Note wrapper through a stock packer ABI.

### Note Off consistency

**PASS under the stated no-intervening-SysEx condition.** R02 redirects both stock copy sites to the same wrapper:

- Note Off copy site: `0x0201c63e`
- Note On copy site: `0x0201c67c`
- shared source for Ch10: `0x01c37fd0`
- shared length: `0x9c`

This addresses the R01 stuck-note class where Note On and Note Off consumed different sources. It remains unsafe if staging is overwritten between Note On and Note Off, exactly as the prior `sysex-staging` negative safety result warned.

### USB-MIDI packetization

**PASS by independent offline check.** For 163 SysEx bytes, the C sender packetization model produces:

- 54 continuation events with CIN `0x04`
- 1 final one-byte SysEx-end event with CIN `0x05`
- total USB-MIDI payload: 220 bytes
- final event: `05 f7 00 00`

The sender also gates input by exact size, header, final `F7`, and SHA-256, and `send` mode requires the explicit confirmation token. I did not run `send` mode.

### Changed-sector set

**PASS.** Offline validation and independent package diff agree R02 changes exactly these four 4 KiB sectors versus official v15 flash representation:

| Sector | Changed bytes | R02 sector SHA-256 |
|---|---:|---|
| `0x04000` | 8 | `4651e4b8c95efbf90473146aaba2147227997b6db33ee43e796a75f3cc286473` |
| `0x20000` | 6 | `ded10e50863409002326d4114766db9b2cdaa16165991633dfb1b5afc6ce725d` |
| `0x22000` | 43 | `466a456f7461b3e07a95efeb7fa509ec55ac3e940f4bb427073535567646a9c9` |
| `0x2a000` | 4 | `b0b8af257fd5b6d39a66adea8371fb809c183c503954d9b92f3707a2d866866d` |

The R01d-only high-risk `0x0a000` sector is absent from R02.

### Rollback gate

**PASS.** Rollback artifacts are present and hash-matched:

- rollback zip SHA-256: `7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d`
- manifest format: `smk37-v15-r02-forced-recovery-plan-v1`
- requires two identical fresh 1 MiB forced-loader dumps
- requires exact R02 target-sector hashes before writing
- write scope limited to four audited 4 KiB app sectors
- forbids chip erase, full-flash write, key burn, boot-prefix write, reset, and run-app

This is materially better controlled than a broad restore path, assuming the guard script is used exactly as packaged.

### Boot-risk differences from R01d

**PASS.** R02 removes the R01d risk pattern:

- R01d most likely boot failure was the new early post-init callsite at `0x02005f9c` into a preload body at `0x0201e13e`.
- R02 does not patch `0x02005f9c`.
- R02 does not execute a factory-loader/preload routine before USB enumeration.
- R02 only reuses event-path Note On/Off redirections previously live-booted by R01b/R01c and stale packer-caller neutralization previously live-booted by R01/R01b/R01c.
- R02 changes no `0x0a000` sector, unlike R01d.

Remaining boot risk is therefore reduced to previously live-booted event-path/code-cave occupancy plus package/header CRC changes, not the revoked R01d early-boot assumption.

## Validation performed

```text
$ python3 tools/validate_v15_r02.py
v15 R02 artifact integrity and rollback readiness: PASS
not a live functional claim; no device access performed
app eebc5190b2e19dedbba68becb27851e9a26cf35f8356319f75bd9f6c20714948
package 93bdf1a7212738b06be8b78919324902729befce8ea07626b0b7aaf7c91e640b
runtime packet 6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27
rollback 7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d
```

Additional independent checks:

```text
runtime packet: 163 bytes, sha256 6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27, header f0430000011b, terminator f7
USB-MIDI: 163 SysEx bytes -> 220 USB-MIDI bytes, final event 05f70000, CIN counts {4: 54, 5: 1}
R01c/R02 wrapper diff offsets: [12, 13, 14, 15]
R02 rollback zip: 68595 bytes, sha256 7035ab4815322f7461c27d4e5f438eb8726c0d5a525d0b2c32a4a999db22383d
```

Compile attempt for the C sender was blocked by missing local dependency, without device access:

```text
tools/smk37_v15_r02_sysex_send.c:1:10: fatal error: 'libusb.h' file not found
```

## Final recommendation

Proceed only as a short, reversible checkpoint with the exact live order in `baselines/v15/analysis/flash-candidates/R02/README.md`. Treat any deviation, additional SysEx, SAVE, reboot without restaging, or ambiguous sound result as **BLOCK and rollback**, not as permission to continue probing on-device.
