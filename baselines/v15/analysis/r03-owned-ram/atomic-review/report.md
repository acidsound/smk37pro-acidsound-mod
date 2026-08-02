# R03 atomic independent review

Date: 2026-08-02 UTC

## Overall verdict

**BLOCK.** `tools/validate_v15_r03.py` and the deterministic app/package/rollback rebuild both pass, but the current R03 atomic artifact does not fully satisfy the requested independent release gates.

No implementation file was modified. No flash, OTA, or device access was performed.

## Gate decisions

| Requested gate | Decision | Basis |
| --- | --- | --- |
| Official v15 exact SHA | PASS | Official app `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` and FWSC `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` are enforced by builder/validator manifests. |
| heap-prefix/BSS/HEAP_BEGIN ownership | PASS | Current artifact reserves `0x01c46520..0x01c465c0` by extending BSS zeroing to `0x3cbec` and moving `HEAP_BEGIN` to `0x01c465c0`. Validator ties this to the recovered v15 `sbrk` match. |
| PI32 ABI and branch/call decode | PASS | Retained trace validates patched Note On/Off, producer callsites, producer lock/unlock calls, and SAVE trace rows against exact R03 app bytes. |
| Official SDK `arch_spin_lock` and official-toolchain object exact bytes | BLOCK | The local object/source bytes are exact and strongly support the primitive, but the pinned SDK `cpu.h` source and an official `objdump` rerun are not preserved or machine-reproduced by the validator. |
| Producer serialization and consumer partial-read prevention | PASS | The producer is protected by the embedded `testset` spinlock, rechecks `valid`, copies 156 bytes, and sets `valid=1` last. Because the snapshot is immutable after first publish, consumers cannot see a partially overwritten valid snapshot. |
| SAVE blocking | BLOCK | R03 only zeroes `0x02026dac`. The earlier SAVE persistent write call at `0x02026da6` remains `beeaacee`, decoded as `call 0x02004b02`. This contradicts the “SAVE disabled/rejected” claim. |
| Package protected hashes and changed sectors | PASS | Protected flash hashes before/after are equal. Diff scope is 199 app bytes, 207 flash bytes including CRC fields, and sectors `0x04000`, `0x20000`, `0x22000`, `0x2a000`, `0x62000`. |
| Rollback v2 exact target hash and deterministic restore guard | PASS | Rollback ZIP hash `6396f253825d067986131d830bcca8cce16ff9ca39b21c4220369958e90344f1` and five exact target-sector hashes are validated. Guard self-test passes in validator and rebuild logs. |
| Quarkslab omission at `0x0201e1a2` (`40e8fdff`) | BLOCK | The embedded bytes are exact and are present in the official-toolchain object body, so the machine-code identity is strong. However Quarkslab still lacks the row, and validator does not rerun official objdump or verify a local pinned SDK `cpu.h`, so I do not treat the provenance chain as fully closed. |

## Critical findings

### 1. SAVE is not actually blocked before persistent writes

The current R03 app bytes are:

```text
0x02026da6 official=beeaacee r03=beeaacee  ; call 0x02004b02 remains
0x02026dac official=bfeac7b9 r03=00000000  ; stock packer call neutralized
```

The retained decoder trace also contains:

```text
02026da6  beeaacee  4  call  call 0x02004b02  UNCONDITIONAL_CALL
02026dac  0000      2  nop   nop              FALL_THROUGH
```

Since the first persistent write remains reachable before the neutralized packer call, the requested SAVE blocking gate is **BLOCK**.

### 2. Quarkslab gap is not fully closed as independent provenance

`0x0201e1a2` is absent from the Quarkslab retained trace. The R03 app contains the expected bytes:

```text
0x0201e19e r03=2000b00040e8fdff20008000
0x0201e1a2 r03=40e8fdff
```

The official-toolchain object contains the exact contiguous lock/unlock body at offset 52, and validator checks source hash, object hash, app embedding, and `ATOMIC_LOCK_BODY[4:8] == 40e8fdff`.

That is enough to support the machine-code byte identity of the lock loop, but not enough for a fully independent provenance gate because the validator does not rerun official objdump and the pinned SDK `arch_spin_lock` source is not a local checked artifact.

## Validation performed

- Ran `python3 tools/validate_v15_r03.py`: PASS.
- Rebuilt R03 app in scratch: byte-identical to `build/v15-R03-fixed-prefix-app.bin`.
- Repacked R03 FWSC in scratch: byte-identical to `build/SMK37Pro-v15-R03-fixed-prefix.fwsc`.
- Rebuilt rollback v2 ZIP in scratch: byte-identical to `build/SMK37Pro-WL82-v15-R03-rollback-20260802-v2.zip`.
- Inspected SAVE and atomic branch bytes directly from official and R03 app images.

See `validation.txt` and `evidence.json` for command output and structured evidence.
