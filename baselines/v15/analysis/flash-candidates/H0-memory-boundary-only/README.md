# H0 memory-boundary-only diagnostic candidate

This directory contains an official-v15-only H0 diagnostic candidate. It is not a functional success claim.

## Scope

The candidate changes only the two R03 memory-boundary instructions in the official v15 application image:

| Symbol | Runtime address | Stock bytes | H0 bytes |
| --- | ---: | --- | --- |
| `BSS_SIZE_INSN` | `0x0200001e` | `c2ff48cb0300` | `c2ffeccb0300` |
| `HEAP_BEGIN_INSN` | `0x0205e9f8` | `c5ff2065c401` | `c5ffc065c401` |

The builder gates that the code cave, Note On/Off calls, product calls, SAVE calls, packer, UI, and all other application bytes stay stock.

## Build

From the repository root:

```sh
python3 baselines/v15/analysis/flash-candidates/H0-memory-boundary-only/build_h0_memory_boundary_only.py --determinism-check
```

Default input is `build/SMK-37_Pro_015.fwsc`. Output is written to ignored build directory:

```text
build/SMK37Pro-v15-H0-memory-boundary-only/
```

The package is produced through the existing v15 repacker, `tools/smk37_v15_app_patch.py repack-app`.

## Validation summary from current build

- Validation gate: PASS
- Deterministic rebuild: PASS
- Input package SHA256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- H0 package SHA256: `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`
- H0 app SHA256: `ab2d4d210605f20e35b96a8471c9f2e1102c24e18f3b062d6eabd4970f9794ce`
- H0 flash SHA256: `458d1c0a1e08e5f74ad07ab3dd04cf7d7b591a421668f5ff822a15b250746998`
- Changed application bytes: 2
- Expected app flash offsets: `0x04140`, `0x62b1a`
- Repacker metadata flash offsets: `0x04000`, `0x04001`, `0x04002`, `0x04003`, `0x04020`, `0x04021`, `0x04022`, `0x04023`
- Changed flash sectors: `0x04000`, `0x62000`
- Protected prefix `0x0000..0x3fff`: unchanged
- Rollback sector replacement restores stock flash: true

See `app-manifest.json`, `package-manifest.json`, `validation.json`, `rollback-manifest.json`, and `SHA256SUMS` for exact details.

## Safety boundary

No device access, flash writes, or transport actions are performed by this builder. The rollback bundle is exact changed-sector stock data generated from the official v15 package.
