# Quarkslab v15 analysis

This directory contains a pinned, reproducible comparison of:

- `quarkslab/ghidra-jieli` at `e1bd0707874b77b759401555d24839ad43af1267`
- `kagaimiq/ghidra-jieli` at `b5e60122b6cd3e6b615387035994b8bed0ea1a26`
  plus `patches/ghidra-jieli-pi32v2-smk37.patch`

The only firmware input is the exact official v15 app with SHA-256
`36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055`.
No firmware is patched or flashed.

Read [`evidence-report.md`](evidence-report.md) first. The result is that
Quarkslab improves decode coverage substantially, but USB MIDI receive and
dispatch entry points remain unidentified because the decoder and p-code model
are still incomplete. Zero recovered xrefs is not treated as code absence.

## Reproduce

```bash
GHIDRA_HOME=/path/to/ghidra_12.1.2_PUBLIC \
JDK_HOME=/path/to/jdk-21/Contents/Home \
WORK_DIR=/large/scratch/smk37-v15-quarkslab \
PROJECT_ROOT="$HOME/jcode-v15-quarkslab-work" \
  bash baselines/v15/analysis/quarkslab/run_analysis.sh
```

`PROJECT_ROOT` cannot contain a hidden path component because Ghidra rejects
such project paths. See the report for method, evidence classifications, and
an output index.
