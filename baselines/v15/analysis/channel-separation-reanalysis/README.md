# v15 Ch1/Ch10 channel-separation reanalysis

Date: 2026-08-02 UTC  
Scope: exact official v15 only. No v12 address, ABI, or patch assumption is accepted.

## Live result already established

| Claim | Result | Evidence |
|---|---|---|
| Physical Pad sends human MIDI Ch10 | PASS | User observed `99 24 66`, meaning Ch10 Note 36 velocity 102. |
| `r9 == 9` can separate Ch10 from Ch1 at `0x0201c5ec` | PASS | R01 family produced a sound different from Ch1 on the physical Pad path. |
| Ch10 Note On and Note Off must use the same source identity | PASS | Original R01 stuck; R01b/R01c matched both hooks and Note Off worked. |
| App-resident static snapshot selects HAND DRUM, BUZZ BASS, or Mooger #1 | FAIL | All three intended identities failed by live comparison. R01b/R01c produced an unintended falling-pitch sound. |
| A known factory Patch can already be assigned independently to Ch10 | NOT ESTABLISHED | Source path separation succeeded, but named voice control did not. |

The device was restored to exact official v15 after R01c.

## What the official v15 loader actually does

`0x02005660` is a global-state loader, not `load(source, destination)`:

1. Read bank from `0x01c33260 + 0x3a4`.
2. Read zero-based preset from `0x01c33260 + 0x3a0 + bank`.
3. Copy the selected 0xa3-byte backing record to `0x01c34c74`.
4. Expand the matching 128-byte DX7 VMEM record into the first `0x9c` bytes.
5. Apply tail/flag postprocessing and call four helper functions.
6. Leave `0x01c34c74` as the current RAM voice source used by both Note On and Note Off.

For Bank D display 14, binary preset index 13, `Mooger #1`, the calculated first
`0x9c` bytes are byte-identical between the offline converter and the simulated
official loader. Therefore the previous failure is not explained by a simple
one-based/zero-based index error or by the DX7 expansion byte map.

## Remaining failure hypotheses

Two explanations remain distinguishable and must not be conflated:

1. **Source-location failure.** R01b/R01c placed the snapshot inside an app/text
   replacement region at `0x0201e162`. Correct bytes at that address may not have
   the same data-read contract as the official RAM object at `0x01c34c74`.
2. **Global-state dependency.** Loader tail bytes `0x9c..0x9f` call helpers
   `0x0200552e`, `0x0200558e`, `0x020055f8`, and `0x0200562c`. These update shared
   product/audio state. A per-note `0x9c` copy may be insufficient for a fully
   independent instrument even when its bytes are correct.

The falling pitch is an observation, not proof of either hypothesis.

## Next falsifiable checkpoint

The next acceptable experiment is a **loader-produced RAM clone**, not another
compiled static snapshot:

1. Outside the Note hot path, save the current UI bank/preset.
2. Select Bank D index 13 and call the official loader.
3. Copy the official `0x01c34c74` first `0x9c` bytes into a provenance-checked RAM
   staging buffer.
4. Restore the original bank/preset and call the official loader again.
5. Route both Ch10 Note On and Note Off to the same cloned RAM buffer.
6. Keep Ch1/non-Ch10 on the stock current source.

Interpretation:

- If Ch10 now matches stock Bank D 14, the previous failure was the app/text
  source location. RAM cloning becomes the valid basis for a Patch set.
- If Ch10 remains different or pitch-falling, the `0x9c` voice object is not an
  independently sufficient instrument state. The four helper states or a larger
  synth context must then be separated before a 10-channel drum instrument is
  possible.

## Safety gate for the next flash

A candidate is flashable only if all of the following pass:

- exact official-v15 app SHA input gate;
- exact original bytes at every hook and callsite;
- bounded code-cave and branch-range validation;
- no protected boot/config/resource change;
- Note On and Note Off use the same Ch10 RAM source;
- original UI selection is restored before returning from preload;
- the RAM buffer's writers and overwrite conditions are documented;
- artifact validator says only `artifact integrity: PASS`, never functional PASS;
- official v15 restore remains available.

## Reproducible evidence

- [`runtime-source/report.md`](runtime-source/report.md)
- [`factory-loader/report.md`](factory-loader/report.md)
- [`design/report.md`](design/report.md)
- [`../flash-candidates/R01/live-validation-20260802.md`](../flash-candidates/R01/live-validation-20260802.md)
- [`../mod-capability-matrix.md`](../mod-capability-matrix.md)
