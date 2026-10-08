# S1-C2 extended H2 producer candidate

Date: 2026-08-02 UTC  
Status: **CANDIDATE, analysis-only bytes, no firmware package**

## Decision

A reduced producer-only implementation fits the requested replacement window. It replaces the live-PASS H2 producer entry at `0x0201e1a2` and extends into the positively owned residual tail, ending at `0x0201e228`. It does not touch the selector range `0x0201e13e..0x0201e19e`, the 4-byte gap `0x0201e19e..0x0201e1a2`, or the official handler at `0x0201e254`.

This is not a firmware image and not a flashable package. It is an offline byte candidate for review.

## Exact byte budget

- Candidate range: `0x0201e1a2..0x0201e228`
- Candidate bytes: `134`
- Maximum authorized bytes: `178`
- Margin: `44` bytes
- Old H2 producer bytes covered: `0x0201e1a2..0x0201e1ec` (74 bytes)
- Residual tail used: `60` bytes
- Official handler first byte: `0x0201e254`, untouched

## ABI and gate admission

- Producer entry ABI used: `r0 = accepted product staging pointer`, proven by the H2 producer and product callsites.
- H2 accepted-packet ingress preserved: the direct and segmented accepted-product callsites still enter at `0x0201e1a2`, the producer still copies exactly `0x9c` bytes from the accepted staging pointer, and the caller still resumes to the existing reload calls after `pop pc`.
- S1-C2 publication intentionally changes the H2 one-slot immediate-visible policy into the requested two-slot `LOADING -> ARMED` policy.
- Preserved return ABI: same saved-register shape as H2, `push {rets,r9..r4}` and `pop {pc,r9..r4}`.
- Preserved caller reloads: direct and segmented product reload callsites after producer return remain outside this candidate.
- Exact packet/route length gate: **omitted by requirement**, because producer ABI evidence does not prove length or route state at `0x0201e1a2`. The only admitted source is the existing official/H2 accepted-product calls after their gates.

## Unlock semantics

- Nonblocking trylock-fail exits directly without clearing the lock, matching H2 semantics and avoiding clearing another owner.
- Every path after a successful trylock reaches the single unlock block before return.
- `ARMED`, malformed lifecycle state, missing `valid0`, and already-present `valid1` all unlock with no publication mutation.

## Publication behavior

- Boot-zero `state=EMPTY`, `valid0=0`, `valid1=0` is expected from the existing S1-C1 BSS extension through `0x01c46660`.
- First accepted product payload under the nonblocking trylock stores `state=LOADING`, stores fixed `note0=36`, copies `0x9c` bytes to slot0, then writes `valid0=1` last.
- Second accepted product payload when `state=LOADING`, `valid0=1`, and `valid1=0` stores fixed `note1=45`, copies `0x9c` bytes to slot1, writes `valid1=1`, then writes `state=ARMED` last.
- `state != LOADING` in the second path, including `ARMED`, unlocks with no mutation.
- Consumers continue to fall back until `ARMED`; that consumer behavior is supplied by the existing fixed-selector evidence, not changed here.

## Branch reach proof

| branch | kind | target | reach bytes | status |
|---|---|---|---:|---|
| `0x0201e1b0` | `ifeq` | `0x0201e226` | 114 | PASS |
| `0x0201e1be` | `jne_imm7` | `0x0201e1e4` | 34 | PASS |
| `0x0201e1e2` | `forward_goto` | `0x0201e218` | 52 | PASS |
| `0x0201e1e4` | `jne_imm7` | `0x0201e218` | 48 | PASS |
| `0x0201e1ea` | `jne_imm7` | `0x0201e218` | 42 | PASS |
| `0x0201e1f4` | `jne_imm7` | `0x0201e218` | 32 | PASS |

## Generated artifacts

- `producer.bin`: raw candidate bytes only.
- `producer.hex`: raw candidate bytes as hex.
- `decode.tsv`: builder ledger for the encoded instructions.
- `independent-decode.tsv`: validator-produced decode from the raw bytes only.
- `evidence.json`: machine-readable evidence and hashes.
- `validate.py`: independent decoder and invariant checker.
- `validation.txt`: captured validation output.

## Validation

```sh
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/build_extended_producer.py
python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer/validate.py
(cd baselines/v15/analysis/patch-set-ui/s1c2-unblock/extended-producer && shasum -a 256 -c SHA256SUMS)
```
