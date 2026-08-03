# S1-C3 16-slot functional offline integration skeleton

Status: **BLOCK until all inputs PASS**.

This directory is a deterministic gate and builder skeleton for a future flashable
S1-C3 16-slot functional candidate. It starts from the exact live-PASS
`S1C3-16slot-boundary-only` app and consumes only reviewed inputs:

- reviewed 96-byte S1-C3 16-note selector from `patch-set-ui/s1c3/selector`;
- future compact assembled 16-slot producer in `inputs/producer/`;
- future exact 16-packet PASS set in `inputs/packets/`.

The builder writes `BLOCK.md` and refuses to create `app.bin`, FWSC, rollback,
exact OTA, or guarded sender until every input gate is PASS. It never accesses a
device, opens USB/MIDI, flashes, resets, or sends packets.

Run:

```sh
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/build_s1c3_16slot_functional.py check-inputs
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/validate.py
```
