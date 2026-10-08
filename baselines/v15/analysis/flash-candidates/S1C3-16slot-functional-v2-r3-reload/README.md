# S1-C3 16-slot functional offline release

Status: **PASS, candidate built offline**.

This directory is self-contained for the S1-C3 16-slot functional release candidate. It contains the deterministic app/FWSC, manifests, exact official-v15 rollback sectors, exact-hash OTA C wrapper, guarded exact 16-packet C sender, and dry-run validator.

## Exact release hashes

- App: `app.bin`, SHA-256 `7c672938023beee74d599f43ccd5c7642396b89819e929501274239aed5e5d4b`.
- FWSC: `SMK37Pro-v15-S1C3-16slot-functional-v2-r3-reload.fwsc`, SHA-256 `0f1c4bf42329a0ca184ac38bb228195b239ed07820fcc0d39be352c2f15982b9`.
- OTA confirmation token: `INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-0F1C4BF4`.
- Sender confirmation token: `SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7`.

## Scope

All build and validation actions are offline-only. `check`, `dry-run`, and Python validation paths never open USB/MIDI, reset, flash, send packets, or access a device. Upload/send code paths are guarded by exact hashes and explicit confirmation tokens.

## Ordering invariant

Producer, selector, packet manifest, C sender, and dry-run validator all use note order slots `0..15` -> MIDI notes `36..51`. The physical Pad permutation from commit `2a23cf5` is recorded as UI-only metadata and is not used for producer/selector/send ordering.

## Validate

```sh
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/validate.py
```
