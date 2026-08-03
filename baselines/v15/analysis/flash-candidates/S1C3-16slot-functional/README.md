# S1-C3 16-slot functional offline release

Status: **PASS, candidate built offline**.

This directory is self-contained for the S1-C3 16-slot functional release candidate. It contains the deterministic app/FWSC, manifests, exact official-v15 rollback sectors, exact-hash OTA C wrapper, guarded exact 16-packet C sender, and dry-run validator.

## Exact release hashes

- App: `app.bin`, SHA-256 `a6f99cf6672ae3bd5b00312876a77ce1ed0e8a909ef56df7af0db34a2f726e05`.
- FWSC: `SMK37Pro-v15-S1C3-16slot-functional.fwsc`, SHA-256 `974c1675426e5d43f6b48e7ac7a1142f40062fca945dc6ba1b3ace8b0d144496`.
- OTA confirmation token: `INSTALL-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-974C1675`.
- Sender confirmation token: `SEND-SMK37PRO-V15-S1C3-16SLOT-FUNCTIONAL-1C923962-AFA89570-8A87A409-A5C086A7`.

## Scope

All build and validation actions are offline-only. `check`, `dry-run`, and Python validation paths never open USB/MIDI, reset, flash, send packets, or access a device. Upload/send code paths are guarded by exact hashes and explicit confirmation tokens.

## Ordering invariant

Producer, selector, packet manifest, C sender, and dry-run validator all use note order slots `0..15` -> MIDI notes `36..51`. The physical Pad permutation from commit `2a23cf5` is recorded as UI-only metadata and is not used for producer/selector/send ordering.

## Validate

```sh
python3 baselines/v15/analysis/flash-candidates/S1C3-16slot-functional/validate.py
```
