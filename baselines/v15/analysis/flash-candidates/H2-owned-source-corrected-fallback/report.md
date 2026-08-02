# H2 owned-source corrected-fallback discriminator

Scope: exact official v15 only. Offline artifact; no device access or flash.

## Intent

H2 tests whether Ch10 Note On/Off consumers can safely consume the H1 producer's owned RAM snapshot at `0x01c46520` when the R03 invalid-branch bug is fixed.

## Hashes

- app SHA-256: `d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59`
- package SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- changed flash sectors: `0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`

## Preserved and changed behavior

- H0 BSS/HEAP boundary is applied.
- Accepted product packet callsites invoke the H1 producer after official final-F7 gates.
- Producer copies `0x9c` bytes from the accepted staging pointer to `0x01c46520`, sets valid last, and unlocks with the nonblocking PI32 `testset` protocol.
- Note On/Off Ch10 consumers read `0x01c46520` only when valid is exactly 1.
- Invalid and non-Ch10 fallbacks restore original `r0` from `r5` before stock memcpy; original `r1` and `r2` are not modified on fallback.
- Product reload calls are preserved, as in the R02/H1 live-success path.
- SAVE is blocked before the first persistent write because the stock packer body is replaced; the later packer call is neutralized.

## Discriminator outcomes

| Live outcome if later authorized | Interpretation |
| --- | --- |
| `intended_mooger_note_off_no_reboot` | owned source 0x01c46520 is consumed safely with corrected fallback semantics |
| `stock_sound_no_reboot` | corrected fallback path is safe, but producer did not publish valid before consumer or product was not accepted |
| `reboot` | H2 FAIL: owned-source consumption or surrounding corrected consumer path still faults |

## Validation

See `app-manifest.json`, `package-manifest.json`, and `SHA256SUMS`. Full release gates are checked by `tools/validate_v15_h2.py`.
