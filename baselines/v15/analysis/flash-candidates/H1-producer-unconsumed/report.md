# H1 producer-unconsumed discriminator

Scope: exact official v15 only. Offline artifact; no device access or flash.

## Intent

H1 tests whether the R03 producer writing/publishing owned RAM can coexist with the live-proven R02 Ch10 staging consumers. No H1 consumer reads `0x01c46520`.

## Hashes

- app SHA-256: `b082e8058cfacdb6e9d548dbe7033f31c0848fcf7d865859bc7c8fd969eac463`
- package SHA-256: `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf`
- changed flash sectors: `0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`

## Preserved and changed behavior

- H0 BSS/HEAP boundary is applied.
- Note On/Off use the R02 live-proven wrapper, with `r9` Ch10 gate, stock fallback, and source `0x01c37fd0`.
- Accepted product packet callsites invoke the producer after official final-F7 gates.
- Producer copies `0x9c` bytes from `0x01c37fd0` to `0x01c46520`, sets valid last, and unlocks with the nonblocking PI32 `testset` protocol.
- Product reload calls are preserved, as in the R02 live-success path.
- SAVE is blocked before the first persistent write because the stock packer body is replaced; the later packer call is neutralized.

## Discriminator outcomes

| Live outcome if later authorized | Interpretation |
| --- | --- |
| `packet_time_reboot` | producer/owned-RAM write or post-product reload path is sufficient to fault before any Ch10 consumer runs |
| `first_pad_reboot` | R02 staging consumer with H0 boundary and producer side effect still faults; investigate event path interaction independent of owned source consumption |
| `PASS` | producer write/publish and R02 staging consumers coexist; R03 first-pad reboot is isolated to owned-source consumption or R03 invalid/fallback consumer behavior |

## Validation

See `app-manifest.json`, `package-manifest.json`, and `SHA256SUMS`. Full release gates are checked by `tools/validate_v15_h1.py`.
