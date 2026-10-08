# R01d incident reanalysis

Scope: official v15, live-booted R01/R01b/R01c, and bricked/revoked R01d only. No v12 firmware assumptions are used. No patching, flashing, or device access is performed.

## Conclusion

Most likely pre-USB boot-failure cause: **0x02005f9c post-init callsite redirection to the new R01d preload body at 0x0201e13e**.

Confidence: high for address family, medium for exact failing instruction inside preload body without trace hardware. It is the only R01d-only executable change that can run before USB enumeration. All other R01d addresses were previously live-booted as event-path or stale-caller changes, or cannot execute until after USB MIDI is available.

## Hash validation

| Artifact | Package SHA-256 | App SHA-256 | Status |
|---|---|---|---|
| official_v15 | `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff` | `36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055` | PASS; official baseline, restored and device-info observed as 015 |
| R01 | `292809383e89ba7032619ae338dfb5bd195409600f417de5e8edb98149f66462` | `e12ac71df2be155a977b6135eedee2bda821226bf354cf8062d3a9624df474c7` | PASS; live-booted; Ch10 branch reached; Note Off stuck voice remained |
| R01b | `50aa3b27b17e4f9f8c682dd0ff053d2e3d198b7c736da63ed7b957627ccfa08d` | `1bd69fa20d4e4dab35d1d9df12bda36e25516ce2d0c1dff00fd2b7c9e3e96c7f` | PASS; live-booted; matched Note On/Off source fixed R01 stuck note; named voice failed |
| R01c | `b34d19e144281e21d1aae141315c3214950d4cf06aa9b0db840d9ebdc15770a7` | `37fe48e8215b7d8036c5cd98a0ff0962abe260dc2af13f633b749c527b96e2cb` | PASS; live-booted; matched Note On/Off source worked; named Mooger #1 failed |
| R01d | `add7baacc38d90bcd28cf51a1d096abe0737c8430ec01f70d5b41423d5dc9a96` | `bdcfdcf1b5e6d60e04e8c9316db94aa38e6cae4a7bcfaf63abefd38bb5347bb3` | PASS; BRICKED/REVOKED; OTA completed but firmware did not live-boot to normal USB |

## R01d address-by-address classification

| Address | Flash offset | Prior live-booted presence | R01d status | Cause likelihood | Classification |
|---|---:|---|---|---|---|
| `0x0201e13e` | `0x2225e` | R01, R01b, R01c | same cave entry reused, contents materially new | medium_as_callee_of_high_risk_post_init | unsafe code-cave expansion when invoked at init; post-USB wrapper primitive only partly proven |
| `0x02005f9c` | `0x0a0bc` | none | new_in_R01d | high | unsafe post-init loader/preload assumption |
| `0x0201c67c` | `0x2079c` | R01, R01b, R01c | reused_from_live_R01_R01b_R01c_with_different_target | low_for_pre_usb | previously live-booted Note On memcpy call redirection primitive |
| `0x0201c63e` | `0x2075e` | R01b, R01c | reused_from_live_R01b_R01c_with_different_target | low_for_pre_usb | previously live-booted Note Off memcpy call redirection primitive |
| `0x0201e468` | `0x22588` | R01, R01b, R01c | reused_from_live_R01_R01b_R01c | low | previously live-booted old SysEx direct caller neutralization |
| `0x0201e49c` | `0x225bc` | R01, R01b, R01c | reused_from_live_R01_R01b_R01c | low | previously live-booted old SysEx direct caller neutralization |

## Address evidence and rationale

### `0x0201e13e`

- App offset: `123198`; flash offset: `0x2225e`; byte length: `150`.
- Present in previous live-booted variants: R01, R01b, R01c.
- Classification: **unsafe code-cave expansion when invoked at init; post-USB wrapper primitive only partly proven**.
- Cause likelihood: **medium_as_callee_of_high_risk_post_init**.
- Rationale: The code-cave location itself was used by live-booted R01/R01b/R01c. R01d replaced the old static snapshot wrapper with a new preload routine plus note wrapper. The unsafe part is executing the cave from post-init before runtime lifecycle is established.
- Reusable primitive: code cave occupancy and compact channel compare wrapper were live-booted; loader-preload body was not.

### `0x02005f9c`

- App offset: `24476`; flash offset: `0x0a0bc`; byte length: `4`.
- Present in previous live-booted variants: none.
- Classification: **unsafe post-init loader/preload assumption**.
- Cause likelihood: **high**.
- Rationale: Only R01d patches this early post-init callsite. It changes an existing call to route into a cave that mutates selection state, calls the factory loader twice, and copies from current-source RAM before USB enumeration. The note hooks cannot execute before USB MIDI traffic, while this hook can execute during boot.
- Reusable primitive: none.

### `0x0201c67c`

- App offset: `116348`; flash offset: `0x2079c`; byte length: `6`.
- Present in previous live-booted variants: R01, R01b, R01c.
- Classification: **previously live-booted Note On memcpy call redirection primitive**.
- Cause likelihood: **low_for_pre_usb**.
- Rationale: R01/R01b/R01c changed this Note On callsite and booted. It requires MIDI event dispatch and is not expected to fire before USB enumeration.
- Reusable primitive: r9 channel-gated Note On source redirection, behavior beyond branch separation not proven.

### `0x0201c63e`

- App offset: `116286`; flash offset: `0x2075e`; byte length: `6`.
- Present in previous live-booted variants: R01b, R01c.
- Classification: **previously live-booted Note Off memcpy call redirection primitive**.
- Cause likelihood: **low_for_pre_usb**.
- Rationale: R01b/R01c introduced this matched Note Off hook and live-booted. It is reached from the MIDI note-off path, not during pre-USB boot.
- Reusable primitive: matched Note On/Off source wrapper redirection, but only post-USB event-path usage is proven.

### `0x0201e468`

- App offset: `124008`; flash offset: `0x22588`; byte length: `4`.
- Present in previous live-booted variants: R01, R01b, R01c.
- Classification: **previously live-booted old SysEx direct caller neutralization**.
- Cause likelihood: **low**.
- Rationale: All R01 variants zeroed this old direct caller and booted. It is not the R01d-specific early-boot change.
- Reusable primitive: neutralize stale direct caller at this exact address only.

### `0x0201e49c`

- App offset: `124060`; flash offset: `0x225bc`; byte length: `4`.
- Present in previous live-booted variants: R01, R01b, R01c.
- Classification: **previously live-booted old SysEx direct caller neutralization**.
- Cause likelihood: **low**.
- Rationale: All R01 variants zeroed this old direct caller and booted. It is not the R01d-specific early-boot change.
- Reusable primitive: neutralize stale direct caller at this exact address only.

## Validated R01d diff ranges

Manifest app ranges:
- `24478..24480` exclusive
- `116288..116291` exclusive
- `116350..116353` exclusive
- `123198..123199` exclusive
- `123200..123348` exclusive
- `124008..124012` exclusive
- `124060..124064` exclusive

Manifest flash ranges, including wrapper/header CRC fields:
- `16384..16388` exclusive
- `16416..16420` exclusive
- `41150..41152` exclusive
- `132960..132963` exclusive
- `133022..133025` exclusive
- `139870..139871` exclusive
- `139872..140020` exclusive
- `140680..140684` exclusive
- `140732..140736` exclusive

Actual changed app byte runs versus official v15:
- `0x05f9e..0x05fa0` exclusive, 2 bytes
- `0x1c640..0x1c643` exclusive, 3 bytes
- `0x1c67e..0x1c681` exclusive, 3 bytes
- `0x1e13e..0x1e13f` exclusive, 1 bytes
- `0x1e140..0x1e1d4` exclusive, 148 bytes
- `0x1e468..0x1e46c` exclusive, 4 bytes
- `0x1e49c..0x1e4a0` exclusive, 4 bytes

R01d changed 4 KiB sectors versus official v15: `0x04000`, `0x0a000`, `0x20000`, `0x22000`.

## Unsafe assumptions explicitly revoked

- Calling the factory loader from a post-init callsite before USB enumeration is safe.
- The live object base 0x01c33260 and selected-bank offsets 0x03a0..0x03a4 are valid and initialized at 0x02005f9c time.
- The current-source buffer at 0x01c34c74 is populated by the loader and stable immediately after the injected early call.
- A dedicated RAM staging buffer at 0x01c37fd0 is unused by official firmware and survives until MIDI events.
- The 0x0201e13e cave is safe as both an early-boot callee and a later MIDI-event callee, despite prior live proof covering only event-path use.
- A 156-byte runtime source object can be cloned or staged without recovering its full producer, lifecycle, and post-load initialization.

## Previously live-booted reusable patch primitives

- At 0x0201c67c, redirecting Note On memcpy to a small wrapper is live-booted by R01/R01b/R01c, but only for post-USB event-path use.
- At 0x0201c63e, redirecting Note Off memcpy to the same Ch10 source wrapper is live-booted by R01b/R01c and fixes the R01 stuck-note class.
- At 0x0201e468 and 0x0201e49c, zeroing the two stale SysEx direct callers is live-booted by R01/R01b/R01c.
- The code cave starting at 0x0201e13e can hold a compact channel-gated wrapper in live-booted builds. R01d's early preload body is not included in this reusable primitive.

## Source evidence

- `baselines/v15/analysis/flash-candidates/R01/live-validation-20260802.md` records R01 booting and summarizes R01b/R01c live behavior.
- `logs/v15/ota-v15-r01d-live-20260802T1813Z.log` records R01d OTA completion through `completion 0xf0000000 acknowledged`.
- `recovery/v15/post-recovery-baseline-20260802.json` records R01d as `BRICKED_REVOKED` and the exact changed sectors.
- `tools/validate_v15_r01d.py` validates R01d artifact integrity and explicitly says it is not a functional success claim.

