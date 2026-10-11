# Policy: the Jieli Forced Upgrade Tool 4.0 must never be required

**Status: binding. This overrides any convenience.**

The Jieli Forced Upgrade Tool 4.0 is proprietary vendor hardware that has to be
bought, and it runs only on Windows. Any deliverable that needs it is not
deliverable. A user who does not own one cannot install the firmware and cannot
recover it if the install goes wrong.

This is not a preference. It is the condition under which the port has value.

## What is an unacceptable approach

Any of these is a defect, not a workaround:

- shipping a package whose only install path is the Forced Upgrade Tool
- shipping a package that cannot be updated again once installed
- documenting the V4 tool as a normal or expected install step
- recommending a V4 tool purchase as part of normal use

The one legitimate use is incident recovery for a device already in a bad state,
on the maintainer's own hardware, and it must be labelled as such wherever it
appears.

## Acceptance criteria

| # | requirement | status |
| --- | --- | --- |
| A1 | A stock official v15 instrument can install pass 3 with no vendor hardware | **holds** |
| A2 | A pass 3 instrument can install any later package with no vendor hardware | **holds once pass 3 is on the device** |
| A3 | Pass 1 and pass 2 are never distributed | **not yet enforced** |
| A4 | A pass 3 instrument that bricks is recoverable without the V4 tool | **unverified** |

A1 holds because the stock bootloader serves OTA: M-UPGRADE installed 012 to
015 on this Mac, and `smk37-fw` drives the same protocol.

A2 holds once pass 3 is installed, because it is built with `FELUCCA_OTA=1` and
`ota_upload_sloop_exact` drives the session over the Felucca transport.

A3 and A4 are open.

## A3: passes 1 and 2 are unrecoverable and must not ship

Pass 1 and pass 2 are built with `FELUCCA_OTA=0`
(`sloop-smk37/tools/build_smk37.py:22`). `ota_service()` sits inside
`#if FELUCCA_OTA`, so the firmware never answers the upgrade command and never
enters `ota_session()`. No host can install anything over such a build:

- M-UPGRADE rejects it on device name: it is `1209:0001 "Felucca"` and the
  updater expects `4353:cf4d "SMK-37 Pro Midi"`
- the repository tool could not either, until `94b35c5` gave it the correct
  Felucca transport, and even then the firmware still refuses

Once such a build is on the device the only way in is the bootloader download
path, which needs the V4 tool. That is the trap this port fell into and must not
fall into again. **Only pass 3 is a distributable build.** Passes 1 and 2 are
intermediate artifacts.

## A4: recovery of a pass 3 device is unverified

If a pass 3 instrument bricks, its OTA path dies with the application and
recovery falls back on the same bootloader download that needs the V4 tool.
Whether the SLOOP `ota_session` path can leave a device recoverable is not
established. Until it is, A4 is an open risk, and it is the reason the rollback
image in `backups/smk37-pro-live-before-sloop-20261011-a.bin` exists.

## How this was violated

Pass 1 was built with the FM-1 defaults, where in-app OTA is off, on the
reasoning recorded at `build_smk37.py:22-27` that updates would go through the
repository host tool instead. That reasoning was wrong: the host tool drives the
same in-application session, so a build with OTA compiled out cannot be updated
by anyone. The consequence was that this instrument ended up needing the V4
tool, which is exactly what this policy forbids.

The build comment predicted the failure and named the alternative:

    Rollback: esp32c3-usbkey / Jieli forced upgrade.

## Going forward

- A build profile is not finished until its successor can be installed on it.
  Ask that of every change, first, not as a formal gate afterwards.
- The macOS storage path was exhausted for hours before defaulting to the V4
  tool. That effort was not wasted, but it arrived too late: it was needed
  before pass 1 was flashed, not after.
