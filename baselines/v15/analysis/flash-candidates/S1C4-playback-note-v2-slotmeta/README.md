# S1-C4 Playback Note v2 slotmeta offline release

Status: **PASS, candidate built offline**.

App SHA-256 `0821809021c245645280b05b61732e210fa5a76e488fae32503e6074f49156cc`. FWSC SHA-256 `4151fb69acf44c75e58072871818869ebc0520828b86e3b05f87d325fc821c71`. OTA token `INSTALL-SMK37PRO-V15-S1C4-PLAYBACK-NOTE-V2-SLOTMETA-4151FB69`.

Selector is fail-closed: `r5` remains Trigger Note for non-Ch10, out-of-range, not-ARMED, and invalid-slot paths. Playback Note is read only after ARMED and selected-slot-valid gates pass. Trigger source remains `slot = trigger_note - 36`. Playback Note is local synth metadata only. Values `0..127` including duplicates are allowed, with repeated-note/cross-release risk documented. No live actions were performed.
