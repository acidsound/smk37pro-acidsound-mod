# S1-C8 one-shot raw-prefix writer investigation: BLOCKED

Decision: no flashable v15/S1C7 successor or one-shot normal-firmware writer is defensible from the current exact v15/S1C5/S1C7 evidence.

A correct candidate would need to write records `96..111` at storage offsets `0x7d20 + slot*0xa3`, length `0x9c`, through wrapper `0x02004b02`, accept only full-length returns, then verify each prefix with `0x02004870` readback before reporting success. The exact 16 current-set prefixes alone require `16 * 0x9c = 2496` embedded source bytes if the firmware is to perform a one-shot write without host seeding.

Current exact blocker evidence:

- S1C5/S1C7 owned producer/selector window is only 278 bytes and has no free slack while preserving WebMIDI producer and playback behavior.
- The only always-disabled SAVE no-write slice is 44 bytes at `0x02026da8..0x02026dd4`.
- Prior exact lower-bound evidence shows even a compact direct-only no-readback experiment is not a defensible successor, and readback/manifest/failure semantics overrun the available window.
- No reviewed executable/data cave exists in the current exact evidence for 2496 bytes of constants plus checked writer/readback code.

Therefore emitting app/FWSC/exact OTA/rollback artifacts would misrepresent safety and could create a partial-write or recovery-prone candidate. S1C5 WebMIDI producer and playback behavior are preserved because this package emits only blocker analysis and validators.
