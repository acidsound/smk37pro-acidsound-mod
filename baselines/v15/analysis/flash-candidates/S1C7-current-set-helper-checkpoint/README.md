# S1-C7 current-set helper checkpoint offline release

Status: **PASS as current-set persistence checkpoint, not a full writer**.

App SHA-256 `71cfc1fcbeecd1a9277f88272be6b122a96f33fbd741d7486c670ffab6e58646`. FWSC SHA-256 `3dfb7e23debbd3a3055945b121991cf7a58b5f1cb59ff98f6dfba7dd084f2593`. OTA token `INSTALL-SMK37PRO-V15-S1C7-CURRENT-SET-HELPER-CHECKPOINT-3DFB7E23`.

This candidate patches the SAVE UI path to skip `0x02026d80..0x02026dd4`, reuses that whole S1C5-disabled body as a helper, preserves the S1C5 producer byte-for-byte, and uses `0x02004870` to restore exact host-seeded raw prefixes when RAM is not ARMED. No device access or live write was performed.
