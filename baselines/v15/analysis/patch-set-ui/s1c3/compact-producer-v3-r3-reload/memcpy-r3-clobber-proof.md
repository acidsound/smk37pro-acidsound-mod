# memcpy r3 clobber proof and r3 reload fix

- Proven clobbering function: stock `memcpy` at `0x02048cce`.
- Body characteristic: uses volatile `r3` internally and saves only `r6,r5,r4`, so caller-held `r3` is not preserved across the call.
- Historical bug in the prior producer: `r3` held `loaded_count` before `call 0x02048cce`, then `add r3,#1` and `sb [r5+1],r3` used the clobbered value.
- New producer fix: after `memcpy`, `csync`, and `valid[i] = 1`, reloads `loaded_count` with `lb.z r3,[r5+1]` before `add r3,#1` and `sb [r5+1],r3`.
- New order from `decode.tsv`: `0x0201e1fc call32 -> 0x02048cce`, `0x0201e202 csync`, `0x0201e204 mov r0,#1`, `0x0201e206 sb [r6],r0`, `0x0201e208 lb.z r3,[r5+1]`, `0x0201e20a add r3,#1`, `0x0201e20c sb [r5+1],r3`.
- Reassembled targets: direct product callsite `0x0201e468 bfeaddfe -> 0x0201e226`; segmented product callsite `0x0201e49c bfeac1fe -> 0x0201e222`; direct/segmented reload callsites remain `bfeaf838` and `bfeade38`.
- Fit: `0x0201e1a2..0x0201e250` within owned `0x0201e1a2..0x0201e254`, 174 bytes used, 4 bytes spare.

No device, MIDI, reset, OTA, flash, or live send was performed.
