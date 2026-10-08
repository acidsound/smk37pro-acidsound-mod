# S1-C5 Marked Playback Note code evidence PASS

The two S1-C4 v3 neutralized post-hook windows change, and the same-length display marker changes from `1.10` to `S1C5`. `0x0201c644` decodes as `lb.z r5,[r0]; mov r0,r0; mov r0,r0`. `0x0201c682` decodes as `lb.z r6,[r0]; mov r0,r0; mov r0,r0`. The exact S1-C4 v3 selector/producer window is preserved byte-for-byte and returns `r0 = dest + 0x9c` after storing the mapped Playback Note byte there.
