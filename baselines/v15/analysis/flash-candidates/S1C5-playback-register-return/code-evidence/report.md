# S1-C5 Playback Register Return code evidence PASS

Only the two S1-C4 v3 neutralized post-hook windows change. `0x0201c644` decodes as `lb.z r5,[r0]; mov r0,r0; mov r0,r0`. `0x0201c682` decodes as `lb.z r6,[r0]; mov r0,r0; mov r0,r0`. The exact S1-C4 v3 selector/producer window is preserved byte-for-byte and returns `r0 = dest + 0x9c` after storing the mapped Playback Note byte there.
