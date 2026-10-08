# S1-C1 additional-0xa0 boundary-only discriminator

Preserves exact H2 code and behavior. Changes only BSS and HEAP_BEGIN boundary immediates relative to H2.

- app SHA-256: `16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e`
- package SHA-256: `ae8c44a493e83d0b41ee422f21bdc115c4e1ff232376fd8a8abf609c96a3765d`
- H2-to-child changed app bytes: `4`
- changed sectors vs official v15: `0x04000, 0x20000, 0x22000, 0x2a000, 0x62000`
- second slot is never accessed
- no per-note selector exists
- no persistence is enabled
