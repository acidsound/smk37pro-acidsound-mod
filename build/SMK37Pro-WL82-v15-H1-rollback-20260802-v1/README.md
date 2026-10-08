# SMK-37 Pro v15 H1 guarded rollback

Exact H1 producer-unconsumed diagnostic state only is restored to official v15.

- official v15 SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- H1 SHA-256: `139ab42b3746477b8bf49e592ba94efd9f6c18b4a360e0e62807bc12e545dacf`
- permitted sectors: `0x04000`, `0x20000`, `0x22000`, `0x2A000`, `0x62000`

This bundle is offline-prepared only. It requires two fresh identical 1 MiB dumps and exact H1 target hashes before any erase/write. Do not reuse for any other build.
