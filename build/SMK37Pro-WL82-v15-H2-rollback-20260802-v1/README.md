# SMK-37 Pro v15 H2 guarded rollback

Exact H2 owned-source corrected-fallback diagnostic state only is restored to official v15.

- official v15 SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- H2 SHA-256: `c1752a69ed8f905af58db0de7c3def29c416b71e832e2834e664cd5d17b85011`
- permitted sectors: `0x04000`, `0x20000`, `0x22000`, `0x2A000`, `0x62000`

This bundle is offline-prepared only. It requires two fresh identical 1 MiB dumps and exact H2 target hashes before any erase/write. Do not reuse for any other build.
