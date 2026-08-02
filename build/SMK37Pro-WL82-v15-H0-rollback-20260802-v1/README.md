# SMK-37 Pro v15 H0 guarded rollback

Exact H0 heap-boundary diagnostic state only is restored to official v15.

- official v15 SHA-256: `f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff`
- H0 SHA-256: `114d814b5def641c979a5f0fbd2e5dc06d982c807662d5221dc2e0e936e5e566`
- permitted sectors: `0x04000`, `0x62000`

This bundle is offline-prepared only. It requires two fresh identical 1 MiB dumps and exact H0 target hashes before any erase/write. Do not reuse for any other build.
