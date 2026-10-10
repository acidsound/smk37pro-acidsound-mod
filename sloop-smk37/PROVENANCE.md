# PROVENANCE — sloop-smk37

| Item | Value |
|---|---|
| Upstream project | https://github.com/isod89/sloop-fm1 (SLOOP for M-VAVE FM-1) |
| Upstream pin | `a1c5d68767ae10fafb6821dc63b9b1fc490342d2` (see `SLOOP_PIN`) |
| Upstream version | SLOOP 2.4.1 behaviour |
| Upstream licence | GPL-3.0-only |
| This port's licence | GPL-3.0-only (derivative work) |
| Target hardware | SMK-37 Pro (Jieli AC791N / WL82 family, pi32v2) |

## Derived files

- `tests/ui_pages_smk37_test.c` is derived from upstream `tests/ui_pages_test.c`.
  The only change is the include of the panel layer
  (`"../firmware/src/panel.c"` → `"../board/src/panel.c"`) plus a banner comment.
  Regenerate with:

  ```sh
  sed -e 's#"../firmware/src/panel.c"#"../board/src/panel.c"#' \
      $SLOOP_SRC/tests/ui_pages_test.c > tests/ui_pages_smk37_test.c
  ```

- `tools/build_smk37.py` copies upstream `firmware/src/felucca.c` verbatim into
  `build/gen/smk37_unity.c` at build time; nothing from upstream is committed here.
- `board/hal/*.h` and `board/src/panel.c` are new code written against the
  upstream HAL contracts (`firmware/hal/*`, `firmware/src/core.h`).

## Not included

- No JieLi SDK blobs, no official firmware images, no flash dumps.
- `build/` (generated headers, host test binaries, PPM renders) is git-ignored.
