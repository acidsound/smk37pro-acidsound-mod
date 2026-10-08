# macOS WL82 recovery tools

This is the macOS host-side sequence for the SMK-37 Pro forced-entry path. The
device must remain powered off until the host command is ready, because the
forced-entry identity can time out.

## Device-less preparation

```sh
make macos-wl82-recovery
build/smk37-wl82-macos-iokit-recovery self-test
python3 -m py_compile tools/prepare_macos_restore_plan.py
```

The recovery binary has no device access during `self-test`. Its `restore`
command refuses to run without all of the following:

- exact `WL80` USB / `WL82 UBOOT1.00` identity;
- the reviewed 31,232-byte loader and locked SHA-256;
- an approved plan covering exactly six 4 KiB sectors;
- two identical 1 MiB forced-loader dumps;
- an independent package/dump representation proof;
- current-sector preflight hashes matching the failed-M09 evidence;
- explicit target, range, and recoverability confirmations.

## One-session dump

Start this command before the single physical forced-entry sequence is
performed. It keeps identity, loader upload, loader queries, and both complete
dumps in one host session:

```sh
build/smk37-wl82-macos-iokit-recovery dump \
  --loader path/to/wl82loader.bin \
  --output build/wl82-readonly-session \
  --wait-seconds 90
```

The command waits for the exact USB interface, so it can be started before the
physical forced-entry sequence.

It sends no Flash erase or Flash write command. It produces `flash-dump-a.bin`,
`flash-dump-b.bin`, and `readonly-report.json`. The report deliberately keeps
`restore_authorized` false.

## Restore-plan gate

After the dumps and representation analysis are independently reviewed, create
the plan offline:

```sh
python3 tools/prepare_macos_restore_plan.py \
  --manifest build/m09-forced-recovery/manifest.json \
  --dump-report build/wl82-readonly-session/readonly-report.json \
  --representation-proof path/to/representation-proof.json \
  --stock-package build/SMK-37_Pro_012.fwsc \
  --output build/verified-restore/restore-plan.txt
```

Until those proofs exist, this command must stop and create no plan.

## Guarded restore

This command is reserved for the explicit restore step after the plan gate has
passed and the target, six-sector range, and recoverability have been reviewed
again. It erases and writes only the six audited 4 KiB sectors, reads each back,
and sends no reset/run-app command:

```sh
build/smk37-wl82-macos-iokit-recovery restore \
  --loader path/to/wl82loader.bin \
  --plan build/verified-restore/restore-plan.txt \
  --enable-write \
  --confirm-target 'WL82 UBOOT1.00' \
  --confirm-range 'six audited 4 KiB sectors only' \
  --confirm-recoverability 'two identical dumps and validated identity mapping'
```

Do not run this command from the preparation phase. A missing, malformed, or
hash-inconsistent plan causes `SAFE STOP` before the USB interface is opened.
