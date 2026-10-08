#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build SLOOP for the SMK-37 Pro: app image from the pinned upstream SLOOP
core plus this port's board layer (BSP overlay, no upstream source edits).

    tools/build_smk37.py [--sdk PATH] [--host-check]

How the overlay works: the unity translation unit is a verbatim copy of the
upstream firmware/src/felucca.c (generated into build/gen/), compiled with
the board directories first on the include path:

    -I board/hal   shadows the FM-1 board HAL (input, LCD, audio, ADC, UART)
    -I board/src   shadows panel.c (the SMK-37 panel: pads carry the FM-1
                   buttons the SMK-37 Pro has no silkscreen for)
    -I upstream/firmware/hal, upstream/firmware/src, build/gen

Everything chip-level (GPIO, timers, IRQ, P33, SFC flash, USB0) is the same
AC791N/WL82 silicon as the FM-1 and comes from upstream untouched.

Build flags differ from the FM-1 build where the SMK-37 Pro hardware differs:
    FELUCCA_UART=0   no TRS MIDI IN jack on the SMK-37 Pro (OUT only)
    FELUCCA_OTA=0    the in-app M-UPGRADE server is the FM-1 updater's wire
                     protocol; the SMK-37 Pro path is the repo's exact_ota
                     with a repacked v15 FWSC (tools/make_smk37_fwsc.py).
                     Rollback: esp32c3-usbkey / Jieli forced upgrade.
    FELUCCA_ID       "SMK37_900"

Gates (offline; the repo's no-live-device rule is untouched):
    _start at 0x02000120 and the entry stub bytes (as upstream build.py);
    .ram_text without calls; no section in the SDRAM window 0x04000000 and
    none outside the confirmed windows 0x01C00000.. / 0x02000000..0x02100000
    (the RC-1 brick cause of 2026-08-15, docs/from-scratch-platform-plan.md);
    image <= the 617,012 B v15 app-data slot (tools/pack_sdk_app_fwsc.py).

Needs the JieLi pi32v2 Linux toolchain (JIELI_TOOLCHAIN; Docker on non-x86_64
Linux, as upstream BUILDING.md). Without it, --host-check runs the host-side
checks only (tests/run_smk37_tests.sh does the same plus the behaviour tests).
"""
import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = HERE.parent
REPO = PORT.parent
PIN = (PORT / "SLOOP_PIN").read_text().split()[0]
OUT = PORT / "build"
GEN = OUT / "gen"
APP_XIP = 0x02000120
APP_SLOT = 617012                      # v15 app-data slot (pack_sdk_app_fwsc)
RAM_LO, RAM_HI = 0x01C00000, 0x01C80000
XIP_LO, XIP_HI = 0x02000000, 0x02100000
SDRAM_LO, SDRAM_HI = 0x04000000, 0x05000000          # RC-1: refuse outright
CFLAGS = ["-Os", "-ffunction-sections", "-fno-builtin", "-Wall", "-Wno-unused-function"]
FLAGS = ["-DFELUCCA_FLASH=1", "-DFELUCCA_OTA=0", "-DFELUCCA_CDC=1",
         "-DFELUCCA_UART=0", "-DFELUCCA_UAC=1", '-DFELUCCA_ID="SMK37_900"']
DOCKER_IMAGE = os.environ.get("JIELI_DOCKER_IMAGE", "debian:bookworm-slim")


def sloop_src() -> Path:
    src = os.environ.get("SLOOP_SRC")
    if src:
        return Path(src).resolve()
    dest = PORT / "upstream" / "sloop-fm1"
    if not (dest / "firmware" / "src" / "felucca.c").exists():
        subprocess.run([sys.executable, str(HERE / "fetch_sloop.py")], check=True)
    got = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"],
                         capture_output=True, text=True).stdout.strip()
    if got != PIN:
        sys.exit(f"build_smk37: {dest} is at {got}, pin is {PIN} (tools/fetch_sloop.py)")
    return dest


def toolchain() -> Path:
    tc = os.environ.get("JIELI_TOOLCHAIN")
    if not tc or not (Path(tc) / "pi32v2" / "bin" / "clang").exists():
        raise SystemExit("build_smk37: JIELI_TOOLCHAIN must point at the JieLi Linux "
                         "toolchain (see upstream BUILDING.md / tools/get_toolchain.sh)")
    return Path(tc).resolve()


def use_docker() -> bool:
    native = platform.system() == "Linux" and platform.machine() in ("x86_64", "AMD64")
    return os.environ.get("JIELI_DOCKER", "0" if native else "1") == "1"


def tc(src: Path, tool: str, *args: str) -> str:
    rel = [str(Path(a).resolve().relative_to(PORT)) if isinstance(a, Path) else a for a in args]
    if tool == "cc":
        tool, rel = "pi32v2/bin/clang", ["-target", "pi32v2", *rel]
    if use_docker():
        cmd = ["docker", "run", "--rm", "--platform", "linux/amd64", "-v", f"{PORT}:/work",
               "-v", f"{toolchain()}:/opt/jieli:ro", "-w", "/work", DOCKER_IMAGE,
               f"/opt/jieli/{tool}", *rel]
    else:
        cmd = [str(toolchain() / tool), *rel]
    r = subprocess.run(cmd, cwd=PORT, capture_output=True, text=True)
    if r.returncode:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f"build_smk37: {tool} failed")
    return r.stdout


def tc_all(src, *cmds):
    with ThreadPoolExecutor(len(cmds)) as ex:
        return list(ex.map(lambda c: tc(src, *c), cmds))


def generate(src: Path) -> None:
    GEN.mkdir(parents=True, exist_ok=True)
    tools = src / "tools"
    cmds = [["gen_font.py", "felucca_font.h"], ["gen_icons.py", "felucca_icons.h"],
            ["gen_tables.py", "felucca_tables.h"], ["gen_samples.py", "felucca_samples.h"],
            ["gen_drumkits.py", "felucca_drumkits.h"], ["gen_fm6_patches.py", "felucca_fm6.h"],
            ["gen_logo.py", "sloop_logo.h"]]
    for script, out in cmds:
        subprocess.run([sys.executable, str(tools / script), str(GEN / out)], check=True)
    unity = GEN / "smk37_unity.c"                      # verbatim upstream unity TU
    shutil.copyfile(src / "firmware" / "src" / "felucca.c", unity)


def includes(src: Path) -> list:
    return [f"-I{PORT / 'board' / 'hal'}", f"-I{PORT / 'board' / 'src'}",
            f"-I{src / 'firmware' / 'hal'}", f"-I{src / 'firmware' / 'src'}", f"-I{GEN}"]


def build(src: Path):
    OUT.mkdir(parents=True, exist_ok=True)
    flags = [*CFLAGS, *FLAGS, *includes(src)]
    tc_all(src, ("cc", *flags, "-c", GEN / "smk37_unity.c", "-o", OUT / "unity.o"),
           ("cc", "-c", src / "firmware" / "crt0.S", "-o", OUT / "crt0.o"),
           ("cc", "-c", src / "firmware" / "hal" / "fm1_vec.S", "-o", OUT / "fm1_vec.o"),
           ("cc", "-c", src / "firmware" / "hal" / "fm1_isr.S", "-o", OUT / "fm1_isr.o"))
    elf = OUT / "smk37-sloop.elf"
    tc(src, "pi32v2/bin/ld", "-T", str(src / "firmware" / "app.ld"),
       str(OUT / "crt0.o"), str(OUT / "fm1_vec.o"), str(OUT / "fm1_isr.o"),
       str(OUT / "unity.o"), "-o", str(elf), "-Map", str(OUT / "smk37-sloop.map"))
    *_, syms, dis, rt = tc_all(
        src, ("common/bin/objcopy", "-O", "binary", "-j", ".text", str(elf), str(OUT / "text.bin")),
        ("common/bin/objcopy", "-O", "binary", "-j", ".data", str(elf), str(OUT / "data.bin")),
        ("common/bin/objcopy", "-O", "binary", "-j", ".ram_text", str(elf), str(OUT / "ramtext.bin")),
        ("common/bin/objdump", "-t", str(elf)),
        ("common/bin/objdump", "-d", str(elf)),
        ("common/bin/objdump", "-d", "-j", ".ram_text", str(elf)))
    (OUT / "smk37-sloop.dis").write_text(dis)

    def symv(name: str) -> int:
        return int(re.search(r"^([0-9a-f]+) .*\s" + name + r"$", syms, re.M).group(1), 16)

    img = bytearray((OUT / "text.bin").read_bytes())
    for sect, lname in (("ramtext.bin", "_rt_load"), ("data.bin", "_data_load")):
        load = symv(lname)
        if load % 4:
            raise SystemExit(f"{lname} {load:#x} is not word aligned")
        blob = (OUT / sect).read_bytes() if (OUT / sect).exists() else b""
        if blob:
            if load - APP_XIP < len(img):
                raise SystemExit(f"{lname} overlaps the image")
            img += b"\xff" * (load - APP_XIP - len(img)) + blob
    img += b"\xff" * (-len(img) % 4)
    (OUT / "smk37-sloop.bin").write_bytes(img)
    return bytes(img), syms, dis, rt


LINE = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)\s*\t(.*)$")


def check(img: bytes, syms: str, dis: str, rt: str):
    errors, notes = [], []
    m = re.search(r"^([0-9a-f]+) .*\s_start$", syms, re.M)
    if not m or int(m.group(1), 16) != APP_XIP:
        errors.append(f"_start is not at {APP_XIP:#x}")
    if img[:4] != bytes.fromhex("04818000"):
        errors.append(f"image starts with {img[:4].hex()}, not the entry stub")
    if [ln for ln in rt.splitlines() if re.search(r"\bcall\b", ln)]:
        errors.append(".ram_text contains calls")
    if len(img) > APP_SLOT:
        errors.append(f"image {len(img)} B exceeds the v15 app slot {APP_SLOT}")
    # RC-1 gate: every loaded section inside the confirmed windows, never SDRAM
    for ln in dis.splitlines():
        mm = LINE.match(ln)
        if not mm:
            continue
        for v in re.findall(r"= (-?\d+) <|call -?\d+ <[^:>]*: ([0-9a-f]+) >", mm.group(3)):
            val = (int(v[0]) & 0xFFFFFFFF) if v[0] else int(v[1], 16) & 0xFFFFFFFF
            if 0xFFC00000 <= val < 0xFFD00000:
                errors.append(f"reference to ROM address {val:#010x}")
    maptext = (OUT / "smk37-sloop.map").read_text() if (OUT / "smk37-sloop.map").exists() else ""
    for ln in maptext.splitlines():
        pm = re.match(r"\s*(\.[\w.]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)", ln)
        if not pm:
            continue
        name, addr, size = pm.group(1), int(pm.group(2), 16), int(pm.group(3), 16)
        if not size:
            continue
        if SDRAM_LO <= addr < SDRAM_HI:
            errors.append(f"section {name} at {addr:#x} is in the SDRAM window (RC-1)")
        elif not (RAM_LO <= addr < RAM_HI or XIP_LO <= addr < XIP_HI or addr < 0x10000):
            errors.append(f"section {name} at {addr:#x} outside confirmed windows")
    bss = int(re.search(r"^([0-9a-f]+) .*\s_bss_end$", syms, re.M).group(1), 16) - 0x01C08000
    notes.append(f"image {len(img)} B of {APP_SLOT}; RAM .data+.bss {bss} B")
    if bss > 96 * 1024:
        errors.append("RAM region overflow")
    return errors, notes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", type=Path, help="JieLi AC79 SDK checkout (packaging only)")
    ap.add_argument("--host-check", action="store_true",
                    help="run the host behaviour tests instead of a target build")
    a = ap.parse_args()
    if a.host_check:
        return subprocess.run(["sh", str(PORT / "tests" / "run_smk37_tests.sh")]).returncode
    src = sloop_src()
    generate(src)
    img, syms, dis, rt = build(src)
    errors, notes = check(img, syms, dis, rt)
    for n in notes:
        print("  ok   ", n)
    for e in errors:
        print("  FAIL ", e)
    if errors:
        raise SystemExit("build_smk37: checks failed")
    print(f"app      {OUT / 'smk37-sloop.bin'}  {len(img)} B")
    print("next:    tools/make_smk37_fwsc.py --app build/smk37-sloop.bin (offline packaging)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
