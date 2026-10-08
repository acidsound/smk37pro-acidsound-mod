# M09 forced-recovery plan

The failure analysis and ranked root-cause hypotheses are recorded in
`docs/m09-brick-incident.md`.

## Current state

M09 completed the normal OTA write but failed before normal display content
and USB initialization. The latest owner observation on 2026-07-16 is:

- the instrument powers on from its own supply;
- the LCD backlight turns on, but no pixels/UI are visible;
- USB does not enumerate;
- there is no observed battery fault.

The earlier immediate post-failure observation that the LCD and pad LEDs were
dark after a power cycle is retained in `docs/m09-brick-incident.md` as a
timeline event, not the current state. macOS detects neither normal
`4C4A:C755` nor updater `4D4A:4155`. The normal OTA and
`upload-resume-v12` paths are therefore unavailable.

The recovery concern is that USB-port VBUS On/Off is not the same event as
switching the instrument's independent power or asserting the SoC reset input.
LCD backlight alone proves that a power rail and the backlight path are alive;
it does not prove that the AC7911 application reached LCD or USB setup.

The remaining actions are ranked as follows:

1. **Controlled USB observation:** known-good data cable, direct isolated host
   port, both USB-C orientations, while recording attach/detach and descriptor
   errors. This can exclude cable/connector/host failures but cannot repair
   Flash.
2. **Guaranteed cold POR:** with every external cable removed, disconnect the
   internal battery connector only after the open-board photos and connector
   orientation have been reviewed. This can clear a latched PMU state but
   cannot repair M09. It is not a battery-fault test.
3. **Forced USB-key entry:** reset/power-on while V4 or a completed ESP32
   adapter transmits the key, then stop at `WL82 UBOOT1.00` identity. This is
   the first path that can make Flash recovery possible.
4. **Mapped internal reset or serial entry:** only after unpowered trace and
   continuity work. No public photo identifies a safe reset/update jumper.
   The WL82 SDK includes a serial download configuration, but SMK's battery
   and power network must be isolated and mapped before using it.

Blind factory-reset key sequences, the highest-C `RESET` label, external-Flash
MISO shorts, arbitrary test-pad shorts, and a normal switched USB hub are not
recovery procedures for this state.

The guaranteed cold-POR test was completed on 2026-07-16: battery and USB were
both removed for five minutes and residual rails were discharged before a
battery-only reboot. Instrument power, panel LEDs, and LCD backlight returned,
but the LCD remained completely blank. Do not repeat this test; move to
controlled USB observation and then forced entry.

The first controlled USB observation was also completed on 2026-07-16 with
the instrument independently powered and connected directly to a Mac. macOS
reported USB-C CC attachment and powered the host port, but created no
`IOUSBHostDevice`; neither the normal, updater, nor WL82 loader identity
appeared. This proves physical Type-C attachment and host-port activation, not
continuity of J5 D+/D- to U10 or operation of the target USB PHY. Test the
opposite USB-C plug orientation once before escalating to forced entry. That
orientation test was then completed: macOS detected the disconnect and new CC
attachment, powered its USB2 host port again, and still created no USB device
node. A one-orientation Type-C contact fault is therefore not a useful leading
hypothesis.

Do not reinstall M09. Do not use chip erase, burn a chip key, write another
product's image, or overwrite the whole 1 MiB Flash.

## Required entry hardware

AC7911B8 belongs to the AC791N/WL82 internal-Flash family. Jieli's official
documentation says an internal-Flash part that cannot run its firmware must be
reset while a forced-upgrade tool transmits `usbkey`. The preferred hardware
is Jieli Forced Upgrade Tool 4.0. A generic replacement is now implemented as
the independent ESP-IDF project `esp32c3-usbkey/` for an ESP32-C3 SuperMini.
It generates only the electrical `USB_KEY`; it does not enumerate the WL82,
load code, read Flash, or write Flash.

The ESP32-C3 tool was built and uploaded to the available board on 2026-07-15.
Its boot console confirmed GPIO4/GPIO5 high impedance and no automatic output.
An invalid console command was rejected while the lines remained high
impedance. The real `SEND USBKEY 16EF` command has not been executed, and no
ESP signal wire has yet been connected to the instrument.

Keep the recovery components separate:

- `esp32c3-usbkey/`: forced-entry signal generator only;
- `tools/smk37_wl82_macos.c`: host-side WL82 detection and, after staged
  validation, loader/read/write transport;
- `tools/prepare_m09_forced_recovery.py`: offline exact-sector preparation and
  hash manifest;
- normal SMK application patch/OTA tools: never a dependency of forced entry.

### Procurement decision

Prefer purchasing a genuine Jieli Forced Upgrade Tool 4.0 over completing a
one-off ESP32-C3 USB mux harness. The vendor tool already integrates the hard
parts that remain unvalidated here: reset/power handling, continuous
`USB_KEY`, target acknowledgement, and the data-bus handoff to the host. The
dated purchase-route check below separates advertised item price from a real
Korea-delivered total. A user-observed AliExpress checkout now provides the
lowest confirmed delivered total; the earlier forwarder-first recommendation
was based on an incomplete retail search and is superseded.

### Dated V4 purchase-route check: 2026-07-15

Jieli's current AC82 documentation says the 4.0 tool can be obtained from an
agent or the linked Jieli Taobao listing. That makes Taobao item
`620295020803` the provenance reference even when another seller is cheaper:

- official documentation/purchase link:
  <https://doc.zh-jieli.com/AC82/zh-cn/master/getting_started/preparation/usb_updater.html>
- Jieli-linked Taobao item:
  <https://item.taobao.com/item.htm?id=620295020803>

The official item's Korean delivered price was not visible without a Taobao
account and final address checkout, so it cannot honestly be called the
current cheapest total. The independently observable candidates are:

| Route | Observable offer | Korea delivery status | Decision status |
| --- | --- | --- | --- |
| AliExpress item `1005010073047537` | KRW 24,500, selected option `With cable`; listing title says Forced Burner V4.0 | KRW 3,994 shipping shown to Korea; **KRW 28,494 total** | Lowest confirmed delivered total and present purchase-route leader |
| AliExpress item `1005007907473118` | Additional user-found listing around USD 20; same V4.0 product-photo family | Live option and final checkout were not independently captured | Price-comparison lead, not yet a confirmed lower delivered total |
| Shenzhen Qingyue / GoldSupplier | USD 8, MOQ 1, 38 g package, V2.0 or V4.0 selected by inquiry | Quote required; no fixed shipping price | Lower advertised item price but not a usable delivered-price comparison |
| Taobao search, exact V4.0 with cable | CNY 149 in the latest public search snapshot, cable included, tax excluded | Requires Taobao Korea shipping or a forwarder | Item price alone already approaches or exceeds the confirmed AliExpress total |
| Taobao search, V4.1 | CNY 80 | Requires Taobao Korea shipping or a forwarder | Cheaper but not accepted until seller proves 4.0 protocol/firmware equivalence |
| AliExpress item `1005009768042266` | Korean product page exists | Reported temporarily out of stock during this check | Excluded |
| Newegg item `9SIANJZKKH7714` | Formerly indexed | Product URL now returns 404 | Excluded |

References:

- GoldSupplier V4 offer: <https://www.goldsupplier.com/provide/p173085127.html>
- Taobao price index: <https://tao.hooos.com/search?w=%E6%9D%B0%E7%90%86>
- current AliExpress leader:
  <https://ko.aliexpress.com/item/1005010073047537.html>
- additional user-found AliExpress lead:
  <https://ko.aliexpress.com/item/1005007907473118.html>
- unavailable AliExpress candidate:
  <https://www.aliexpress.com/item/1005009768042266.html>

The AliExpress screenshot for item `1005010073047537` also shows seller rating
4.9, 193 sold, free returns, and a July 20-26 delivery estimate. The displayed
KRW 4,100 coupon requires a KRW 30,000 basket, so it is not included in the
single-unit total above. The black inline enclosure, Jieli marking, two USB
connections, cable bundle, and V4.0 title are consistent with the official
tool family. The English `Jerry` in the title is treated as a common
translation/transcription error for Jieli, not as evidence of a different
model.

Photographs cannot prove that the internal hardware is genuine, that the tool
firmware is current and updateable, or that a seller substituted another
revision. Nevertheless, the exact option, delivered price, sales history, and
return policy make this a materially better one-off purchase candidate than a
USD-8 inquiry plus international quote or a Taobao forwarder. Before ordering,
reconfirm that the selected option still reads `With cable` and the title still
states V4.0. On arrival, inspect the labels and switch bank, test the V4 alone
on Windows, and make the first SMK interaction entry-only: switch-3 continuous
`usbkey` followed by read-only SCSI identity checks. Do not start with erase,
loader execution, or Flash writes.

For a single personal-use unit, all observed prices are below Korea's USD-150
small-consignment duty-free threshold, but Customs makes the final personal-use
determination. Customs reference:
<https://www.customs.go.kr/call/ad/crmcc/selectFaqViewPage.do?cnslKnwlSrno=482&mi=6822>.

Buying V4 does not force the Flash host to be Windows. In switch-3 mode the
hardware continuously sends `usbkey` without a PC command; after successful
entry the target should enumerate to the attached host as a mass-storage/SCSI
device. macOS or Linux software may then operate that device independently of
the dongle. The present software is not a complete Windows recovery-tool
replacement, however:

- `tools/smk37_wl82_macos.c` currently performs only standard read-only SCSI
  `INQUIRY`; its self-test passes but it has never seen the real target;
- `windows-readonly/` now has a Windows SCSI transport, exact WL82 identity
  lock, official-loader hash lock, and double-dump verification, but has not
  run against the real target and intentionally has no restore path;
- `jl-uboot-tool` has loader/read/write logic, but no macOS transport and marks
  actual WL82 support unknown;
- the official Windows `isd_download.exe` plus the AC79 WL82 loader remains the
  only researched vendor-supported complete path.

Therefore use V4 first to prove forced entry on the Mac without a Flash write.
If `WL82 UBOOT1.00` appears, extend the native macOS host in the staged order
INQUIRY -> loader identity -> full read-only dump -> verified sector readback.
Do not add erase or write commands merely because the hardware entry succeeds.
The ESP32-C3 project remains a documented fallback and protocol test source,
not the preferred first connection to the failed instrument.

The separate public-board audit in `docs/internal-recovery-entry.md` found no
visible user reset/boot DIP or jumper. It did identify PB1/QFN48 pin 42 as the
SoC's long-press reset net and pins 47/48 as the existing USB D-/D+ pair. An
internal reset point could provide the genuine reset edge that USB VBUS
cycling cannot guarantee while the instrument remains independently powered,
but reset alone does not enter forced mode. No unknown pad may be shorted
before unpowered trace and continuity mapping.

### Pre-purchase restoration feasibility audit

The V4 purchase has strong product-family justification, but it is not a
guaranteed repair. Jieli's AC79 USB-download documentation explicitly says
that internal-Flash AC79 variants use the forced-upgrade tool and identifies a
successful device as `WL82 UBOOT1.00 USB Device`. This is substantially
stronger evidence than a generic Jieli-chip compatibility list:

- <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.1.0/getting_started/preparation/update.html>

The official AC79 v1.2.0 SDK branch also contains `wl82loader.bin` and invokes
`isd_download` with `-dev wl82 -boot 0x1c02000 -tonorflash`. At inspected
commit `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`, its loader is 31,232 bytes
with SHA-256
`9920e66626fc86b2db536050a4d23dec10c8d1081575553539835fd812276c27`.

The V4 can nevertheless fail to produce a restorable target at four separate
gates:

1. **No real reset/key acceptance.** The official switch-1 mode resets a
   target by removing tool-supplied VBUS for at least 250 ms. SMK-37 Pro has
   another power source, so that action alone may not reset its processor.
   Switch-3 continuously transmits the key, but the instrument still needs a
   genuine power-on/reset edge while the key is present. A soft front-panel
   power state is not yet proven equivalent to a chip reset.
2. **No `WL82 UBOOT1.00` enumeration.** A damaged USB connector/PHY, unstable
   rail or oscillator, wrong data adapter, old/counterfeit V4 firmware, or an
   undocumented product-specific boot/security setting can prevent entry.
   AC79 documentation provides no evidence that SMK uses such a disabling
   setting, so this is a residual possibility rather than the leading
   hypothesis. V4 firmware itself is updated through Jieli's package-manager
   workflow; confirm that a purchased unit is current.
3. **Entry works but no usable host transport.** This was a major risk while
   only Apple Silicon macOS was available: the native tool stops at standard
   read-only SCSI `INQUIRY`, and Jieli's Linux `isd_download` is an x86-64
   ELF. A Windows laptop is now available, so the official Windows SDK path
   and the existing open-source Windows SCSI pass-through backend can be used.
   The risk is reduced, but the exact WL82 loader/dump sequence still has to be
   validated on the real target.
4. **Loader/dump/write incompatibility.** `jl-uboot-tool` labels real WL82
   support `unknown`. Its bundled WL82 loader is 24,064 bytes with SHA-256
   `d41da6126760c9d66660bcc0cac8d27d221806c5e369a8036921efe68dca5376`,
   not the inspected official v1.2.0 loader. Do not assume they are
   interchangeable. The macOS path must use the reviewed official loader or
   first prove another loader entirely through non-destructive identity and
   full-dump tests.

The official SMK `012.fwsc` file is an application OTA container, not a file
that V4's forced loader can consume directly. A working V4 therefore unlocks
development of the recovery transport; it does not by itself install
`012.fwsc`.

There are two distinct Flash representations. The recovery manifest hashes
the `flash.bin` bytes unpacked from `.fwsc`. Normal-mode live dumps are the
physical raw Flash representation with additional address-dependent SFC
scrambling. Applying key `0x980F` maps the first 32 raw bytes to the package
image, but the project has not derived or validated that mapping for every
address. It is not yet known whether the forced loader returns those physical
bytes, a controller-decoded view, or another representation on this target.
Consequently the six package-side `expected_m09_sha256` values must **not** be
compared directly with forced-loader sector hashes and the package-side stock
sector files must **not** be written directly. The first forced-mode milestone
is acquisition only; returned dump semantics and any required conversion are
new mandatory gates before a writer can be designed.

M09 did not intentionally remove the forced-entry path. Its audited manifest
keeps the following official-v12 hashes unchanged before and after patching:

- Flash/boot layout `0x0000..0x3fff`;
- `uboot.boot` at `0x00a0..0x38cf`;
- `isd_config` at `0x38d0..0x3b8a`;
- all data after the application area.

Only six 4 KiB application sectors differ in the prepared recovery manifest.
Consequently an M09 application crash is more likely than deliberate
destruction of Mask ROM entry or the boot prefix. An interrupted or unexpected
OTA write could still have produced different live Flash contents, so the
failed unit must be dumped before the dump/package relationship can be solved and
the six intended change sectors can be evaluated.

Current confidence by checkpoint:

| Checkpoint | Confidence before real V4 test | Reason |
| --- | --- | --- |
| V4 is the correct hardware class for AC791/WL82 internal Flash | High | Explicit AC79 documentation |
| The SMK will enumerate as `WL82 UBOOT1.00` | Medium-high | Boot prefix was preserved, but reset and product settings are untested |
| macOS can identify the enumerated device | Medium | Probe is implemented but has never seen the target |
| A complete read-only Flash dump will succeed | Medium | Windows SCSI transport exists; real WL82 loader use remains untested |
| Six-sector stock restoration will succeed | Blocked after dump until mapping | Raw/package conversion and WL82 write/readback are both unproven |

Purchase is reasonable as a recovery-enabling instrument, not as a guaranteed
consumer repair. Prefer a seller who confirms all of the following in writing:

- genuine V4 hardware with current firmware;
- AC791N/WL82 internal-Flash USB forced upgrade support;
- both required host/target data cables or an exact connector description;
- return eligibility if it cannot produce `WL82 UBOOT1.00`.

After arrival, the first test is entry plus `INQUIRY` only. If the identity
does not appear, stop before any loader or Flash command. If it appears, the
next development gate is official-loader upload followed by a full read-only
dump. Chip-key burn, chip erase, boot-prefix write, and direct full-image write
remain prohibited.

Inspected official Linux package:

- URL: <https://jl-update.oss-cn-shenzhen.aliyuncs.com/jieli-linux-post-build-tools-20260129.1.tar.xz>
- archive SHA-256: `c2c51251411f4cea1fae244655c5927cacf31da8a1bd8b2410c06667ab2f9784`
- `isd_download` SHA-256: `562ea21eeba82a846050d9155215dc68323636932fa3155e3c43528a552abaf4`
- architecture: Linux x86-64, statically linked

### Windows-host path

Availability of an x86/x64 Windows laptop materially improves the recovery
case. It eliminates the need to port SCSI pass-through to macOS before the
first target test. Keep two Windows tool roles separate:

- Jieli's official `isd_download.exe` and official `wl82loader.bin`: the
  vendor-supported AC79/WL82 loader and download path;
- `jl-uboot-tool`: an open-source Windows `SCSI_PASS_THROUGH_DIRECT` transport
  that exposes raw Flash read/dump and sector erase/write operations.

The official AC79 SDK includes `write_file_to_flash.bat` with this form:

```bat
isd_download.exe isd_config.ini -tonorflash -dev wl82 ^
  -boot 0x1c02000 -div 1 -wait 300 -todisk FILE ADDRESS
```

Despite its name, `-todisk` writes `FILE` to the target Flash at `ADDRESS`; it
is not a Flash-backup command. The earlier description of it as a generic
direct form was ambiguous. Do not run it before a full dump and target-sector
hash validation. The official downloader does perform content comparison in
normal download flows and documents `ERR_CRCCMP` for a post-download mismatch,
but this does not replace archiving the failed Flash before repair.

`jl-uboot-tool` has a Windows backend and commands equivalent to:

```text
read ADDRESS LENGTH FILE
erase ADDRESS LENGTH
write ADDRESS FILE
```

Its `write` command automatically aligns and erases 4 KiB or 64 KiB regions
before writing. The unmodified interactive program also exposes dangerous
`erasechip`, chip-key, and arbitrary memory commands. Do not use that shell
directly for recovery.

The separate `windows-readonly/` program implements the safe acquisition
subset instead. Its 16-byte vendor-CDB allowlist contains only volatile-RAM
loader upload/jump, loader information queries, and Flash read. Flash
erase/write, key write, reset/run-app, format, and generic interactive command
paths do not exist. It requires exact INQUIRY vendor `WL82`, product
`UBOOT1.00`, exact official-loader size/hash, a fixed 1 MiB address range, two
byte-identical dumps, and a declared distinction between package and an
unvalidated forced-loader representation. It records the six candidate-sector
dump hashes but always reports
`restore_authorized: false`. The portable bundle contains numbered
PowerShell/CMD entry points and generates its own file-hash manifest.

Running `00-self-test.cmd` without hardware validates the fake transport,
command allowlist, loader hash when present, double-dump comparison, and M09
manifest logic. It cannot dump the bricked instrument without the instrument
and V4. The actual sequence remains probe -> RAM loader probe -> human review
-> double dump. Add a separate manifest-locked sector writer only after the
real dump passes and its package relationship is independently validated.

The Windows sequence after V4 arrival is therefore:

1. Obtain the SDK and package-manager components only from Jieli's official
   documentation/Gitee endpoints; update V4 and `isd_download` before target
   use.
2. Connect V4 and produce `WL82 UBOOT1.00`; do not run `download.bat`.
3. Use `windows-readonly/` to upload the exact reviewed official WL82 loader
   to RAM, jump to it, and dump `0x000000..0x0FFFFF`.
4. Copy both byte-identical dumps off the Windows laptop and archive their
   hashes plus the six candidate-sector dump hashes.
5. Identify and independently test the forced-loader dump representation and
   its relationship to `.fwsc` `flash.bin` bytes.
6. Only after that separate gate, design a manifest-locked writer and its
   correctly derived readback expectations. No writer currently exists.

Running an official full SDK `download.bat` is not the first recovery action:
it can rewrite layout, VM, resources, boot configuration, and product data,
and the SMK `012.fwsc` is not its native input set. Never add `-format vm` or
`-format all`. Never provide or burn a key file during this recovery.

Windows reduces the host-software risk from a required platform port to a
bounded WL82 compatibility test. It does not remove the two decisive gates:
V4 must first expose `WL82 UBOOT1.00`, and the official loader must then produce
a repeatable read-only dump. If either fails, stop without writing.

Because SMK-37 Pro remains independently powered when USB VBUS is removed, the
dongle's switch-1 VBUS cycling does not guarantee a processor reset. This is
not a battery-fault hypothesis. The likely entry sequence is:

1. Turn the instrument fully off.
2. Put the official forced-upgrade tool in switch-3 continuous-`usbkey` mode,
   or arm the reviewed ESP32-C3 tool without yet sending its confirmation
   command.
3. Connect the dongle between an isolated host USB port and the SMK USB-C data
   port using a data-capable adapter.
4. Turn the instrument on once while the dongle is transmitting the key.
5. Confirm a `WL82 UBOOT1.00`-style mass-storage identity before running any
   loader command.

This sequence remains unverified on SMK-37 Pro. The forced tool operates on
the existing USB data pair. Opening the instrument is useful only for the
documented photo-first reset/USB mapping in `docs/internal-recovery-entry.md`;
do not probe or short the mainboard merely to try forced entry.

Before substituting the ESP32-C3, settle the physical D+/D- routing. The C3's
native USB-C remains connected to macOS for power and console, while GPIO4 is
the target D+ clock and GPIO5 is the target D- data signal. Both GPIO paths
require series resistance. A plain USB hub is not a signal injector: connecting
the C3 and SMK to two downstream ports makes both of them separate devices of
the Mac and gives the C3 no electrical access to the SMK data pair.

Per-port On/Off buttons do not by themselves change that conclusion. Most
consumer switched hubs control downstream VBUS or the hub controller's port
state; the button is not evidence that both D+ and D- become electrically
isolated. Even a data-disabling hub still does not route one downstream port
to another. A specific hub can serve as the **host-isolation half** of the
handoff only if its schematic or bench measurement proves that its selected
downstream D+/D- pair is truly high impedance while Off. The topology would
then require a separate target-cable breakout: the isolated hub branch and
the protected ESP GPIO branch meet only at the SMK pair, the ESP becomes high
impedance before the hub port is enabled, ground remains common, and VBUS
cannot backfeed. This can functionally avoid a 2:1 mux, but it is a modified
parallel-injection harness rather than normal hub use. A VBUS-only port switch
cannot do it, and VBUS switching still does not guarantee a reset while the
SMK remains independently powered.

The researched protocol requires two data-bus phases. During `USB_KEY`, the C3
must control the target D+/D- pair. After target acknowledgement, the C3 must
release both lines and the target pair must be switched to the Mac host for USB
enumeration. Therefore the reliable topology needs an inline USB data breakout
plus a reviewed two-line switch/multiplexer, or equivalent forced-upgrade
hardware. Do not directly parallel GPIOs onto an active host pair or improvise
a powered USB Y cable. A hub may supply power and an isolated host port, but it
does not replace the data-pair tap or phase switch. Hub traffic from unrelated
full/low-speed devices may also disturb the target's initial USB clock
measurement, so use a dedicated/otherwise empty path for first validation.

### Breadboard and data-switch correction

The ESP32-C3 SuperMini pinout must be read with its USB-C connector at the top.
In that orientation GPIO4 is the fourth castellated pad down the left edge and
GPIO5 is the first pad down the right edge. A bare SuperMini needs two soldered
2.54 mm male-header rows before it can straddle a solderless breadboard's
center trench.

On a conventional breadboard, the five holes in each numbered A-E strip are
connected together, the five holes in the matching F-J strip are connected
together, and the center trench separates those two strips. Power rails are
separate from the numbered strips and may themselves be split midway. Verify
the actual board with continuity mode; do not infer connection from physical
proximity.

A three-pin slide switch is one SPDT pole. It cannot switch both D+ and D- and
must not carry the USB pair directly. It can instead drive the `SEL` input of a
proper dual-channel 2:1 USB 2.0 mux.

The mux board itself is not a protocol requirement. The required function is a
two-pole, break-before-make handoff of D+ and D- from the ESP key source to the
Mac host. The available implementations are:

1. a USB 2.0 2:1 mux PCB or evaluation module: preferred and repeatable;
2. a six-terminal DPDT center-off switch with extremely short paired data
   wiring: possible for a Full-Speed prototype, but less reliable;
3. physically replacing the ESP target cable with the Mac cable after key
   transmission: no extra switch, but unverified because VBUS loss or reconnect
   timing may make the target leave forced mode.

The ESP32-C3 alone cannot perform the handoff. Its native connector is a USB
Serial/JTAG device connected to the Mac; it is neither a transparent analog
path nor a general USB host for the SMK. GPIO4/GPIO5 can generate the key and
then become high impedance, but they cannot forward the Mac's differential USB
waveform to the target.

This handoff requirement was missing from the first ESP32-C3-only wiring
concept. The vendor tool is an inline device between the PC and target, while
the reverse-engineered dongle description explicitly says that it sends the
key and then passes the USB bus through to the host. Therefore the current C3
firmware is only the key-source half of a complete recovery adapter.

A robust mux-based prototype keeps these parts on separate electrical domains:

- breadboard: SuperMini, its 3.3 V/GND rails, GPIO4/GPIO5 protection
  resistors, and low-speed `SEL`/`OE` control;
- USB-switch PCB or evaluation module: Mac D+/D-, protected ESP D+/D-, and the
  common SMK D+/D- pair, all with short differential routing;
- target cable/breakout: SMK USB-C D+/D-, VBUS, and GND with every conductor
  identified by continuity rather than trusting cable colors.

USB-switch candidates with an explicit disconnect state include TI
TS3USB221A and onsemi FSUSB42. Both switch D+ and D- together; `OE=HIGH`
disconnects all ports. FSUSB42 additionally specifies internal
break-before-make timing. TI's TS3USB221EVM/221EEVM is the reference-module
route and uses controlled-impedance PCB traces. The small bare IC packages are
not solderless-breadboard parts.

For the 50 kHz ESP-only key branches, use equal-value series resistors on both
GPIO4 and GPIO5 before the mux. `330 ohm`, 1/8 W or 1/4 W, is the conservative
first bench value: a hard 3.3 V contention is limited to approximately 10 mA.
This value is an engineering starting point, not a Jieli-validated component
value; verify the waveform and target levels before connection. Do not put
these 330-ohm resistors in the Mac USB host branch. Do not substitute arbitrary
very-low or multi-kilohm values.

Pinout reference supplied for the board in use:

- <https://europe1.discourse-cdn.com/arduino/original/4X/c/2/8/c286595a99d202f8a3aef6d6caf1f2c90474200d.jpeg>

Switch and electrical references:

- <https://www.ti.com/product/TS3USB221A>
- <https://www.ti.com/lit/pdf/scdu001>
- <https://www.onsemi.com/download/data-sheet/pdf/fsusb42-d.pdf>
- <https://documentation.espressif.com/esp32-c3_datasheet_en.html>
- <https://github.com/kagaimiq/jl-uboot-tool/blob/main/docs/how-to-enter-uboot.md>

## Host software candidates

- Official AC79 SDK v1.2.0 includes `wl82loader.bin` and Windows
  `isd_download.exe`. Its `-todisk <file> <address>` form is a direct target
  Flash write, not a read/dump operation.
- `jl-uboot-tool` commit `adb3f18889e88ac512ce0a3c4d8cc3d3cb30696a`
  includes WL82 protocol metadata and a WL82 loader, but labels real WL82
  support `unknown`. Treat it as read-only until a full dump succeeds.
- The open-source tool has Linux and Windows SCSI transports, not a macOS
  transport. Its Linux implementation sends the JL vendor CDBs through the
  standard `SG_IO` ioctl and is the preferred first recovery host.
- `windows-readonly/` is the preferred Windows acquisition host. It derives
  the actual SCSI Path/Target/LUN from the selected physical drive, accepts
  only exact `WL82 UBOOT1.00`, and has no Flash-mutating CDB implementation.
  Its device-less self-test passes; the real V4/WL82 path is still unverified.
- A native macOS port is technically possible. The installed macOS SDK exposes
  `SCSITaskDeviceInterface`, `CreateSCSITask`, `ExecuteTaskSync`, data-transfer
  buffers, sense data, and exclusive-access control. It would require a new
  backend plus device-side validation, so it must not debut with Flash writes.
  The first native checkpoint is implemented as
  `tools/smk37_wl82_macos.c`. It compiles on the current Apple Silicon macOS
  host and exposes only `self-test` and standard read-only SCSI `INQUIRY` via
  `probe`; it contains no JL vendor or Flash commands. Prove INQUIRY, loader
  upload, and full read-only dump in that order before adding a write path.
- Docker on macOS is not equivalent to a Linux USB host for this purpose. Use a
  physical Linux system or a VM that provides real USB-device pass-through.

Build and run the native read-only probe with:

```sh
make macos-wl82
build/smk37-wl82-macos self-test
build/smk37-wl82-macos probe
```

The probe requests exclusive SCSI access but does not automatically unmount
media. If macOS mounts the WL82 pseudo-disk and the probe reports busy, inspect
and unmount that specific disk before retrying; never unmount by an ambiguous
disk number.

Official SDK snapshot used for comparison:

- repository: `https://gitee.com/Jieli-Tech/fw-AC79_AIoT_SDK.git`
- branch: `release/AC79NN_SDK_V1.2.0`
- commit: `e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d`

## Minimal restoration scope

The exact M09 Flash image differs from the exact official-v12 Flash image in
only six 4 KiB sectors:

| Sector | Reason represented in that sector |
| --- | --- |
| `0x04000` | application-area CRC/header |
| `0x20000` | Note Off hook |
| `0x21000` | Note On hook and wrapper |
| `0x27000` | local-pad bridge hook |
| `0x5A000` | display marker |
| `0x99000` | attempted DX7 runtime templates and related ciphertext |

Prepare exact sector files offline with:

```sh
python3 tools/prepare_m09_forced_recovery.py \
  build/SMK-37_Pro_012.fwsc \
  build/SMK37ProMod-M09-dx7-drums-base012.fwsc \
  build/m09-forced-recovery
```

This command does not access USB. Its sector files and hashes are in the
FWSC-unpacked `flash.bin` representation, not a validated forced-loader
representation. Before any write, forced mode must first dump the entire
1 MiB Flash twice. Preserve both byte-identical files, but do not expect their
candidate-sector hashes to equal `expected_m09_sha256` until the returned
representation is identified.

A later writer may touch only the six sectors after the dump/package relationship is
validated. It must preserve `0x00000..0x03FFF`, all non-target application
sectors, and all user/calibration regions, then verify separately derived
readback hashes. The current package-side stock files are not valid direct
writer inputs.

## Evidence needed before declaring recovery

1. Forced-loader identity and chip family are WL82/AC791N.
2. A read-only full dump succeeds and is archived before writing.
3. Two complete forced-loader dumps are byte-identical.
4. Dump/package representation semantics are validated for every candidate address.
5. Each written sector reads back with a separately derived expected hash.
6. Normal USB identity returns as `SMK-37 Pro_012`.
7. Display 1.05, audio, local keys, pads, and user banks are checked.

## Sources

- <https://doc.zh-jieli.com/AC79/zh-cn/release_v1.1.0/getting_started/preparation/update.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/upgrade_and_download.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/forced_upgrade/toggle_switch.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/dev_tools/faqs/why_failed_to_download.html>
- <https://doc.zh-jieli.com/Tools/zh-cn/other_info/index.html>
- <https://github.com/kagaimiq/jl-uboot-tool>
- <https://developer.apple.com/documentation/iokit/scsitaskinterface>
- <https://developer.apple.com/documentation/iokit/scsitaskdeviceinterface/1575374-obtainexclusiveaccess>
