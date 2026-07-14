# ESP32-C3 SMK-37 Pro USB_KEY generator

This is a recovery-entry signal generator, not a Flash writer. It sends Jieli
`USB_KEY` value `0x16EF` MSB-first at approximately 50 kHz:

- GPIO4: target USB D+ clock
- GPIO5: target USB D- data
- GND: target USB ground

The SuperMini's own USB-C remains connected to macOS for power and the console.
GPIO4 and GPIO5 are high-impedance at boot and after every attempt. No signal
is generated until the console receives the exact text `SEND USBKEY 16EF`.

Keep this as a standalone recovery tool. It has no dependency on SMK firmware
patch generation or normal OTA code. After it forces the WL82 boot ROM to
enumerate, a separate host-side tool must identify the target, dump Flash, and
perform any explicitly authorized restoration.

The firmware installs ESP-IDF's interrupt-driven USB Serial/JTAG driver before
reading commands. The default non-blocking VFS can return partial input to
`fgets()`, which is unsafe for an exact confirmation phrase. Board-only testing
confirmed that `PING` is received as one line and rejected once without driving
GPIO4/GPIO5.

Do not connect GPIOs directly to a Mac USB data pair or SMK USB data pair.
Each ESP output needs a series resistor, and the physical Mac/ESP/SMK USB
routing must be settled before connecting the instrument. Do not improvise a
Y cable while any device is powered.

A plain hub is insufficient. Its downstream ports do not expose one device's
data pins to another device. Forced entry requires an inline connection to the
SMK D+/D- pair, followed by a handoff of that pair from the C3 to the Mac after
the key is accepted. This project currently provides the key waveform and
high-impedance release only; the external two-line switch/handoff hardware is
not yet implemented or validated.

## Breadboard boundary

With the SuperMini USB-C connector pointing upward, GPIO4 is the fourth pad
down the left edge and GPIO5 is the first pad down the right edge. Solder two
male-header rows before mounting the board across the breadboard center trench.
The A-E holes of one numbered row are common, F-J of that row are separately
common, and the center trench isolates the two sides. Confirm the exact board
and split power rails with a continuity meter.

Only low-speed key-generation wiring belongs on the solderless breadboard:

- GPIO4 -> 330-ohm series resistor -> USB mux key-side D+;
- GPIO5 -> 330-ohm series resistor -> USB mux key-side D-;
- GND -> common ground;
- optional three-pin SPDT slide switch -> USB mux `SEL` control.

The two resistors must have the same value. `330 ohm`, 1/8 W or 1/4 W, limits
a worst-case 3.3 V contention to about 10 mA, but remains a provisional bench
value until the waveform is measured. It is not permission to connect the SMK.
Do not add 330-ohm resistors to the Mac USB D+/D- branch.

A three-pin SPDT switch cannot carry both D+ and D-. Use it only as a logic
selector for a dual 2:1 USB 2.0 mux such as TS3USB221A or FSUSB42. Keep the Mac
USB pair and common SMK pair on a purpose-built mux PCB/evaluation module with
short differential routing, not through breadboard rows or long jumpers. A
safe mux also needs a defined `OE` state that disconnects all ports during
reset or rewiring.

The mux PCB is the preferred implementation, not the only possible one. A
six-terminal DPDT center-off switch can provide the same two-pole handoff for
an experimental Full-Speed path if its paired wiring is extremely short.
Manual cable replacement after key transmission removes the switch but remains
unverified because the target may lose forced mode during VBUS disconnect.

The SuperMini by itself cannot replace any of these handoff methods. Its native
USB-C is a USB Serial/JTAG device used for the Mac console, not a transparent
USB switch or target-facing USB host. GPIO4/GPIO5 generate only the electrical
key waveform and then release to high impedance.

This external handoff was omitted from the initial C3-only wiring concept. The
vendor forced-upgrade tool is connected inline between the PC and target, and
the reverse-engineered dongle description reports the same two phases: send
the special signal, then pass the USB bus through to the host. This project is
therefore not yet a complete replacement for that dongle.

Build and upload:

```sh
source ~/esp/esp-idf/export.sh
cd esp32c3-usbkey
idf.py set-target esp32c3
idf.py build
idf.py -p "$ESP_PORT" flash monitor
```

Set `ESP_PORT` to the board's rediscovered serial device after reconnecting it.

Protocol reference:

- <https://kagaimiq.github.io/jielie/isp/usb/usb-key.html>
