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
