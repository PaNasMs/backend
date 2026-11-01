# Optional physical shutdown button

Raspberry Pi 5 builds with a compatible external power-cut board can configure
both functions in Settings → General → Power control. First setup selects both
options, but does not claim GPIOs until settings are saved. Existing installations
retain their settings and do not enable a button input during upgrade.

The final output defaults to BCM GPIO25 (physical pin22); the button input defaults
to BCM GPIO22 (physical pin15). These are candidates, not universal free pins.
Confirm the actual board pinout and wiring. The input is active-low with a 3.3V
pull-up; use a normally-open contact to ground or an appropriately wired
optocoupler. Never connect a 12V switch node directly to a Raspberry Pi GPIO.
See the [hardware guide](https://panasms.github.io/hardware/rpi_radxa_penta/#power-button-shutdown)
for the proposed Pololu/PC817 circuit and its physical validation limitations.

Saving final power control requires a reboot to activate the kernel overlay.
The input waits for that output to be active, then waits for a stable initial
release. Only a later complete press/release (100ms debounce per transition)
requests normal systemd poweroff. Shutdown may interrupt NAS tasks. The input
never drives the OFF output itself. Agent restart resets arming; a held button
is ignored. Failed GPIO reads disarm the detector. Request failure is reported
in the agent journal. After a stable release, a new deliberate press/release can
retry; no automatic shutdown retry occurs.

The Pololu ON signal can override OFF while physically asserted. Release the
button and do not hold it during final shutdown; software cannot guarantee power
removal against that electrical override. The input feature has automated state
and configuration tests, but the optocoupler assembly is not physically qualified.
The owner's installed ON-only button remains unchanged.
