# Device profiles

A profile describes one piece of hardware to the hub agent.
The agent holds no hardware-specific branch: everything that differs between devices is declared here.

A profile is a TOML file named after the device, for example `raspberry-pi-5.toml`.
The agent is started with one profile and refuses to start if the profile names a capability it has no module for.

## Shape

```toml
# Human-readable name of the hardware.
name = "Raspberry Pi 5"

[network]
# The interface the agent listens on. It never listens on any other.
interface = "eth0"

[display]
# "none", or the name of a display driver module.
driver = "none"
width = 0
height = 0

[key_store]
# Where the device key lives: "file" or "tpm".
kind = "file"

[radios]
# Radios the agent may use for observation. Empty means wired only.
wifi_monitor = false
bluetooth = false
```

## Rules

- A profile declares capabilities; it carries no secrets, addresses or customer data.
- `display.driver = "none"` is always valid: a hub works without a screen.
- A capability that is declared but not present on the machine is a start-up error, not a silent fallback.
- Adding a device: add a profile, add a driver module only if an existing one does not fit, and add the device to the table below.

## Supported devices

| Profile | Display | Key store | Status |
|---|---|---|---|
| `generic-linux.toml` | none | file | Planned: first development target |
| `raspberry-pi-5.toml` | small panel | file | Planned |
