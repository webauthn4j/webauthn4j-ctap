# unifidokey-uhid

CLI application that creates a virtual FIDO2 security key on Linux via UHID.

## Quick Start

```bash
# Build
./gradlew :unifidokey-uhid:quarkusBuild

# Run (requires root or udev rules for /dev/uhid access)
sudo java -jar unifidokey-uhid/build/unifidokey-uhid.jar
```

## CLI Options

```
Usage: webauthn4j-uhid [-hV] [-d=<devicePath>]
  -d, --device=<devicePath>   UHID device path (default: /dev/uhid)
  -h, --help                  Show this help message and exit.
  -V, --version               Print version information and exit.
```

## Verifying the Device

```bash
ls /dev/hidraw*
fido2-token -L
```

## Permissions

Run with `sudo`, or create a udev rule:

```bash
sudo usermod -a -G input $USER
echo 'KERNEL=="uhid", GROUP="input", MODE="0660"' | sudo tee /etc/udev/rules.d/99-uhid.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
# Log out and back in
```
