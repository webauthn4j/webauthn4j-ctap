# unifidokey-usbip

CLI application that creates a virtual FIDO2 security key over USB/IP. Remote machines (Windows, Linux) can attach it over the network.

## Quick Start

```bash
# Build
./gradlew :unifidokey-usbip:quarkusBuild

# Run
java -jar unifidokey-usbip/build/unifidokey-usbip.jar
```

## CLI Options

```
Usage: webauthn4j-usbip [-hV] [-H=<host>] [-p=<port>]
  -H, --host=<host>   Bind address (default: 0.0.0.0)
  -p, --port=<port>   TCP port (default: 3240)
  -h, --help          Show this help message and exit.
  -V, --version       Print version information and exit.
```

## Connecting from Linux

```bash
sudo modprobe vhci-hcd
usbip list -r <server-ip>
sudo usbip attach -r <server-ip> -b 1-1
```

## Connecting from Windows

Install [usbip-win2](https://github.com/vadimgrn/usbip-win2), then:

```powershell
usbip.exe list -r <server-ip>
usbip.exe attach -r <server-ip> -b 1-1
```
