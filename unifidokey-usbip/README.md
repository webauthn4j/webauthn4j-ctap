# unifidokey-usbip

CLI application that creates a virtual FIDO2 security key over USB/IP. Remote machines (Windows, Linux) can attach it over the network.

## Quick Start

```bash
# Build
./gradlew :unifidokey-usbip:quarkusBuild

# Start USB-IP server
java -jar unifidokey-usbip/build/unifidokey-usbip.jar serve

# Generate FIDO MetadataStatement for Conformance Tools
java -jar unifidokey-usbip/build/unifidokey-usbip.jar generate-metadata /tmp/metadata.json
```

## Commands

### serve

Starts the USB-IP server exposing a virtual FIDO2 security key.

```
Usage: webauthn4j-usbip serve [-hV] [-H=<host>] [-p=<port>]
  -H, --host=<host>   Bind address (default: 0.0.0.0)
  -p, --port=<port>   TCP port (default: 3240)
```

### generate-metadata

Generates a FIDO MetadataStatement JSON file for use with FIDO Conformance Tools.
The authenticatorGetInfo section is derived from an actual authenticator session.

```
Usage: webauthn4j-usbip generate-metadata <outputFile>
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
