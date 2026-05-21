# webauthn4j-ctap-authenticator-usbip

Library that exposes a `CtapAuthenticator` as a virtual USB HID FIDO2 device over USB/IP (TCP/IP).

The primary use case is running **FIDO Conformance Tests on Windows** against the WebAuthn4J CTAP Authenticator. The `unifidokey-usbip` CLI application uses this module to serve the authenticator, and Windows-side tools connect via USB/IP as if it were a physical security key.

## Requirements

- Java 17+
- USB/IP client on the connecting machine ([usbip-win2](https://github.com/vadimgrn/usbip-win2) for Windows, `usbip` for Linux)

## Usage

```kotlin
val authenticator = CtapAuthenticator()
val config = USBIPDeviceConfig(host = "0.0.0.0", port = 3240)
val device = USBIPDevice(authenticator, config)
val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

device.start(scope)
// Clients can now attach via: usbip attach -r <server-ip> -b 1-1
```

## Key Classes

| Class | Description |
|---|---|
| `USBIPDevice` | TCP accept loop, lifecycle management, and URB routing |
| `USBIPClientHandler` | Per-client protocol state machine |
| `USBIPDeviceConfig` | Server and device configuration |
| `ControlRequestHandler` | USB control endpoint (EP0) handling |
| `InterruptEndpointHandler` | HID interrupt endpoint handling |
