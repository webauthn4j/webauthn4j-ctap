# webauthn4j-ctap-authenticator-usbip

Expose virtual FIDO2 USB devices through a single USB/IP TCP server. Java 17+ is required.

```kotlin
val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
val server = USBIPServer(host = "0.0.0.0", port = 3240)
val first = USBIPDevice(CtapAuthenticator(), USBIPDeviceConfig(busId = "1-1", devNum = 1))
val second = USBIPDevice(CtapAuthenticator(), USBIPDeviceConfig(busId = "1-2", devNum = 2))
server.addDevice(first)
server.addDevice(second)
server.start(scope)
// usbip list -r <server-ip>
// usbip attach -r <server-ip> -b 1-1

server.removeDevice("1-1") // Disconnect the host and cancel its ongoing CTAP operations.
server.addDevice(first)    // Reconnect the same authenticator, preserving credentials.
server.stop()
```

`USBIPServer` owns the listener and exported devices. `start` returns after binding.
`devices` lists the exported devices. Each device can be imported by one host at a time;
unknown or busy devices return an import error. Removing one device leaves the others connected.

`USBIPDevice` holds a `CtapAuthenticator` and its USB identity/descriptors. It has no server
lifecycle methods. Every import starts a fresh HID transport; closing or removing the
connection cancels its operations and releases the HID worker threads. The authenticator
and its credential store survive removal when the caller retains the device.

`USBIPDeviceConfig` contains USB identity and descriptor settings. Host/port belong to
`USBIPServer`. The server rejects duplicate bus IDs and bus/device number pairs.

The `unifidokey-usbip` CLI serves a single device using the same server API.
Protocol details: https://docs.kernel.org/usb/usbip_protocol.html
