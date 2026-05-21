# webauthn4j-ctap-authenticator-uhid

Library that exposes a `CtapAuthenticator` as a virtual USB HID FIDO2 device via the Linux UHID subsystem.

## Requirements

- Linux kernel 3.6+ with UHID support
- Java 17+
- Read/write access to `/dev/uhid`

## Usage

```kotlin
val authenticator = CtapAuthenticator()
val device = UHIDDevice(authenticator)
val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

device.start(scope)
// The device is now visible as /dev/hidrawN
```

## Key Classes

| Class | Description |
|---|---|
| `UHIDDevice` | Lifecycle management and UHID event loop |
| `UHIDConnection` | Low-level `/dev/uhid` I/O |
| `UHIDDeviceConfig` | Device metadata (name, VID, PID, etc.) |
