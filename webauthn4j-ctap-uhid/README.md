# WebAuthn4J CTAP UHID Bridge

Linux UHID (User-space HID) bridge for creating virtual FIDO2 security keys.

## Overview

This module allows you to expose a `CtapAuthenticator` instance as a virtual USB HID device on Linux using the UHID subsystem. The virtual device appears to the operating system as a physical FIDO2/WebAuthn security key and can be used with browsers, command-line tools, and other FIDO2 clients.

## Features

- ✅ Creates virtual FIDO2 HID devices via Linux UHID
- ✅ Full CTAP2 protocol support through `CtapAuthenticator`
- ✅ Appears as a standard USB HID device to applications
- ✅ Compatible with browsers (Chrome, Firefox, etc.)
- ✅ Compatible with FIDO2 command-line tools (e.g., `fido2-token`)
- ✅ Configurable device metadata (VID, PID, name, etc.)

## Requirements

- **Linux kernel 3.6+** with UHID support
- **Java 17+**
- **Read/write permissions** on `/dev/uhid`

## Permissions Setup

The UHID device (`/dev/uhid`) typically requires root access. You have two options:

### Option 1: Run with sudo (Quick test)

```bash
sudo ./gradlew :webauthn4j-ctap-uhid-sample:run
```

### Option 2: Configure udev rules (Recommended for development)

1. Add your user to the `input` group:
   ```bash
   sudo usermod -a -G input $USER
   ```

2. Create `/etc/udev/rules.d/99-uhid.rules`:
   ```
   KERNEL=="uhid", GROUP="input", MODE="0660"
   ```

3. Reload udev rules and log out/in:
   ```bash
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   ```

## Usage

### Basic Example

```kotlin
import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.uhid.UHIDBridge
import com.webauthn4j.ctap.uhid.UHIDDeviceConfig
import kotlinx.coroutines.*

fun main() = runBlocking {
    // Create a CTAP authenticator
    val authenticator = CtapAuthenticator()

    // Configure the virtual device
    val config = UHIDDeviceConfig(
        deviceName = "My Virtual FIDO2 Key",
        vendorId = 0x1234,
        productId = 0xF1D0,
        version = 0x0100
    )

    // Create and start the UHID bridge
    val bridge = UHIDBridge(authenticator, config)
    val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    bridge.start(scope)
    println("Virtual FIDO2 device is running!")

    // Keep running...
    delay(Long.MAX_VALUE)
}
```

### Configuration Options

The `UHIDDeviceConfig` class allows you to customize the virtual device:

```kotlin
data class UHIDDeviceConfig(
    val deviceName: String = "WebAuthn4J Virtual FIDO2 Key",
    val vendorId: Int = 0x1234,
    val productId: Int = 0xF1D0,
    val version: Int = 0x0100,
    val devicePath: String = "/dev/uhid",
    val physicalAddress: String = "",
    val uniqueId: String = ""
)
```

## Verifying the Device

After starting the bridge, verify the device was created:

```bash
# List HID raw devices
ls -la /dev/hidraw*

# Check device details
cat /sys/class/hidraw/hidraw1/device/uevent

# View kernel messages
dmesg | tail

# Test with FIDO2 tools (if available)
fido2-token -L
```

## Architecture

```
┌─────────────────────────┐
│  FIDO2 Client           │
│  (Browser, fido2-token) │
└───────────┬─────────────┘
            │
            │ HID Protocol
            │
┌───────────▼─────────────┐
│  Linux Kernel           │
│  (HID Subsystem)        │
└───────────┬─────────────┘
            │
            │ /dev/uhid
            │
┌───────────▼─────────────┐
│  UHIDBridge             │
│  ┌─────────────────┐    │
│  │ UHIDConnection  │    │
│  └────────┬────────┘    │
│           │             │
│  ┌────────▼────────┐    │
│  │  HIDTransport   │    │
│  └────────┬────────┘    │
│           │             │
│  ┌────────▼────────┐    │
│  │ CtapAuthenticator│   │
│  └─────────────────┘    │
└─────────────────────────┘
```

## Implementation Details

### UHID Event Structure

The bridge communicates with the kernel using fixed-size `uhid_event` structures (4380 bytes). Key event types:

- **UHID_CREATE2**: Creates the virtual HID device
- **UHID_DESTROY**: Removes the virtual device
- **UHID_INPUT2**: Sends HID reports to the host (device → host)
- **UHID_OUTPUT**: Receives HID reports from the host (host → device)
- **UHID_START/STOP**: Device lifecycle events

### HID Report Descriptor

The FIDO HID report descriptor defines a 64-byte bidirectional interface using the FIDO Alliance Usage Page (0xF1D0):

```
Usage Page: FIDO Alliance (0xF1D0)
Usage: U2F HID Authenticator Device
Collection: Application
  Input Report: 64 bytes
  Output Report: 64 bytes
```

## Sample Application

A complete sample application is available in the `webauthn4j-ctap-uhid-sample` module:

```bash
# Build
./gradlew :webauthn4j-ctap-uhid-sample:build

# Run
sudo ./gradlew :webauthn4j-ctap-uhid-sample:run

# Or use the distribution
cd webauthn4j-ctap-uhid-sample/build/distributions
tar -xzf webauthn4j-ctap-uhid-sample-*.tar.gz
cd webauthn4j-ctap-uhid-sample-*/bin
sudo ./webauthn4j-ctap-uhid-sample
```

## Troubleshooting

### Permission denied on /dev/uhid

**Error**: `java.io.IOException: Permission denied`

**Solution**: Run with sudo or configure udev rules (see Permissions Setup above)

### Device not appearing

1. Check kernel messages: `dmesg | tail -20`
2. Verify UHID module is loaded: `lsmod | grep uhid`
3. Check for HID errors in kernel log

### Invalid argument error

**Error**: `java.io.IOException: Invalid argument`

**Cause**: Incorrect uhid_event structure layout

**Solution**: Ensure you're using the latest version with corrected field offsets

## Testing

Run the unit tests:

```bash
./gradlew :webauthn4j-ctap-uhid:test
```

## Limitations

- **Linux only**: UHID is a Linux-specific interface
- **Root required**: Standard systems require root or udev configuration
- **No device removal notification**: Applications may not detect device disconnection immediately
- **Single client**: While multiple clients can enumerate the device, CTAP2 protocol requires exclusive access during transactions

## License

Apache 2.0 License (same as webauthn4j-ctap)

## References

- [Linux UHID Documentation](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [FIDO CTAPHID Protocol](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#usb)
- [HID Usage Tables](https://usb.org/sites/default/files/hut1_4.pdf)
- [FIDO Alliance Usage Page](https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html#hid-report-descriptor-and-device-discovery)
