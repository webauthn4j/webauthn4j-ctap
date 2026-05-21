# WebAuthn4J UHID Sample Application

Sample application demonstrating how to create a virtual FIDO2 security key on Linux using the UHID bridge.

## What This Does

This application creates a virtual FIDO2/WebAuthn security key that appears to the operating system as a physical USB device. The virtual device can be used with:

- Web browsers (Chrome, Firefox, Edge, etc.) for WebAuthn authentication
- Command-line tools like `fido2-token`
- Any FIDO2/CTAP2 compatible client application

## Quick Start

### Prerequisites

1. Linux system with UHID support (kernel 3.6+)
2. Java 17 or later
3. Root access or proper udev configuration

### Run the Sample

```bash
# From the project root directory
sudo ./gradlew :webauthn4j-ctap-uhid-sample:run
```

You should see output like:

```
=================================================
WebAuthn4J UHID Virtual FIDO2 Device Sample
=================================================

✓ Virtual FIDO2 device is now running!
  Device name: WebAuthn4J Virtual FIDO2 Key
  VID:PID: 0x1050:0x0402

The device should now be visible to:
  - Web browsers (Chrome, Firefox, etc.)
  - fido2-token command (libfido2)
  - Other FIDO2/WebAuthn clients

Press Ctrl+C to stop
```

### Verify the Device

In another terminal:

```bash
# List HID devices
ls -la /dev/hidraw*

# Check device information
cat /sys/class/hidraw/hidraw1/device/uevent

# View kernel messages
dmesg | tail

# Test FIDO2 communication (requires root)
sudo python3 << 'EOF'
import os
fd = os.open('/dev/hidraw1', os.O_RDWR)
# Send CTAPHID_INIT
packet = b'\xff\xff\xff\xff\x86\x00\x08' + bytes(range(1,9)) + bytes(49)
os.write(fd, packet)
import time; time.sleep(0.5)
response = os.read(fd, 64)
print(f"Response: {response.hex()}")
os.close(fd)
EOF
```

## How It Works

The sample application:

1. Creates a `CtapAuthenticator` instance (in-memory FIDO2 authenticator)
2. Configures a `UHIDDeviceConfig` with device metadata
3. Initializes a `UHIDBridge` to connect the authenticator to UHID
4. Starts the bridge, which:
   - Opens `/dev/uhid`
   - Creates the virtual HID device via `UHID_CREATE2` event
   - Starts an event loop to handle HID communication
5. Translates HID packets ↔ CTAP commands

```
Browser → /dev/hidraw1 → Kernel HID → /dev/uhid → UHIDBridge → CtapAuthenticator
```

## Code Overview

```kotlin
// Create authenticator
val authenticator = CtapAuthenticator()

// Configure virtual device
val config = UHIDDeviceConfig(
    deviceName = "WebAuthn4J Virtual FIDO2 Key",
    physicalAddress = "webauthn4j/uhid/sample",
    uniqueId = "webauthn4j-sample-001",
    vendorId = 0x1050,  // Yubico VID (for example)
    productId = 0x0402,
    version = 0x0100
)

// Create and start bridge
val bridge = UHIDBridge(authenticator, config)
val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
bridge.start(scope)

// Graceful shutdown on Ctrl+C
Runtime.getRuntime().addShutdownHook(
    Thread { runBlocking { bridge.stop() } }
)
```

## Permissions

### Option 1: Run with sudo (easiest for testing)

```bash
sudo ./gradlew :webauthn4j-ctap-uhid-sample:run
```

### Option 2: Configure udev rules (for development)

1. Add your user to the `input` group:
   ```bash
   sudo usermod -a -G input $USER
   ```

2. Create `/etc/udev/rules.d/99-uhid.rules`:
   ```
   KERNEL=="uhid", GROUP="input", MODE="0660"
   ```

3. Reload udev and log out/in:
   ```bash
   sudo udevadm control --reload-rules
   sudo udevadm trigger
   # Log out and back in for group changes to take effect
   ```

4. Run without sudo:
   ```bash
   ./gradlew :webauthn4j-ctap-uhid-sample:run
   ```

## Testing with a Browser

1. Start the sample application
2. Open Chrome/Firefox
3. Navigate to a WebAuthn demo site:
   - https://webauthn.io
   - https://webauthn.me
4. Try to register a new credential
5. The browser should detect the virtual security key

**Note**: The in-memory authenticator does not persist credentials across restarts.

## Customization

Edit `Main.kt` to customize:

```kotlin
// Change device name and IDs
val config = UHIDDeviceConfig(
    deviceName = "My Custom FIDO2 Key",
    vendorId = 0x1234,
    productId = 0x5678,
    // ...
)

// Use a different authenticator implementation
val authenticator = CtapAuthenticator()
// Configure authenticator settings, add extensions, etc.
```

## Building a Standalone Distribution

```bash
# Build distribution
./gradlew :webauthn4j-ctap-uhid-sample:distTar

# Extract and run
cd webauthn4j-ctap-uhid-sample/build/distributions
tar -xzf webauthn4j-ctap-uhid-sample-0.2.0-SNAPSHOT.tar.gz
cd webauthn4j-ctap-uhid-sample-0.2.0-SNAPSHOT/bin

# Run the script
sudo ./webauthn4j-ctap-uhid-sample
```

## Troubleshooting

### "ERROR: /dev/uhid does not exist"

Your kernel doesn't have UHID support. Check:
```bash
uname -r  # Should be 3.6 or later
modinfo uhid
```

### "ERROR: No read/write permission on /dev/uhid"

Run with sudo or configure udev rules (see Permissions section).

### Device appears but browser doesn't detect it

1. Check device is visible: `ls -la /dev/hidraw*`
2. Check kernel messages: `dmesg | tail`
3. Verify HID report descriptor: See browser console for errors
4. Try restarting the browser

### "Invalid argument" error during startup

This indicates a problem with the UHID event structure. Ensure you're using the latest version of the webauthn4j-ctap-uhid module.

## Logs

Logs are written to:
- Console (stdout)
- `~/logs/uhid-sample-*.log` (if using `tee`)

Adjust log levels in `src/main/resources/logback.xml`:

```xml
<!-- More verbose UHID logging -->
<logger name="com.webauthn4j.ctap.uhid" level="TRACE" />
```

## Next Steps

- Integrate with a persistent credential store
- Add support for PIN/biometric authentication
- Implement additional CTAP2 extensions
- Create a systemd service for background operation
- Test with various WebAuthn scenarios

## See Also

- [UHID Module README](../webauthn4j-ctap-uhid/README.md)
- [WebAuthn4J Documentation](https://github.com/webauthn4j/webauthn4j)
- [FIDO2 Specification](https://fidoalliance.org/specifications/)
