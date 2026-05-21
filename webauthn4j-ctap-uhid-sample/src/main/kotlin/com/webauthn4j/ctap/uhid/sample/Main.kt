package com.webauthn4j.ctap.uhid.sample

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.uhid.UHIDBridge
import com.webauthn4j.ctap.uhid.UHIDDeviceConfig
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import kotlin.system.exitProcess

/**
 * Sample application that creates a virtual FIDO2 security key using UHID on Linux.
 *
 * This program:
 * 1. Creates a CtapAuthenticator instance (in-memory FIDO2 authenticator)
 * 2. Bridges it to /dev/uhid to appear as a physical USB device
 * 3. Runs until interrupted (Ctrl+C)
 *
 * Prerequisites:
 * - Linux with UHID support (kernel 3.6+)
 * - Read/write permissions on /dev/uhid (usually requires root or udev rules)
 *
 * Usage:
 *   sudo ./gradlew :webauthn4j-ctap-uhid-sample:run
 *
 * The virtual device will appear as "WebAuthn4J Virtual FIDO2 Key" and can be
 * used with browsers and other FIDO2 clients.
 */
fun main() = runBlocking {
    val logger = LoggerFactory.getLogger("UHIDSample")

    logger.info("=================================================")
    logger.info("WebAuthn4J UHID Virtual FIDO2 Device Sample")
    logger.info("=================================================")
    logger.info("")

    // Check if we have access to /dev/uhid
    val uhidPath = "/dev/uhid"
    val uhidFile = java.io.File(uhidPath)
    if (!uhidFile.exists()) {
        logger.error("ERROR: $uhidPath does not exist")
        logger.error("Make sure your kernel has UHID support (Linux 3.6+)")
        exitProcess(1)
    }
    if (!uhidFile.canRead() || !uhidFile.canWrite()) {
        logger.error("ERROR: No read/write permission on $uhidPath")
        logger.error("Try running with sudo or configure udev rules:")
        logger.error("  sudo usermod -a -G input \$USER")
        logger.error("  # Then create /etc/udev/rules.d/99-uhid.rules:")
        logger.error("  KERNEL==\"uhid\", GROUP=\"input\", MODE=\"0660\"")
        exitProcess(1)
    }

    // Create the CTAP authenticator (in-memory FIDO2 authenticator)
    val authenticator = CtapAuthenticator()
    logger.info("Created CTAP authenticator")

    // Configure the virtual device
    val config = UHIDDeviceConfig(
        deviceName = "WebAuthn4J Virtual FIDO2 Key",
        physicalAddress = "webauthn4j/uhid/sample",
        uniqueId = "webauthn4j-sample-001",
        vendorId = 0x1050,  // Yubico VID (example)
        productId = 0x0402,  // Example PID
        version = 0x0100
    )

    // Create the UHID bridge
    val bridge = UHIDBridge(authenticator, config)
    logger.info("Created UHID bridge")

    // Set up shutdown hook for graceful termination
    val shutdownHook = Thread {
        runBlocking {
            logger.info("Shutting down...")
            bridge.stop()
            logger.info("Virtual device removed")
        }
    }
    Runtime.getRuntime().addShutdownHook(shutdownHook)

    try {
        // Start the bridge in a supervised scope
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        bridge.start(scope)

        logger.info("")
        logger.info("✓ Virtual FIDO2 device is now running!")
        logger.info("  Device name: ${config.deviceName}")
        logger.info("  VID:PID: ${String.format("0x%04X:0x%04X", config.vendorId, config.productId)}")
        logger.info("")
        logger.info("The device should now be visible to:")
        logger.info("  - Web browsers (Chrome, Firefox, etc.)")
        logger.info("  - fido2-token command (libfido2)")
        logger.info("  - Other FIDO2/WebAuthn clients")
        logger.info("")
        logger.info("Try: lsusb | grep -i fido")
        logger.info("     ls -la /dev/hidraw*")
        logger.info("")
        logger.info("Press Ctrl+C to stop")
        logger.info("")

        // Keep running until interrupted
        delay(Long.MAX_VALUE)
    } catch (e: CancellationException) {
        logger.info("Application cancelled")
    } catch (e: Exception) {
        logger.error("Error running UHID bridge", e)
        exitProcess(1)
    }
}
