package com.webauthn4j.ctap.usbip.sample

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.usbip.USBIPBridge
import com.webauthn4j.ctap.usbip.USBIPDeviceConfig
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory
import java.net.InetAddress
import kotlin.system.exitProcess

/**
 * Sample application that creates a virtual FIDO2 security key using USB-IP protocol.
 *
 * This program:
 * 1. Creates a CtapAuthenticator instance (in-memory FIDO2 authenticator)
 * 2. Exposes it via USB-IP protocol over TCP/IP
 * 3. Runs until interrupted (Ctrl+C)
 *
 * Prerequisites:
 * - Network connectivity
 * - Port 3240 available (or configure a different port)
 *
 * Usage:
 *   ./gradlew :webauthn4j-ctap-usbip-sample:run
 *
 * From Windows (using usbipd-win):
 *   usbip list -r <server-ip>
 *   usbip attach -r <server-ip> -b 1-1
 *
 * From Linux (using usbip client):
 *   usbip list -r <server-ip>
 *   sudo usbip attach -r <server-ip> -b 1-1
 *
 * The virtual device will appear as "WebAuthn4J Virtual FIDO2 Key" and can be
 * used with browsers, FIDO Conformance Tools, and other FIDO2 clients.
 */
fun main() = runBlocking {
    val logger = LoggerFactory.getLogger("USBIPSample")

    logger.info("=================================================")
    logger.info("WebAuthn4J USB-IP Virtual FIDO2 Device Sample")
    logger.info("=================================================")
    logger.info("")

    // Create the CTAP authenticator (in-memory FIDO2 authenticator)
    val authenticator = CtapAuthenticator()
    logger.info("Created CTAP authenticator")

    // Configure the virtual device and server
    val config = USBIPDeviceConfig(
        deviceName = "WebAuthn4J Virtual FIDO2 Key",
        vendorId = 0x1050,      // Yubico VID (example)
        productId = 0x0402,      // Example PID
        version = 0x0100,
        host = "0.0.0.0",        // Listen on all interfaces
        port = 3240,             // Standard USB-IP port
        busId = "1-1"
    )

    // Create the USB-IP bridge
    val bridge = USBIPBridge(authenticator, config)
    logger.info("Created USB-IP bridge")

    // Set up shutdown hook for graceful termination
    val shutdownHook = Thread {
        runBlocking {
            logger.info("Shutting down...")
            bridge.stop()
            logger.info("USB-IP server stopped")
        }
    }
    Runtime.getRuntime().addShutdownHook(shutdownHook)

    try {
        // Start the bridge in a supervised scope
        val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
        bridge.start(scope)

        logger.info("")
        logger.info("✓ USB-IP server is now running!")
        logger.info("  Device name: ${config.deviceName}")
        logger.info("  VID:PID: ${String.format("0x%04X:0x%04X", config.vendorId, config.productId)}")
        logger.info("  Server: ${config.host}:${config.port}")
        logger.info("  Bus ID: ${config.busId}")
        logger.info("")

        // Try to determine local IP address
        try {
            val localHost = InetAddress.getLocalHost()
            val hostAddress = localHost.hostAddress
            logger.info("Server IP address: $hostAddress")
            logger.info("")
        } catch (e: Exception) {
            // Ignore, not critical
        }

        logger.info("To attach from Windows (PowerShell):")
        logger.info("  usbip list -r <server-ip>")
        logger.info("  usbip attach -r <server-ip> -b ${config.busId}")
        logger.info("")
        logger.info("To attach from Linux:")
        logger.info("  usbip list -r <server-ip>")
        logger.info("  sudo usbip attach -r <server-ip> -b ${config.busId}")
        logger.info("")
        logger.info("After attaching, the device will appear as a USB HID device")
        logger.info("and can be used with:")
        logger.info("  - Web browsers (Chrome, Firefox, Edge, etc.)")
        logger.info("  - FIDO Conformance Tools")
        logger.info("  - fido2-token command (libfido2)")
        logger.info("  - Other FIDO2/WebAuthn clients")
        logger.info("")
        logger.info("Press Ctrl+C to stop")
        logger.info("")

        // Keep running until interrupted
        delay(Long.MAX_VALUE)
    } catch (e: CancellationException) {
        logger.info("Application cancelled")
    } catch (e: Exception) {
        logger.error("Error running USB-IP server", e)
        exitProcess(1)
    }
}
