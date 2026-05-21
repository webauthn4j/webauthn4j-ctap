package com.webauthn4j.ctap.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory

/**
 * Bridges a [CtapAuthenticator] to USB-IP protocol, making it appear
 * as a physical USB FIDO2 security key over TCP/IP.
 *
 * Usage:
 * ```
 * val bridge = USBIPBridge(ctapAuthenticator)
 * bridge.start(coroutineScope)
 * // ... Windows/Linux clients can now attach via usbip
 * bridge.stop()
 * ```
 *
 * The bridge creates a TCP server on port 3240 (configurable) and implements
 * the USB-IP protocol to expose the virtual FIDO2 device. Clients like
 * usbipd-win can attach to this device and use it as if it were a physical
 * USB security key.
 */
class USBIPBridge(
    ctapAuthenticator: CtapAuthenticator,
    private val config: USBIPDeviceConfig = USBIPDeviceConfig()
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(USBIPBridge::class.java)
    private val hidTransport = HIDTransport(ctapAuthenticator)

    private val controlHandler = ControlRequestHandler(config)
    private val interruptHandler = InterruptEndpointHandler(hidTransport)

    private var serverJob: Job? = null
    private var server: USBIPServer? = null

    /**
     * Starts the USB-IP server and begins accepting connections.
     *
     * @param scope Coroutine scope for the server lifecycle
     */
    suspend fun start(scope: CoroutineScope) {
        logger.info("Starting USB-IP bridge")
        logger.info("Device: {}", config.deviceName)
        logger.info("VID:PID = 0x{}:0x{}",
            Integer.toHexString(config.vendorId),
            Integer.toHexString(config.productId))
        logger.info("Server address: {}:{}", config.host, config.port)
        logger.info("Bus ID: {}", config.busId)

        server = USBIPServer(config) { urb ->
            handleURB(urb)
        }

        serverJob = scope.launch(Dispatchers.IO) {
            server?.start(this)
        }

        logger.info("USB-IP server started successfully")
    }

    /**
     * Stops the USB-IP server and closes all connections.
     */
    suspend fun stop() {
        logger.info("Stopping USB-IP bridge")
        server?.stop()
        serverJob?.cancelAndJoin()
        serverJob = null
        server = null
        interruptHandler.clearPendingResponses()
        logger.info("USB-IP bridge stopped")
    }

    override fun close() {
        runBlocking { stop() }
    }

    /**
     * Routes URBs to appropriate handlers based on endpoint.
     */
    private suspend fun handleURB(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        return when (urb.ep) {
            USBIPProtocol.EP0_ADDRESS -> {
                // Control endpoint
                controlHandler.handle(urb)
            }
            USBIPProtocol.EP_INTERRUPT_OUT -> {
                // Interrupt OUT: host → device
                interruptHandler.handleOut(urb)
            }
            USBIPProtocol.EP_INTERRUPT_IN -> {
                // Interrupt IN: device → host
                interruptHandler.handleIn(urb)
            }
            else -> {
                logger.warn("URB for unknown endpoint: 0x{}", Integer.toHexString(urb.ep))
                createErrorResult(urb, USBIPProtocol.STATUS_EPIPE)
            }
        }
    }

    /**
     * Creates an error result for unsupported endpoints.
     */
    private fun createErrorResult(urb: USBIPProtocol.URBSubmit, status: Int): USBIPProtocol.URBResult {
        return USBIPProtocol.URBResult(
            seqnum = urb.seqnum,
            devid = urb.devid,
            direction = urb.direction,
            ep = urb.ep,
            status = status,
            actualLength = 0,
            startFrame = 0,
            numberOfPackets = 0,
            errorCount = 0,
            data = ByteArray(0)
        )
    }
}
