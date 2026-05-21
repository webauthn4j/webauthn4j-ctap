package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.DeviceInfo
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.USBIPProtocol
import com.webauthn4j.ctap.authenticator.transport.usbip.server.USBIPClientHandler
import com.webauthn4j.ctap.authenticator.transport.usbip.usb.ControlRequestHandler
import com.webauthn4j.ctap.authenticator.transport.usbip.usb.InterruptEndpointHandler
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.aSocket
import kotlinx.coroutines.*
import org.slf4j.LoggerFactory

/**
 * Virtual USB FIDO2 security key exposed over USB/IP (TCP/IP).
 *
 * Wraps a [CtapAuthenticator] and serves it as a USB HID device that remote
 * machines can attach via the USB/IP protocol.
 */
class USBIPDevice(
    ctapAuthenticator: CtapAuthenticator,
    private val config: USBIPDeviceConfig = USBIPDeviceConfig()
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(USBIPDevice::class.java)
    private val hidTransport = HIDTransport(ctapAuthenticator)

    private val controlHandler = ControlRequestHandler(config)
    private val interruptHandler = InterruptEndpointHandler(hidTransport)

    private var serverJob: Job? = null
    private var selectorManager: SelectorManager? = null

    suspend fun start(scope: CoroutineScope) {
        logger.info("Starting USB-IP server")
        logger.info("Device: {}", config.deviceName)
        logger.info("VID:PID = 0x{}:0x{}",
            Integer.toHexString(config.vendorId),
            Integer.toHexString(config.productId))
        logger.info("Server address: {}:{}", config.host, config.port)
        logger.info("Bus ID: {}", config.busId)

        val deviceInfo = createDeviceInfo()
        val sm = SelectorManager(Dispatchers.IO)
        selectorManager = sm

        serverJob = scope.launch(Dispatchers.IO) {
            val serverSocket = aSocket(sm).tcp().bind(config.host, config.port)
            try {
                logger.info("USB-IP server listening on {}:{}", config.host, config.port)

                while (isActive) {
                    val clientSocket = serverSocket.accept()
                    logger.info("Client connected from {}", clientSocket.remoteAddress)

                    launch {
                        USBIPClientHandler(clientSocket, deviceInfo, this@USBIPDevice).handle()
                    }
                }
            } finally {
                serverSocket.close()
            }
        }
    }

    suspend fun stop() {
        logger.info("Stopping USB-IP server")
        serverJob?.cancelAndJoin()
        serverJob = null
        selectorManager?.close()
        selectorManager = null
        interruptHandler.close()
        logger.info("USB-IP server stopped")
    }

    override fun close() {
        runBlocking { stop() }
    }

    /**
     * Routes a URB to the appropriate handler based on endpoint and direction.
     */
    internal suspend fun handleSubmit(request: SubmitRequest): SubmitResponse {
        return when (request.ep) {
            USBIPProtocol.EP0_ADDRESS -> controlHandler.handle(request)
            EP_INTERRUPT_NUMBER -> {
                if (request.direction == USBIPProtocol.USBIP_DIR_OUT) {
                    interruptHandler.handleOut(request)
                } else {
                    interruptHandler.handleIn(request)
                }
            }
            else -> {
                logger.warn("Unknown endpoint: 0x{}", Integer.toHexString(request.ep))
                SubmitResponse.error(request, USBIPProtocol.STATUS_EPIPE)
            }
        }
    }

    private fun createDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            path = "/sys/devices/virtual/usbip/${config.busId}",
            busid = config.busId,
            busnum = config.busNum,
            devnum = config.devNum,
            speed = 3,
            idVendor = config.vendorId,
            idProduct = config.productId,
            bcdDevice = config.version,
            bDeviceClass = 0,
            bDeviceSubClass = 0,
            bDeviceProtocol = 0,
            bConfigurationValue = 1,
            bNumConfigurations = 1,
            bNumInterfaces = 1,
            interfaces = listOf(
                DeviceInfo.InterfaceInfo(
                    bInterfaceClass = 0x03,
                    bInterfaceSubClass = 0x00,
                    bInterfaceProtocol = 0x00
                )
            )
        )
    }

    companion object {
        private const val EP_INTERRUPT_NUMBER = 1
    }
}
