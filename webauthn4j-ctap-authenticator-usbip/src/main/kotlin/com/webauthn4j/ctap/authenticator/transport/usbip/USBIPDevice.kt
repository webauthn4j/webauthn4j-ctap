package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.CtapAuthenticator
import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceInfo
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.USBSpeed
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

        hidTransport.start(scope)

        val deviceInfo = createDeviceInfo()
        val sm = SelectorManager(Dispatchers.IO)
        selectorManager = sm

        serverJob = scope.launch(Dispatchers.IO) {
            aSocket(sm).tcp().bind(config.host, config.port).use { serverSocket ->
                logger.info("USB-IP server listening on {}:{}", config.host, config.port)

                while (isActive) {
                    val clientSocket = serverSocket.accept()
                    logger.info("Client connected from {}", clientSocket.remoteAddress)

                    launch {
                        try {
                            clientSocket.use { socket ->
                                USBIPSession.create(socket, deviceInfo, config, hidTransport).use { session ->
                                    URBProcessor(session).process()
                                }
                            }
                        } catch (_: java.io.IOException) {
                            logger.debug("Client disconnected: {}", clientSocket.remoteAddress)
                        } catch (e: Exception) {
                            logger.error("Session error", e)
                        }
                    }
                }
            }
        }
    }

    suspend fun stop() {
        logger.info("Stopping USB-IP server")
        serverJob?.cancelAndJoin()
        serverJob = null
        selectorManager?.close()
        selectorManager = null
        hidTransport.close()
        logger.info("USB-IP server stopped")
    }

    override fun close() {
        runBlocking { stop() }
    }

    private fun createDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            path = "/sys/devices/virtual/usbip/${config.busId}",
            busid = config.busId,
            busnum = config.busNum,
            devnum = config.devNum,
            speed = USBSpeed.FULL,
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
}
