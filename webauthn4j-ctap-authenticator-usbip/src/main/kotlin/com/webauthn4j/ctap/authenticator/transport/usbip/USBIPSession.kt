package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceInfo
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceListRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.DeviceListResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.HandshakeRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.ImportRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake.ImportResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.ControlEndpoint
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.InterruptEndpoint
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import org.slf4j.LoggerFactory

/**
 * An established USB-IP client connection with its per-session endpoints.
 *
 * [create] opens TCP channels, negotiates the USB-IP handshake, and returns
 * a ready-to-use session. [URBProcessor] then drives endpoint I/O on it.
 */
class USBIPSession private constructor(
    val readChannel: ByteReadChannel,
    val writeChannel: ByteWriteChannel,
    val controlEndpoint: ControlEndpoint,
    val interruptEndpoint: InterruptEndpoint
) : AutoCloseable {

    private val logger = LoggerFactory.getLogger(USBIPSession::class.java)

    companion object {
        suspend fun create(
            socket: Socket,
            deviceInfo: DeviceInfo,
            config: USBIPDeviceConfig,
            hidTransport: HIDTransport
        ): USBIPSession {
            val readChannel = socket.openReadChannel()
            val writeChannel = socket.openWriteChannel(autoFlush = true)
            val session = USBIPSession(
                readChannel = readChannel,
                writeChannel = writeChannel,
                controlEndpoint = ControlEndpoint(config),
                interruptEndpoint = InterruptEndpoint(hidTransport)
            )
            session.negotiateHandshake(deviceInfo)
            return session
        }
    }

    private suspend fun negotiateHandshake(deviceInfo: DeviceInfo) {
        while (true) {
            when (val request = HandshakeRequest.parse(readChannel)) {
                is DeviceListRequest -> {
                    logger.debug("Handling OP_REQ_DEVLIST")
                    writeResponse(DeviceListResponse(devices = listOf(deviceInfo)).toBytes())
                }
                is ImportRequest -> {
                    logger.debug("Handling OP_REQ_IMPORT: busid={}", request.busId)
                    if (request.busId != deviceInfo.busid) {
                        logger.warn("Import request for unknown busid: {}", request.busId)
                        continue
                    }
                    writeResponse(ImportResponse(device = deviceInfo).toBytes())
                    logger.info("Device attached to client")
                    return
                }
            }
        }
    }

    suspend fun writeResponse(data: ByteArray) {
        writeChannel.writeFully(data, 0, data.size)
    }

    override fun close() {
        interruptEndpoint.close()
    }
}
