package com.webauthn4j.ctap.authenticator.transport.usbip.usb

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitRequest
import kotlinx.coroutines.channels.Channel
import org.slf4j.LoggerFactory

/**
 * Handles HID interrupt endpoint transfers (IN and OUT).
 *
 * For Interrupt IN, [handleIn] suspends until response data becomes available,
 * matching real USB behavior where NAK is handled transparently by the
 * host controller at the hardware level.
 */
class InterruptEndpointHandler(
    private val hidTransport: HIDTransport
) {
    private val logger = LoggerFactory.getLogger(InterruptEndpointHandler::class.java)

    private val responseChannel = Channel<ByteArray>(Channel.UNLIMITED)

    /**
     * Handles Interrupt OUT transfer (host -> device).
     * Receives 64-byte HID reports and passes them to HIDTransport.
     */
    suspend fun handleOut(request: SubmitRequest): SubmitResponse {
        logger.debug("Interrupt OUT: {} bytes", request.data.size)

        if (request.data.isEmpty()) {
            logger.warn("Interrupt OUT with no data")
            return SubmitResponse.success(request, ByteArray(0))
        }

        hidTransport.onHIDDataReceived(request.data) { responseBytes ->
            responseChannel.trySend(responseBytes)
            logger.debug("Queued response: {} bytes", responseBytes.size)
        }

        return SubmitResponse.success(request, ByteArray(0), actualLength = request.data.size)
    }

    /**
     * Handles Interrupt IN transfer (device -> host).
     * Suspends until response data is available.
     * Cancellation via CMD_UNLINK is handled by cancelling the calling coroutine.
     */
    suspend fun handleIn(request: SubmitRequest): SubmitResponse {
        logger.trace("Interrupt IN: waiting for data (seqnum={})", request.seqnum)
        val data = responseChannel.receive()
        logger.debug("Interrupt IN: returning {} bytes (seqnum={})", data.size, request.seqnum)
        return SubmitResponse.success(request, data)
    }

    fun close() {
        responseChannel.close()
    }
}
