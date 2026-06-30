package com.webauthn4j.ctap.authenticator.transport.usbip.endpoint

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitResponse
import kotlinx.coroutines.channels.Channel
import org.slf4j.LoggerFactory

/**
 * Bridges USB HID interrupt transfers to [HIDTransport].
 *
 * OUT transfers forward HID data to [HIDTransport]; resulting responses
 * are queued in [responses] for [URBProcessor] to pair with pending
 * Interrupt IN requests. Each instance is scoped to a single session.
 */
class InterruptEndpoint(
    private val hidTransport: HIDTransport
) {
    private val logger = LoggerFactory.getLogger(InterruptEndpoint::class.java)

    val responses = Channel<ByteArray>(Channel.UNLIMITED)

    companion object {
        const val EP_NUMBER = 1
    }

    fun process(request: SubmitRequest): SubmitResponse {
        logger.debug("Interrupt OUT: {} bytes", request.transferBuffer.size)

        if (request.transferBuffer.isEmpty()) {
            logger.warn("Interrupt OUT with no data")
            return SubmitResponse.ok(request, ByteArray(0))
        }

        hidTransport.onHIDDataReceived(request.transferBuffer) { responseBytes ->
            responses.trySend(responseBytes)
            logger.debug("Queued response: {} bytes", responseBytes.size)
        }

        return SubmitResponse.ok(request, ByteArray(0))
    }

    fun close() {
        responses.close()
    }
}
