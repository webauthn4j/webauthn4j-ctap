package com.webauthn4j.ctap.usbip

import com.webauthn4j.ctap.authenticator.transport.hid.HIDTransport
import kotlinx.coroutines.runBlocking
import org.slf4j.LoggerFactory
import java.util.concurrent.LinkedBlockingQueue

/**
 * Handles HID interrupt endpoint transfers (IN and OUT).
 * Integrates with HIDTransport for CTAP protocol processing.
 */
class InterruptEndpointHandler(
    private val hidTransport: HIDTransport
) {
    private val logger = LoggerFactory.getLogger(InterruptEndpointHandler::class.java)

    // Queue for HID response packets waiting to be sent via Interrupt IN
    private val responseQueue = LinkedBlockingQueue<ByteArray>()

    /**
     * Handles Interrupt OUT transfer (host → device).
     * Receives 64-byte HID reports and passes them to HIDTransport.
     */
    suspend fun handleOut(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        logger.debug("Interrupt OUT: {} bytes", urb.data.size)

        if (urb.data.isEmpty()) {
            logger.warn("Interrupt OUT with no data")
            return createSuccessResult(urb, ByteArray(0))
        }

        // Process HID packet through transport
        hidTransport.onHIDDataReceived(urb.data) { responseBytes ->
            // Queue response for next Interrupt IN URB
            responseQueue.offer(responseBytes)
            logger.debug("Queued response: {} bytes (queue size: {})", responseBytes.size, responseQueue.size)
        }

        // Acknowledge OUT transfer immediately
        return createSuccessResult(urb, ByteArray(0))
    }

    /**
     * Handles Interrupt IN transfer (device → host).
     * Returns queued HID report or NAK if no data available.
     */
    fun handleIn(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        // Check if we have response data ready
        val responseData = responseQueue.poll()

        return if (responseData != null) {
            logger.debug("Interrupt IN: returning {} bytes (queue size: {})",
                responseData.size, responseQueue.size)
            createSuccessResult(urb, responseData)
        } else {
            logger.trace("Interrupt IN: no data ready, returning NAK")
            createNakResult(urb)
        }
    }

    /**
     * Creates a successful URB result.
     */
    private fun createSuccessResult(urb: USBIPProtocol.URBSubmit, data: ByteArray): USBIPProtocol.URBResult {
        return USBIPProtocol.URBResult(
            seqnum = urb.seqnum,
            devid = urb.devid,
            direction = urb.direction,
            ep = urb.ep,
            status = USBIPProtocol.STATUS_SUCCESS,
            actualLength = data.size,
            startFrame = 0,
            numberOfPackets = 0,
            errorCount = 0,
            data = data
        )
    }

    /**
     * Creates a NAK result (no data available).
     */
    private fun createNakResult(urb: USBIPProtocol.URBSubmit): USBIPProtocol.URBResult {
        return USBIPProtocol.URBResult(
            seqnum = urb.seqnum,
            devid = urb.devid,
            direction = urb.direction,
            ep = urb.ep,
            status = USBIPProtocol.STATUS_EAGAIN,
            actualLength = 0,
            startFrame = 0,
            numberOfPackets = 0,
            errorCount = 0,
            data = ByteArray(0)
        )
    }

    /**
     * Clears any pending responses (useful for cleanup).
     */
    fun clearPendingResponses() {
        val cleared = responseQueue.size
        responseQueue.clear()
        if (cleared > 0) {
            logger.debug("Cleared {} pending responses", cleared)
        }
    }
}
