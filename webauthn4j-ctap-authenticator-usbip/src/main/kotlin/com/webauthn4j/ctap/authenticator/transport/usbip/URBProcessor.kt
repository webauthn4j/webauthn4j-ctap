package com.webauthn4j.ctap.authenticator.transport.usbip

import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.SubmitResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.TransferDirection
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.UnlinkRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.UnlinkResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.UrbRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.data.urb.UrbStatus
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.ControlEndpoint
import com.webauthn4j.ctap.authenticator.transport.usbip.endpoint.InterruptEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import org.slf4j.LoggerFactory

/**
 * Processes URBs on an established [USBIPSession] using a select-based event loop.
 *
 * An IO coroutine reads URBs from the TCP stream and feeds them into a queue.
 * The main loop uses [select] to monitor both the URB queue and the HID response
 * channel simultaneously, ensuring Interrupt IN requests are fulfilled in FIFO
 * order without blocking URB reading.
 *
 * UNLINK requests correctly remove pending Interrupt IN entries, preventing
 * stale responses and ensuring accurate status reporting.
 */
class URBProcessor(private val session: USBIPSession) {

    private val logger = LoggerFactory.getLogger(URBProcessor::class.java)

    suspend fun process() {
        coroutineScope {
            val urbQueue = Channel<UrbRequest>(Channel.UNLIMITED)
            launch(Dispatchers.IO) { readURBs(urbQueue) }
            launch { processURBs(urbQueue) }
        }
    }

    private suspend fun readURBs(urbQueue: Channel<UrbRequest>) {
        try {
            while (currentCoroutineContext().isActive) {
                urbQueue.send(UrbRequest.parse(session.readChannel))
            }
        } finally {
            urbQueue.close()
        }
    }

    private suspend fun processURBs(urbQueue: Channel<UrbRequest>) {
        val pendingIns = LinkedHashMap<Int, SubmitRequest>()

        while (true) {
            select {
                urbQueue.onReceive { urb ->
                    when (urb) {
                        is SubmitRequest -> {
                            if (urb.transferBufferLength > MAX_TRANSFER_BUFFER_LENGTH) {
                                logger.warn("Transfer size too large: {}", urb.transferBufferLength)
                                session.writeResponse(SubmitResponse.error(urb, UrbStatus.EINVAL).toBytes())
                                return@onReceive
                            }
                            logger.debug("CMD_SUBMIT: ep={}, dir={}, len={}", urb.ep, urb.direction, urb.transferBufferLength)
                            if (urb.direction == TransferDirection.IN && urb.ep == InterruptEndpoint.EP_NUMBER) {
                                pendingIns[urb.seqnum] = urb
                            } else {
                                submitAndRespond(urb)
                            }
                        }
                        is UnlinkRequest -> {
                            logger.debug("CMD_UNLINK: seqnum={}, unlinkSeqnum={}", urb.seqnum, urb.unlinkSeqnum)
                            val wasPending = pendingIns.remove(urb.unlinkSeqnum) != null
                            val status = if (wasPending) UrbStatus.ECONNRESET else UrbStatus.SUCCESS
                            session.writeResponse(UnlinkResponse(seqnum = urb.seqnum, status = status).toBytes())
                        }
                    }
                }
                if (pendingIns.isNotEmpty()) {
                    session.interruptEndpoint.responses.onReceive { data ->
                        val entry = pendingIns.entries.first()
                        pendingIns.remove(entry.key)
                        logger.debug("Interrupt IN: returning {} bytes (seqnum={})", data.size, entry.key)
                        session.writeResponse(SubmitResponse.ok(entry.value, data).toBytes())
                    }
                }
            }
        }
    }

    private suspend fun submitAndRespond(request: SubmitRequest) {
        try {
            val response = when (request.ep) {
                ControlEndpoint.EP_NUMBER -> session.controlEndpoint.process(request)
                InterruptEndpoint.EP_NUMBER -> session.interruptEndpoint.processOut(request)
                else -> {
                    logger.warn("Unknown endpoint: 0x{}", Integer.toHexString(request.ep))
                    SubmitResponse.error(request, UrbStatus.EPIPE)
                }
            }
            session.writeResponse(response.toBytes())
        } catch (e: Exception) {
            logger.error("Error processing submit request", e)
            session.writeResponse(SubmitResponse.error(request, UrbStatus.EINVAL).toBytes())
        }
    }

    companion object {
        private const val MAX_TRANSFER_BUFFER_LENGTH = 4096
    }
}
