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
 * Drives URB processing on an established [USBIPSession].
 *
 * An IO coroutine reads URBs from the TCP stream into a queue. The main
 * coroutine uses [select] to concurrently monitor that queue and the HID
 * response channel, dispatching each URB to the appropriate endpoint and
 * fulfilling pending Interrupt IN requests in FIFO order.
 */
class URBProcessor(private val session: USBIPSession) {

    private val logger = LoggerFactory.getLogger(URBProcessor::class.java)
    private val pendingIns = LinkedHashMap<Int, SubmitRequest>()

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
        while (true) {
            select {
                urbQueue.onReceive { urb ->
                    when (urb) {
                        is SubmitRequest -> handleSubmit(urb)
                        is UnlinkRequest -> handleUnlink(urb)
                    }
                }
                if (pendingIns.isNotEmpty()) {
                    session.interruptEndpoint.responses.onReceive { data ->
                        completeInterruptIn(data)
                    }
                }
            }
        }
    }

    private suspend fun handleSubmit(request: SubmitRequest) {
        if (request.transferBufferLength > MAX_TRANSFER_BUFFER_LENGTH) {
            logger.warn("Transfer size too large: {}", request.transferBufferLength)
            session.writeResponse(SubmitResponse.error(request, UrbStatus.EINVAL).toBytes())
            return
        }
        logger.debug("CMD_SUBMIT: ep={}, dir={}, len={}", request.ep, request.direction, request.transferBufferLength)
        if (request.direction == TransferDirection.IN && request.ep == InterruptEndpoint.EP_NUMBER) {
            pendingIns[request.seqnum] = request
        } else {
            val response = try {
                dispatchSubmit(request)
            } catch (e: Exception) {
                handleEndpointFailure(request, e)
            }
            session.writeResponse(response.toBytes())
        }
    }

    private suspend fun handleUnlink(request: UnlinkRequest) {
        logger.debug("CMD_UNLINK: seqnum={}, unlinkSeqnum={}", request.seqnum, request.unlinkSeqnum)
        val wasPending = pendingIns.remove(request.unlinkSeqnum) != null
        val status = if (wasPending) UrbStatus.ECONNRESET else UrbStatus.SUCCESS
        session.writeResponse(UnlinkResponse(seqnum = request.seqnum, status = status).toBytes())
    }

    private suspend fun completeInterruptIn(data: ByteArray) {
        val entry = pendingIns.entries.first()
        pendingIns.remove(entry.key)
        logger.debug("Interrupt IN: returning {} bytes (seqnum={})", data.size, entry.key)
        session.writeResponse(SubmitResponse.ok(entry.value, data).toBytes())
    }

    private suspend fun dispatchSubmit(request: SubmitRequest): SubmitResponse {
        return when (request.ep) {
            ControlEndpoint.EP_NUMBER -> session.controlEndpoint.process(request)
            InterruptEndpoint.EP_NUMBER -> session.interruptEndpoint.process(request)
            else -> throw IllegalArgumentException("Unknown endpoint: 0x${Integer.toHexString(request.ep)}")
        }
    }

    private fun handleEndpointFailure(request: SubmitRequest, e: Exception): SubmitResponse {
        logger.error("Error processing submit request", e)
        return SubmitResponse.error(request, UrbStatus.EINVAL)
    }

    companion object {
        private const val MAX_TRANSFER_BUFFER_LENGTH = 4096
    }
}
