package com.webauthn4j.ctap.authenticator.transport.usbip.server

import com.webauthn4j.ctap.authenticator.transport.usbip.USBIPDevice
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.DeviceInfo
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.DeviceListResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.ImportRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.ImportResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.UnlinkRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.UnlinkResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitResponse
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.SubmitRequest
import com.webauthn4j.ctap.authenticator.transport.usbip.protocol.USBIPProtocol
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.slf4j.LoggerFactory
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap

/**
 * Handles a single USB-IP client connection through the protocol state machine.
 *
 * The protocol has two phases:
 * 1. Handshake phase: device list and import requests (version+opcode header format)
 * 2. URB phase: submit and unlink commands (command+seqnum header format)
 */
class USBIPClientHandler(
    private val socket: Socket,
    private val deviceInfo: DeviceInfo,
    private val device: USBIPDevice
) {
    private val logger = LoggerFactory.getLogger(USBIPClientHandler::class.java)
    private val writeMutex = Mutex()
    private val pendingInJobs = ConcurrentHashMap<Int, Job>()
    private val inRequestQueue = Channel<PendingInRequest>(Channel.UNLIMITED)

    private lateinit var readChannel: ByteReadChannel
    private lateinit var writeChannel: ByteWriteChannel

    suspend fun handle() {
        readChannel = socket.openReadChannel()
        writeChannel = socket.openWriteChannel(autoFlush = true)
        try {
            handleHandshakePhase()
            coroutineScope {
                handleSubmitPhase()
            }
        } catch (e: Exception) {
            logger.debug("Client disconnected", e)
        } finally {
            socket.close()
        }
    }

    // --- Handshake phase: version(2) + opcode(2) + status(4) ---

    private suspend fun handleHandshakePhase() {
        while (true) {
            val header = readBigEndianBuffer(8)
            val version = header.short.toInt() and 0xFFFF
            val opCode = header.short.toInt() and 0xFFFF

            logger.debug("Handshake: version=0x{}, opCode=0x{}",
                Integer.toHexString(version), Integer.toHexString(opCode))

            when (opCode) {
                USBIPProtocol.OP_REQ_DEVLIST -> handleDevlist()
                USBIPProtocol.OP_REQ_IMPORT -> {
                    if (handleImport()) return
                }
                else -> logger.warn("Unknown handshake opcode: 0x{}", Integer.toHexString(opCode))
            }
        }
    }

    private suspend fun handleDevlist() {
        logger.debug("Handling OP_REQ_DEVLIST")
        writeResponse(DeviceListResponse(listOf(deviceInfo)).toBytes())
    }

    private suspend fun handleImport(): Boolean {
        val importRequest = ImportRequest.parse(readBigEndianBuffer(32))
        logger.debug("Handling OP_REQ_IMPORT: busid={}", importRequest.busId)

        if (importRequest.busId != deviceInfo.busid) {
            logger.warn("Import request for unknown busid: {}", importRequest.busId)
            return false
        }

        writeResponse(ImportResponse(deviceInfo).toBytes())
        logger.info("Device attached to client")
        return true
    }

    // --- URB phase: command(4) + seqnum(4) + ... ---

    private suspend fun CoroutineScope.handleSubmitPhase() {
        launch { interruptInPump() }
        while (isActive) {
            val header = readBigEndianBuffer(48)
            when (header.int) {
                USBIPProtocol.USBIP_CMD_SUBMIT -> handleCmdSubmit(header)
                USBIPProtocol.USBIP_CMD_UNLINK -> handleCmdUnlink(header)
                else -> logger.warn("Unknown command")
            }
        }
    }

    /**
     * Sequentially processes queued Interrupt IN requests.
     * Interrupt IN is a polling transfer that suspends until the device has data to send.
     * A sequential pump ensures response ordering for multi-packet HID replies.
     */
    private suspend fun interruptInPump() {
        for (pending in inRequestQueue) {
            try {
                val response = device.handleSubmit(pending.request)
                writeResponse(response)
                pending.done.complete(Unit)
            } catch (_: CancellationException) {
                pending.done.complete(Unit)
            } catch (e: Exception) {
                logger.error("Error processing Interrupt IN request", e)
                writeResponse(SubmitResponse.error(pending.request, USBIPProtocol.STATUS_EINVAL))
                pending.done.complete(Unit)
            }
        }
    }

    private suspend fun CoroutineScope.handleCmdSubmit(header: ByteBuffer) {
        var request = SubmitRequest.parse(header)

        if (request.transferBufferLength > MAX_TRANSFER_BUFFER_LENGTH) {
            logger.warn("Transfer size too large: {}", request.transferBufferLength)
            writeResponse(SubmitResponse.error(request, USBIPProtocol.STATUS_EINVAL))
            return
        }

        if (request.direction == USBIPProtocol.USBIP_DIR_OUT && request.transferBufferLength > 0) {
            request = request.copy(data = readBytes(request.transferBufferLength))
        }

        logger.debug("CMD_SUBMIT: ep={}, dir={}, len={}", request.ep, request.direction, request.transferBufferLength)

        val capturedRequest = request
        when {
            // Control transfers (EP0) and OUT transfers always have immediate responses.
            request.ep == USBIPProtocol.EP0_ADDRESS || request.direction == USBIPProtocol.USBIP_DIR_OUT -> {
                try {
                    writeResponse(device.handleSubmit(capturedRequest))
                } catch (e: Exception) {
                    logger.error("Error processing submit request", e)
                    writeResponse(SubmitResponse.error(capturedRequest, USBIPProtocol.STATUS_EINVAL))
                }
            }
            // Interrupt IN transfers suspend until data is available; route through sequential pump.
            else -> {
                val pending = PendingInRequest(capturedRequest)
                inRequestQueue.send(pending)
                val job = launch { pending.done.await() }
                pendingInJobs[request.seqnum] = job
                job.invokeOnCompletion { pendingInJobs.remove(request.seqnum) }
            }
        }
    }

    private suspend fun handleCmdUnlink(header: ByteBuffer) {
        val unlinkRequest = UnlinkRequest.parse(header)

        logger.debug("CMD_UNLINK: seqnum={}, unlinkSeqnum={}", unlinkRequest.seqnum, unlinkRequest.unlinkSeqnum)
        pendingInJobs.remove(unlinkRequest.unlinkSeqnum)?.cancel()
        writeResponse(UnlinkResponse(unlinkRequest.seqnum).toBytes())
    }

    // --- Helpers ---

    private class PendingInRequest(
        val request: SubmitRequest,
        val done: CompletableDeferred<Unit> = CompletableDeferred()
    )

    private suspend fun writeResponse(result: SubmitResponse) {
        writeResponse(result.toBytes())
    }

    private suspend fun readBytes(length: Int): ByteArray {
        val buffer = ByteArray(length)
        readChannel.readFully(buffer, 0, length)
        return buffer
    }

    private suspend fun readBigEndianBuffer(length: Int): ByteBuffer {
        return ByteBuffer.wrap(readBytes(length)).order(ByteOrder.BIG_ENDIAN)
    }

    private suspend fun writeResponse(data: ByteArray) {
        writeMutex.withLock {
            writeChannel.writeFully(data, 0, data.size)
        }
    }

    companion object {
        private const val MAX_TRANSFER_BUFFER_LENGTH = 4096
    }
}
