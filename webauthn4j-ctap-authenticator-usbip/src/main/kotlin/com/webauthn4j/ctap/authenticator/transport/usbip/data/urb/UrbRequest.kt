package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.readInt

/** Base type for USB-IP URB phase requests. */
sealed class UrbRequest {
    abstract val seqnum: Int

    companion object {
        suspend fun parse(channel: ByteReadChannel): UrbRequest {
            val command = channel.readInt()
            val seqnum = channel.readInt()
            val devid = channel.readInt()
            val directionValue = channel.readInt()
            val ep = channel.readInt()

            return when (command) {
                SubmitRequest.COMMAND -> {
                    val direction = TransferDirection.fromValue(directionValue)
                    val transferFlags = channel.readInt()
                    val transferBufferLength = channel.readInt()
                    val startFrame = channel.readInt()
                    val numberOfPackets = channel.readInt()
                    val interval = channel.readInt()
                    val setupBytes = ByteArray(SubmitRequest.Setup.SIZE)
                    channel.readFully(setupBytes, 0, setupBytes.size)

                    val transferBuffer = if (direction == TransferDirection.OUT && transferBufferLength > 0) {
                        val bytes = ByteArray(transferBufferLength)
                        channel.readFully(bytes, 0, transferBufferLength)
                        bytes
                    } else {
                        ByteArray(0)
                    }

                    SubmitRequest(
                        seqnum = seqnum, devid = devid, direction = direction, ep = ep,
                        transferFlags = transferFlags, transferBufferLength = transferBufferLength,
                        startFrame = startFrame, numberOfPackets = numberOfPackets, interval = interval,
                        setup = SubmitRequest.Setup.parse(setupBytes), transferBuffer = transferBuffer
                    )
                }
                UnlinkRequest.COMMAND -> {
                    val unlinkSeqnum = channel.readInt()
                    // skip remaining 24 bytes of padding
                    val padding = ByteArray(24)
                    channel.readFully(padding, 0, padding.size)
                    UnlinkRequest(seqnum = seqnum, unlinkSeqnum = unlinkSeqnum)
                }
                else -> throw IllegalArgumentException("Unknown URB command: 0x${Integer.toHexString(command)}")
            }
        }
    }
}
