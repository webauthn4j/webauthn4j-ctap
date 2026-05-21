package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * USB Request Block (URB) for submit command.
 */
data class SubmitRequest(
    val seqnum: Int,
    val devid: Int,
    val direction: Int,
    val ep: Int,
    val transferFlags: Int,
    val transferBufferLength: Int,
    val startFrame: Int,
    val numberOfPackets: Int,
    val interval: Int,
    val setup: ByteArray,
    val data: ByteArray
) {
    companion object {
        /**
         * Parses a CMD_SUBMIT from the buffer (position should be at seqnum, after command code).
         */
        fun parse(buffer: ByteBuffer): SubmitRequest {
            buffer.order(ByteOrder.BIG_ENDIAN)
            val seqnum = buffer.int
            val devid = buffer.int
            val direction = buffer.int
            val ep = buffer.int
            val transferFlags = buffer.int
            val transferBufferLength = buffer.int
            val startFrame = buffer.int
            val numberOfPackets = buffer.int
            val interval = buffer.int
            val setup = ByteArray(8)
            buffer.get(setup)

            return SubmitRequest(
                seqnum = seqnum, devid = devid, direction = direction, ep = ep,
                transferFlags = transferFlags, transferBufferLength = transferBufferLength,
                startFrame = startFrame, numberOfPackets = numberOfPackets, interval = interval,
                setup = setup, data = ByteArray(0)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SubmitRequest
        return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                ep == other.ep && transferFlags == other.transferFlags &&
                transferBufferLength == other.transferBufferLength &&
                startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                interval == other.interval && setup.contentEquals(other.setup) &&
                data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = seqnum
        result = 31 * result + devid
        result = 31 * result + direction
        result = 31 * result + ep
        result = 31 * result + transferFlags
        result = 31 * result + transferBufferLength
        result = 31 * result + startFrame
        result = 31 * result + numberOfPackets
        result = 31 * result + interval
        result = 31 * result + setup.contentHashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }
}
