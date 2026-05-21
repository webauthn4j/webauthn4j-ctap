package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * URB result for submit return.
 */
data class SubmitResponse(
    val seqnum: Int,
    val devid: Int,
    val direction: Int,
    val ep: Int,
    val status: Int,
    val actualLength: Int,
    val startFrame: Int,
    val numberOfPackets: Int,
    val errorCount: Int,
    val data: ByteArray
) {
    /**
     * Writes this result as a USBIP_RET_SUBMIT response to the buffer.
     */
    fun writeTo(buffer: ByteBuffer) {
        buffer.putInt(USBIPProtocol.USBIP_RET_SUBMIT)
        buffer.putInt(seqnum)
        buffer.putInt(devid)
        buffer.putInt(direction)
        buffer.putInt(ep)

        buffer.putInt(status)
        buffer.putInt(actualLength)
        buffer.putInt(startFrame)
        buffer.putInt(numberOfPackets)
        buffer.putInt(errorCount)

        buffer.putLong(0) // setup padding
        buffer.put(data)
    }

    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(48 + data.size).order(ByteOrder.BIG_ENDIAN)
        writeTo(buffer)
        return buffer.array()
    }

    companion object {
        fun success(request: SubmitRequest, data: ByteArray, actualLength: Int = data.size): SubmitResponse = SubmitResponse(
            seqnum = request.seqnum, devid = request.devid, direction = request.direction, ep = request.ep,
            status = USBIPProtocol.STATUS_SUCCESS, actualLength = actualLength,
            startFrame = 0, numberOfPackets = 0, errorCount = 0, data = data
        )

        fun error(request: SubmitRequest, status: Int): SubmitResponse = SubmitResponse(
            seqnum = request.seqnum, devid = request.devid, direction = request.direction, ep = request.ep,
            status = status, actualLength = 0,
            startFrame = 0, numberOfPackets = 0, errorCount = 0, data = ByteArray(0)
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SubmitResponse
        return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                ep == other.ep && status == other.status && actualLength == other.actualLength &&
                startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                errorCount == other.errorCount && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = seqnum
        result = 31 * result + devid
        result = 31 * result + direction
        result = 31 * result + ep
        result = 31 * result + status
        result = 31 * result + actualLength
        result = 31 * result + startFrame
        result = 31 * result + numberOfPackets
        result = 31 * result + errorCount
        result = 31 * result + data.contentHashCode()
        return result
    }
}
