package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** USBIP_RET_SUBMIT — server response after processing a submitted URB. */
class SubmitResponse(
    val seqnum: Int,
    val status: UrbStatus,
    val actualLength: Int,
    val startFrame: Int,
    val numberOfPackets: Int,
    val errorCount: Int,
    val transferBuffer: ByteArray
) {
    val devid: Int = 0
    val direction: TransferDirection = TransferDirection.OUT
    val ep: Int = 0

    companion object {
        const val COMMAND = 0x00000003
        // command(4) + seqnum(4) + devid(4) + direction(4) + ep(4) + status(4) + actualLength(4) + startFrame(4) + numberOfPackets(4) + errorCount(4) + setup(8) = 48
        private const val HEADER_SIZE = 48

        fun ok(request: SubmitRequest, transferBuffer: ByteArray, actualLength: Int = transferBuffer.size): SubmitResponse = SubmitResponse(
            seqnum = request.seqnum,
            status = UrbStatus.SUCCESS, actualLength = actualLength,
            startFrame = 0, numberOfPackets = 0, errorCount = 0, transferBuffer = transferBuffer
        )

        fun error(request: SubmitRequest, status: UrbStatus): SubmitResponse = SubmitResponse(
            seqnum = request.seqnum,
            status = status, actualLength = 0,
            startFrame = 0, numberOfPackets = 0, errorCount = 0, transferBuffer = ByteArray(0)
        )
    }

    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(HEADER_SIZE + transferBuffer.size).order(ByteOrder.BIG_ENDIAN)

        buffer.putInt(COMMAND)
        buffer.putInt(seqnum)
        buffer.putInt(devid)
        buffer.putInt(direction.value)
        buffer.putInt(ep)
        buffer.putInt(status.value)
        buffer.putInt(actualLength)
        buffer.putInt(startFrame)
        buffer.putInt(numberOfPackets)
        buffer.putInt(errorCount)
        buffer.putLong(0) // setup padding
        buffer.put(transferBuffer)

        return buffer.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as SubmitResponse
        return seqnum == other.seqnum && devid == other.devid && direction == other.direction &&
                ep == other.ep && status == other.status && actualLength == other.actualLength &&
                startFrame == other.startFrame && numberOfPackets == other.numberOfPackets &&
                errorCount == other.errorCount && transferBuffer.contentEquals(other.transferBuffer)
    }

    override fun hashCode(): Int {
        var result = seqnum
        result = 31 * result + devid
        result = 31 * result + direction.hashCode()
        result = 31 * result + ep
        result = 31 * result + status.hashCode()
        result = 31 * result + actualLength
        result = 31 * result + startFrame
        result = 31 * result + numberOfPackets
        result = 31 * result + errorCount
        result = 31 * result + transferBuffer.contentHashCode()
        return result
    }

    override fun toString(): String {
        return "SubmitResponse(seqnum=$seqnum, devid=$devid, direction=$direction, ep=$ep, status=$status, actualLength=$actualLength, transferBufferSize=${transferBuffer.size})"
    }
}
