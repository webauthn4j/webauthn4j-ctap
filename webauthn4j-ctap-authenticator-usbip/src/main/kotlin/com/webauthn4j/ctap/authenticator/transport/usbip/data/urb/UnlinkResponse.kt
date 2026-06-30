package com.webauthn4j.ctap.authenticator.transport.usbip.data.urb

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** USBIP_RET_UNLINK — server response to an unlink request. */
data class UnlinkResponse(
    val seqnum: Int,
    val status: UrbStatus
) {
    val devid: Int = 0
    val direction: TransferDirection = TransferDirection.OUT
    val ep: Int = 0

    companion object {
        const val COMMAND = 0x00000004
        // command(4) + seqnum(4) + devid(4) + direction(4) + ep(4) + status(4) + padding(24) = 48
        private const val SIZE = 48
    }

    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(SIZE).order(ByteOrder.BIG_ENDIAN)

        buffer.putInt(COMMAND)
        buffer.putInt(seqnum)
        buffer.putInt(devid)
        buffer.putInt(direction.value)
        buffer.putInt(ep)

        buffer.putInt(status.value)
        repeat(6) { buffer.putInt(0) } // padding

        return buffer.array()
    }
}
