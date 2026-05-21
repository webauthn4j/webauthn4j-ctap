package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * USBIP_RET_UNLINK response.
 */
data class UnlinkResponse(
    val seqnum: Int
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(48).order(ByteOrder.BIG_ENDIAN)

        buffer.putInt(USBIPProtocol.USBIP_RET_UNLINK)
        buffer.putInt(seqnum)
        buffer.putInt(0) // devid
        buffer.putInt(0) // direction
        buffer.putInt(0) // ep

        buffer.putInt(USBIPProtocol.STATUS_ECONNRESET)
        repeat(6) { buffer.putInt(0) } // padding

        return buffer.array()
    }
}
