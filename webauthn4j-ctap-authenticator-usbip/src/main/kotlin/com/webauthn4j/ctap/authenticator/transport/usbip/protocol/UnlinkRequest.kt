package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * USBIP_CMD_UNLINK request.
 */
data class UnlinkRequest(
    val seqnum: Int,
    val unlinkSeqnum: Int
) {
    companion object {
        /**
         * Parses a CMD_UNLINK from the buffer (position should be at seqnum, after command code).
         */
        fun parse(buffer: ByteBuffer): UnlinkRequest {
            buffer.order(ByteOrder.BIG_ENDIAN)
            val seqnum = buffer.int
            buffer.position(buffer.position() + 12) // skip devid, direction, ep
            val unlinkSeqnum = buffer.int
            return UnlinkRequest(seqnum = seqnum, unlinkSeqnum = unlinkSeqnum)
        }
    }
}
