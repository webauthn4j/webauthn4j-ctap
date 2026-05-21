package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OP_REQ_IMPORT request.
 */
data class ImportRequest(
    val busId: String
) {
    companion object {
        fun parse(buffer: ByteBuffer): ImportRequest {
            buffer.order(ByteOrder.BIG_ENDIAN)
            val bytes = ByteArray(32)
            buffer.get(bytes)
            val nullIndex = bytes.indexOf(0)
            val endIndex = if (nullIndex >= 0) nullIndex else bytes.size
            return ImportRequest(String(bytes, 0, endIndex, Charsets.US_ASCII))
        }
    }
}
