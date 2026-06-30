package com.webauthn4j.ctap.authenticator.transport.uhid.event

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * UHID_OUTPUT event: receives a HID report from host to device.
 */
data class OutputReportEvent(
    val data: ByteArray,
    val size: Int,
    val rtype: Byte
) : UHIDEvent {
    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEvent.TYPE_OUTPUT)
        buf.position(DATA_OFFSET)
        buf.put(data)
        buf.position(SIZE_OFFSET)
        buf.putShort(size.toShort())
        buf.put(rtype)
        return buf.array()
    }

    companion object {
        private const val DATA_OFFSET = 4
        private const val SIZE_OFFSET = 4100
        private const val RTYPE_OFFSET = 4102

        fun parse(eventBytes: ByteArray): OutputReportEvent {
            require(eventBytes.size == UHIDEvent.EVENT_SIZE) { "Event must be ${UHIDEvent.EVENT_SIZE} bytes" }
            val buf = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN)
            val size = buf.getShort(SIZE_OFFSET).toInt() and 0xFFFF
            val rtype = buf.get(RTYPE_OFFSET)

            val reportSize = minOf(size, 64)
            val data = ByteArray(reportSize)
            buf.position(DATA_OFFSET)
            buf.get(data, 0, reportSize)

            return OutputReportEvent(data, size, rtype)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is OutputReportEvent) return false
        return size == other.size && rtype == other.rtype && data.contentEquals(other.data)
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + size
        result = 31 * result + rtype.hashCode()
        return result
    }
}
