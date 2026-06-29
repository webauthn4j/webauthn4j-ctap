package com.webauthn4j.ctap.authenticator.transport.uhid.event

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * UHID_INPUT2 event: sends a HID report from device to host.
 */
data class InputReportEvent(
    val data: ByteArray
) : UHIDEvent {
    override fun toBytes(): ByteArray {
        val buf = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEvent.TYPE_INPUT2)
        buf.position(SIZE_OFFSET)
        buf.putShort(data.size.toShort())
        buf.position(DATA_OFFSET)
        buf.put(data)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is InputReportEvent) return false
        return data.contentEquals(other.data)
    }

    override fun hashCode(): Int = data.contentHashCode()

    companion object {
        private const val SIZE_OFFSET = 4
        private const val DATA_OFFSET = 6

        fun parse(eventBytes: ByteArray): InputReportEvent {
            require(eventBytes.size == UHIDEvent.EVENT_SIZE) { "Event must be ${UHIDEvent.EVENT_SIZE} bytes" }
            val buf = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN)
            val size = buf.getShort(SIZE_OFFSET).toInt() and 0xFFFF
            val data = ByteArray(size)
            buf.position(DATA_OFFSET)
            buf.get(data)
            return InputReportEvent(data)
        }
    }
}
