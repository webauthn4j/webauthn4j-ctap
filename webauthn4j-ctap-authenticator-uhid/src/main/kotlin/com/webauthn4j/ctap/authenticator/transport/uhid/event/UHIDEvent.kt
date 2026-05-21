package com.webauthn4j.ctap.authenticator.transport.uhid.event

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Base type for all UHID events.
 * All uhid_event structs are fixed-size (4380 bytes), little-endian.
 */
sealed interface UHIDEvent {

    fun toBytes(): ByteArray

    companion object {
        const val EVENT_SIZE = 4380

        internal const val TYPE_DESTROY = 1
        internal const val TYPE_START = 2
        internal const val TYPE_STOP = 3
        internal const val TYPE_OPEN = 4
        internal const val TYPE_CLOSE = 5
        internal const val TYPE_OUTPUT = 6
        internal const val TYPE_CREATE2 = 11
        internal const val TYPE_INPUT2 = 12

        fun parse(eventBytes: ByteArray): UHIDEvent {
            require(eventBytes.size == EVENT_SIZE) { "Event must be $EVENT_SIZE bytes" }
            val type = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0)
            return when (type) {
                TYPE_DESTROY -> DestroyDeviceEvent
                TYPE_START -> StartEvent
                TYPE_STOP -> StopEvent
                TYPE_OPEN -> OpenEvent
                TYPE_CLOSE -> CloseEvent
                TYPE_OUTPUT -> OutputReportEvent.parse(eventBytes)
                TYPE_CREATE2 -> CreateDeviceEvent.parse(eventBytes)
                TYPE_INPUT2 -> InputReportEvent.parse(eventBytes)
                else -> UnknownEvent(type)
            }
        }

        internal fun createSimpleEvent(type: Int): ByteArray {
            val buf = ByteBuffer.allocate(EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
            buf.putInt(type)
            return buf.array()
        }
    }
}
