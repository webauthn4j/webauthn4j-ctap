package com.webauthn4j.ctap.uhid

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Serialization and deserialization of Linux uhid_event structs.
 * All events are fixed-size (4380 bytes), little-endian.
 */
object UHIDEvent {
    const val EVENT_SIZE = 4380

    // UHID_CREATE2 field offsets within uhid_event structure
    // struct uhid_event { u32 type; union { struct uhid_create2_req create2; ... } u; }
    // Offsets verified with offsetof() in Linux kernel uhid.h
    private const val CREATE2_NAME_OFFSET = 4        // event.u.create2.name
    private const val CREATE2_NAME_SIZE = 128
    private const val CREATE2_PHYS_OFFSET = 132      // event.u.create2.phys
    private const val CREATE2_PHYS_SIZE = 64
    private const val CREATE2_UNIQ_OFFSET = 196      // event.u.create2.uniq
    private const val CREATE2_UNIQ_SIZE = 64
    private const val CREATE2_RD_SIZE_OFFSET = 260   // event.u.create2.rd_size
    private const val CREATE2_BUS_OFFSET = 262       // event.u.create2.bus
    private const val CREATE2_VENDOR_OFFSET = 264    // event.u.create2.vendor
    private const val CREATE2_PRODUCT_OFFSET = 268   // event.u.create2.product
    private const val CREATE2_VERSION_OFFSET = 272   // event.u.create2.version
    private const val CREATE2_COUNTRY_OFFSET = 276   // event.u.create2.country
    private const val CREATE2_RD_DATA_OFFSET = 280   // event.u.create2.rd_data
    private const val CREATE2_RD_DATA_SIZE = 4096

    // UHID_INPUT2 field offsets
    private const val INPUT2_SIZE_OFFSET = 4
    private const val INPUT2_DATA_OFFSET = 6

    // UHID_OUTPUT field offsets
    private const val OUTPUT_DATA_OFFSET = 4
    private const val OUTPUT_DATA_SIZE = 4096
    private const val OUTPUT_SIZE_OFFSET = 4100
    private const val OUTPUT_RTYPE_OFFSET = 4102

    private const val BUS_USB: Short = 0x03

    fun createCreate2(config: UHIDDeviceConfig, reportDescriptor: ByteArray): ByteArray {
        require(reportDescriptor.size <= CREATE2_RD_DATA_SIZE) {
            "Report descriptor must not exceed $CREATE2_RD_DATA_SIZE bytes"
        }
        val buf = ByteBuffer.allocate(EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEventType.UHID_CREATE2.value)
        putFixedString(buf, CREATE2_NAME_OFFSET, config.deviceName, CREATE2_NAME_SIZE)
        putFixedString(buf, CREATE2_PHYS_OFFSET, config.physicalAddress, CREATE2_PHYS_SIZE)
        putFixedString(buf, CREATE2_UNIQ_OFFSET, config.uniqueId, CREATE2_UNIQ_SIZE)
        buf.position(CREATE2_RD_SIZE_OFFSET)
        buf.putShort(reportDescriptor.size.toShort())
        buf.position(CREATE2_BUS_OFFSET)
        buf.putShort(BUS_USB)
        buf.position(CREATE2_VENDOR_OFFSET)
        buf.putInt(config.vendorId)
        buf.position(CREATE2_PRODUCT_OFFSET)
        buf.putInt(config.productId)
        buf.position(CREATE2_VERSION_OFFSET)
        buf.putInt(config.version)
        buf.position(CREATE2_COUNTRY_OFFSET)
        buf.putInt(0)
        buf.position(CREATE2_RD_DATA_OFFSET)
        buf.put(reportDescriptor)
        return buf.array()
    }

    fun createInput2(data: ByteArray): ByteArray {
        val buf = ByteBuffer.allocate(EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEventType.UHID_INPUT2.value)
        buf.position(INPUT2_SIZE_OFFSET)
        buf.putShort(data.size.toShort())
        buf.position(INPUT2_DATA_OFFSET)
        buf.put(data)
        return buf.array()
    }

    fun createDestroy(): ByteArray {
        val buf = ByteBuffer.allocate(EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEventType.UHID_DESTROY.value)
        return buf.array()
    }

    fun parseType(eventBytes: ByteArray): UHIDEventType? {
        require(eventBytes.size == EVENT_SIZE) { "Event must be $EVENT_SIZE bytes" }
        val type = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN).getInt(0)
        return UHIDEventType.fromValue(type)
    }

    fun parseOutput(eventBytes: ByteArray): OutputEvent {
        require(eventBytes.size == EVENT_SIZE) { "Event must be $EVENT_SIZE bytes" }
        val buf = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN)
        val size = buf.getShort(OUTPUT_SIZE_OFFSET).toInt() and 0xFFFF
        val rtype = buf.get(OUTPUT_RTYPE_OFFSET)

        // FIDO HID reports are always 64 bytes (or 65 with report ID)
        // The 'size' field from UHID may be larger, but we only need the HID report data
        val reportSize = minOf(size, 64)
        val data = ByteArray(reportSize)
        buf.position(OUTPUT_DATA_OFFSET)
        buf.get(data, 0, reportSize)

        return OutputEvent(data, size, rtype)
    }

    private fun putFixedString(buf: ByteBuffer, offset: Int, str: String, maxLen: Int) {
        val bytes = str.toByteArray(Charsets.UTF_8)
        val len = minOf(bytes.size, maxLen - 1) // leave room for null terminator
        buf.position(offset)
        buf.put(bytes, 0, len)
        // remaining bytes are already zero-initialized
    }

    data class OutputEvent(val data: ByteArray, val size: Int, val rtype: Byte) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is OutputEvent) return false
            return size == other.size && rtype == other.rtype && data.contentEquals(other.data)
        }

        override fun hashCode(): Int {
            var result = data.contentHashCode()
            result = 31 * result + size
            result = 31 * result + rtype.hashCode()
            return result
        }
    }
}
