package com.webauthn4j.ctap.authenticator.transport.uhid.event

import com.webauthn4j.ctap.authenticator.transport.uhid.UHIDDeviceConfig
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * UHID_CREATE2 event: creates a virtual HID device.
 */
data class CreateDeviceEvent(
    val config: UHIDDeviceConfig,
    val reportDescriptor: ByteArray
) : UHIDEvent {
    override fun toBytes(): ByteArray {
        require(reportDescriptor.size <= RD_DATA_SIZE) {
            "Report descriptor must not exceed $RD_DATA_SIZE bytes"
        }
        val buf = ByteBuffer.allocate(UHIDEvent.EVENT_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(UHIDEvent.TYPE_CREATE2)
        putFixedString(buf, NAME_OFFSET, config.deviceName, NAME_SIZE)
        putFixedString(buf, PHYS_OFFSET, config.physicalAddress, PHYS_SIZE)
        putFixedString(buf, UNIQ_OFFSET, config.uniqueId, UNIQ_SIZE)
        buf.position(RD_SIZE_OFFSET)
        buf.putShort(reportDescriptor.size.toShort())
        buf.position(BUS_OFFSET)
        buf.putShort(BUS_USB)
        buf.position(VENDOR_OFFSET)
        buf.putInt(config.vendorId)
        buf.position(PRODUCT_OFFSET)
        buf.putInt(config.productId)
        buf.position(VERSION_OFFSET)
        buf.putInt(config.version)
        buf.position(COUNTRY_OFFSET)
        buf.putInt(0)
        buf.position(RD_DATA_OFFSET)
        buf.put(reportDescriptor)
        return buf.array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CreateDeviceEvent) return false
        return config == other.config && reportDescriptor.contentEquals(other.reportDescriptor)
    }

    override fun hashCode(): Int = 31 * config.hashCode() + reportDescriptor.contentHashCode()

    companion object {
        private const val NAME_OFFSET = 4
        private const val NAME_SIZE = 128
        private const val PHYS_OFFSET = 132
        private const val PHYS_SIZE = 64
        private const val UNIQ_OFFSET = 196
        private const val UNIQ_SIZE = 64
        private const val RD_SIZE_OFFSET = 260
        private const val BUS_OFFSET = 262
        private const val VENDOR_OFFSET = 264
        private const val PRODUCT_OFFSET = 268
        private const val VERSION_OFFSET = 272
        private const val COUNTRY_OFFSET = 276
        private const val RD_DATA_OFFSET = 280
        private const val RD_DATA_SIZE = 4096
        private const val BUS_USB: Short = 0x03

        fun parse(eventBytes: ByteArray): CreateDeviceEvent {
            require(eventBytes.size == UHIDEvent.EVENT_SIZE) { "Event must be ${UHIDEvent.EVENT_SIZE} bytes" }
            val buf = ByteBuffer.wrap(eventBytes).order(ByteOrder.LITTLE_ENDIAN)
            val name = readFixedString(buf, NAME_OFFSET, NAME_SIZE)
            val phys = readFixedString(buf, PHYS_OFFSET, PHYS_SIZE)
            val uniq = readFixedString(buf, UNIQ_OFFSET, UNIQ_SIZE)
            val rdSize = buf.getShort(RD_SIZE_OFFSET).toInt() and 0xFFFF
            val vendorId = buf.getInt(VENDOR_OFFSET)
            val productId = buf.getInt(PRODUCT_OFFSET)
            val version = buf.getInt(VERSION_OFFSET)
            val rdData = ByteArray(rdSize)
            buf.position(RD_DATA_OFFSET)
            buf.get(rdData)
            val config = UHIDDeviceConfig(
                deviceName = name, vendorId = vendorId, productId = productId,
                version = version, physicalAddress = phys, uniqueId = uniq
            )
            return CreateDeviceEvent(config, rdData)
        }

        private fun readFixedString(buf: ByteBuffer, offset: Int, maxLen: Int): String {
            val bytes = ByteArray(maxLen)
            buf.position(offset)
            buf.get(bytes)
            val nullIndex = bytes.indexOf(0)
            val endIndex = if (nullIndex >= 0) nullIndex else bytes.size
            return String(bytes, 0, endIndex, Charsets.UTF_8)
        }

        private fun putFixedString(buf: ByteBuffer, offset: Int, str: String, maxLen: Int) {
            val bytes = str.toByteArray(Charsets.UTF_8)
            val len = minOf(bytes.size, maxLen - 1)
            buf.position(offset)
            buf.put(bytes, 0, len)
        }
    }
}
