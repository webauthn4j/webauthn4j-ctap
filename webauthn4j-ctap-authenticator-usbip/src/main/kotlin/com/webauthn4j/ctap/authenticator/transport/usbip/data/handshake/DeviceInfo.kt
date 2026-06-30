package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

import java.nio.ByteBuffer

/**
 * Device information structure for USB-IP.
 */
data class DeviceInfo(
    val path: String,  // 256 bytes
    val busid: String, // 32 bytes
    val busnum: Int,
    val devnum: Int,
    val speed: USBSpeed,
    val idVendor: Int,
    val idProduct: Int,
    val bcdDevice: Int,
    val bDeviceClass: Int,
    val bDeviceSubClass: Int,
    val bDeviceProtocol: Int,
    val bConfigurationValue: Int,
    val bNumConfigurations: Int,
    val bNumInterfaces: Int,
    val interfaces: List<InterfaceInfo> = emptyList()
) {
    data class InterfaceInfo(
        val bInterfaceClass: Int,
        val bInterfaceSubClass: Int,
        val bInterfaceProtocol: Int
    ) {
        companion object {
            const val SIZE = 4
        }
    }

    companion object {
        private const val PATH_FIELD_SIZE = 256
        const val BUSID_FIELD_SIZE = 32
        const val SIZE = PATH_FIELD_SIZE + BUSID_FIELD_SIZE + 4 * 3 + 2 * 3 + 6 // 312
    }

    fun writeTo(buffer: ByteBuffer, includeInterfaces: Boolean = false) {
        writeString(buffer, path, PATH_FIELD_SIZE)
        writeString(buffer, busid, BUSID_FIELD_SIZE)
        buffer.putInt(busnum)
        buffer.putInt(devnum)
        buffer.putInt(speed.value)
        buffer.putShort(idVendor.toShort())
        buffer.putShort(idProduct.toShort())
        buffer.putShort(bcdDevice.toShort())
        buffer.put(bDeviceClass.toByte())
        buffer.put(bDeviceSubClass.toByte())
        buffer.put(bDeviceProtocol.toByte())
        buffer.put(bConfigurationValue.toByte())
        buffer.put(bNumConfigurations.toByte())
        buffer.put(bNumInterfaces.toByte())

        if (includeInterfaces) {
            for (iface in interfaces) {
                buffer.put(iface.bInterfaceClass.toByte())
                buffer.put(iface.bInterfaceSubClass.toByte())
                buffer.put(iface.bInterfaceProtocol.toByte())
                buffer.put(0) // padding
            }
        }
    }

    private fun writeString(buffer: ByteBuffer, str: String, length: Int) {
        val bytes = str.toByteArray(Charsets.US_ASCII)
        val toCopy = minOf(bytes.size, length - 1)
        buffer.put(bytes, 0, toCopy)
        repeat(length - toCopy) { buffer.put(0) }
    }
}
