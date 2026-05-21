package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer

/**
 * Device information structure for USB-IP.
 */
data class DeviceInfo(
    val path: String,
    val busid: String,
    val busnum: Int,
    val devnum: Int,
    val speed: Int,
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
    )

    /**
     * Writes this device info to the buffer.
     * @param includeInterfaces true for devlist (includes 4-byte interface descriptors), false for import
     */
    fun writeTo(buffer: ByteBuffer, includeInterfaces: Boolean = false) {
        writeString(buffer, path, 256)
        writeString(buffer, busid, 32)
        buffer.putInt(busnum)
        buffer.putInt(devnum)
        buffer.putInt(speed)
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
