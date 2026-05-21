package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OP_REP_DEVLIST response.
 */
data class DeviceListResponse(
    val devices: List<DeviceInfo>
) {
    fun toBytes(): ByteArray {
        val bufferSize = 12 + devices.sumOf { 312 + 4 * it.bNumInterfaces }
        val buffer = ByteBuffer.allocate(bufferSize).order(ByteOrder.BIG_ENDIAN)

        buffer.putShort(USBIPProtocol.USBIP_VERSION.toShort())
        buffer.putShort(USBIPProtocol.OP_REP_DEVLIST.toShort())
        buffer.putInt(0) // status
        buffer.putInt(devices.size)

        for (device in devices) {
            device.writeTo(buffer, includeInterfaces = true)
        }

        return buffer.array()
    }
}
