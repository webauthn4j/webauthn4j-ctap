package com.webauthn4j.ctap.authenticator.transport.usbip.protocol

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * OP_REP_IMPORT response.
 */
data class ImportResponse(
    val device: DeviceInfo
) {
    fun toBytes(): ByteArray {
        val buffer = ByteBuffer.allocate(320).order(ByteOrder.BIG_ENDIAN)

        buffer.putShort(USBIPProtocol.USBIP_VERSION.toShort())
        buffer.putShort(USBIPProtocol.OP_REP_IMPORT.toShort())
        buffer.putInt(0) // status

        device.writeTo(buffer, includeInterfaces = false)

        return buffer.array()
    }
}
