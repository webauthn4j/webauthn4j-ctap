package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** OP_REP_IMPORT — response confirming device attachment with device details. */
data class ImportResponse(
    val status: HandshakeStatus = HandshakeStatus.OK,
    val device: DeviceInfo
) {
    val version: USBIPVersion = USBIPVersion.V1_1_1

    companion object {
        const val OPCODE = 0x0003
    }

    fun toBytes(): ByteArray {
        val headerSize = 2 + 2 + 4 // version + opcode + status
        val buffer = ByteBuffer.allocate(headerSize + DeviceInfo.SIZE).order(ByteOrder.BIG_ENDIAN)

        buffer.putShort(version.value.toShort())
        buffer.putShort(OPCODE.toShort())
        buffer.putInt(status.value)

        device.writeTo(buffer, includeInterfaces = false)

        return buffer.array()
    }
}
