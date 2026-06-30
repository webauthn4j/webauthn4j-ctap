package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** OP_REP_DEVLIST — response containing exported USB devices. */
data class DeviceListResponse(
    val devices: List<DeviceInfo>
) {
    val version: USBIPVersion = USBIPVersion.V1_1_1
    val status: HandshakeStatus = HandshakeStatus.OK

    companion object {
        const val OPCODE = 0x0005
    }

    fun toBytes(): ByteArray {
        val headerSize = 2 + 2 + 4 + 4 // version + opcode + status + numDevices
        val bufferSize = headerSize + devices.sumOf { DeviceInfo.SIZE + DeviceInfo.InterfaceInfo.SIZE * it.bNumInterfaces }
        val buffer = ByteBuffer.allocate(bufferSize).order(ByteOrder.BIG_ENDIAN)

        buffer.putShort(version.value.toShort())
        buffer.putShort(OPCODE.toShort())
        buffer.putInt(status.value)
        buffer.putInt(devices.size)

        for (device in devices) {
            device.writeTo(buffer, includeInterfaces = true)
        }

        return buffer.array()
    }
}
