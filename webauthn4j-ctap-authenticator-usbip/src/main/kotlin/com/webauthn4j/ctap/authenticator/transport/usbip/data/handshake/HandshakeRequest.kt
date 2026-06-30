package com.webauthn4j.ctap.authenticator.transport.usbip.data.handshake

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readFully
import io.ktor.utils.io.readInt
import io.ktor.utils.io.readShort

/** Base type for USB-IP handshake phase requests. */
sealed class HandshakeRequest {
    abstract val version: USBIPVersion

    companion object {
        suspend fun parse(channel: ByteReadChannel): HandshakeRequest {
            val versionValue = channel.readShort().toInt() and 0xFFFF
            val opcode = channel.readShort().toInt() and 0xFFFF
            val status = channel.readInt()
            val version = USBIPVersion.V1_1_1

            return when (opcode) {
                DeviceListRequest.OPCODE -> DeviceListRequest(version = version)
                ImportRequest.OPCODE -> {
                    val bytes = ByteArray(DeviceInfo.BUSID_FIELD_SIZE)
                    channel.readFully(bytes, 0, bytes.size)
                    val nullIndex = bytes.indexOf(0)
                    val endIndex = if (nullIndex >= 0) nullIndex else bytes.size
                    ImportRequest(version = version, busId = String(bytes, 0, endIndex, Charsets.US_ASCII))
                }
                else -> throw IllegalArgumentException("Unknown handshake opcode: 0x${Integer.toHexString(opcode)}")
            }
        }
    }
}
