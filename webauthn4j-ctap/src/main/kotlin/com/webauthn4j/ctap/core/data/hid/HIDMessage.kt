package com.webauthn4j.ctap.core.data.hid

import java.lang.Integer.min

interface HIDMessage {

    companion object {
        private const val INIT_PACKET_HEADER_SIZE = 7
        private const val CONT_PACKET_HEADER_SIZE = 5
        const val MAX_PACKET_SIZE = 62
        const val MAX_INIT_PACKET_DATA_SIZE = MAX_PACKET_SIZE - INIT_PACKET_HEADER_SIZE
        const val MAX_CONT_PACKET_DATA_SIZE = MAX_PACKET_SIZE - CONT_PACKET_HEADER_SIZE
    }

    val channelId: HIDChannelId
    val command: HIDCommand
    val data: ByteArray

    fun toHIDPackets(): List<HIDPacket> {
        require(data.size <= 7609) { "data must not exceed 7609 bytes, which is the max HID message size." }

        var pos = 0

        val initPacketData = ByteArray(MAX_INIT_PACKET_DATA_SIZE)
        val initPacketActualDataSize = min(data.size, MAX_INIT_PACKET_DATA_SIZE)
        data.copyInto(initPacketData, 0, 0, initPacketActualDataSize)
        val initializationPacket =
            HIDInitializationPacket(channelId, command, data.size.toUShort(), initPacketData)
        pos += initPacketActualDataSize
        val list = mutableListOf<HIDPacket>(initializationPacket)

        var index: Byte = 0
        while (true) {
            val remainingDataSize = data.size - pos
            if (remainingDataSize == 0) {
                break
            }
            val contPacketData = ByteArray(MAX_CONT_PACKET_DATA_SIZE)
            val contPacketActualDataSize = min(remainingDataSize, MAX_CONT_PACKET_DATA_SIZE)
            data.copyInto(contPacketData, 0, pos, pos + contPacketActualDataSize)
            val continuationPacket = HIDContinuationPacket(channelId, index, contPacketData)
            pos += contPacketActualDataSize
            list.add(continuationPacket)
            index++
        }
        return list
    }

}