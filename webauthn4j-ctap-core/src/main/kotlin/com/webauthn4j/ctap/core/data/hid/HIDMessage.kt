package com.webauthn4j.ctap.core.data.hid

import java.lang.Integer.min

interface HIDMessage {

    companion object {
        const val INIT_PACKET_HEADER_SIZE = 7
        const val CONT_PACKET_HEADER_SIZE = 5
        const val DEFAULT_PACKET_SIZE = 64

        // Kept for backward compatibility; derived from DEFAULT_PACKET_SIZE
        const val MAX_PACKET_SIZE = DEFAULT_PACKET_SIZE
        const val MAX_INIT_PACKET_DATA_SIZE = DEFAULT_PACKET_SIZE - INIT_PACKET_HEADER_SIZE
        const val MAX_CONT_PACKET_DATA_SIZE = DEFAULT_PACKET_SIZE - CONT_PACKET_HEADER_SIZE

        fun initPacketDataSize(packetSize: Int): Int = packetSize - INIT_PACKET_HEADER_SIZE
        fun contPacketDataSize(packetSize: Int): Int = packetSize - CONT_PACKET_HEADER_SIZE
        fun maxMessageDataSize(packetSize: Int): Int =
            initPacketDataSize(packetSize) + 128 * contPacketDataSize(packetSize)
    }

    val channelId: HIDChannelId
    val command: HIDCommand
    val data: ByteArray

    fun toHIDPackets(packetSize: Int = DEFAULT_PACKET_SIZE): List<HIDPacket> {
        val maxInitDataSize = initPacketDataSize(packetSize)
        val maxContDataSize = contPacketDataSize(packetSize)
        val maxMessageSize = maxMessageDataSize(packetSize)
        require(data.size <= maxMessageSize) { "data must not exceed $maxMessageSize bytes, which is the max HID message size for packet size $packetSize." }

        var pos = 0

        val initPacketData = ByteArray(maxInitDataSize)
        val initPacketActualDataSize = min(data.size, maxInitDataSize)
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
            val contPacketData = ByteArray(maxContDataSize)
            val contPacketActualDataSize = min(remainingDataSize, maxContDataSize)
            data.copyInto(contPacketData, 0, pos, pos + contPacketActualDataSize)
            val continuationPacket = HIDContinuationPacket(channelId, index, contPacketData)
            pos += contPacketActualDataSize
            list.add(continuationPacket)
            index++
        }
        return list
    }

}