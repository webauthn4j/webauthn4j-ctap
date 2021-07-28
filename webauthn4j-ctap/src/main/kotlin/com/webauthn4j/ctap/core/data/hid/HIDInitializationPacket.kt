package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.UnsignedNumberUtil
import java.nio.ByteBuffer
import kotlin.experimental.or

class HIDInitializationPacket : HIDPacket {
    val command: HIDCommand
    val length: Int

    constructor(channelId: HIDChannelId, command: HIDCommand, length: Int, data: ByteArray) : super(
        channelId
    ) {
//        require(data.size == MAX_INIT_PACKET_DATA_SIZE){ "HIDInitializationPacket data size must be %d bytes".format(MAX_INIT_PACKET_DATA_SIZE) }
        require(length < UnsignedNumberUtil.UNSIGNED_SHORT_MAX) { "length must not exceed UNSIGNED_SHORT_MAX." }
        require(length > 0) { "length must not be negative value." }
        this.command = command
        this.length = length
        this.data = ArrayUtil.clone(data)
    }

    val data: ByteArray
        get() = ArrayUtil.clone(field)

    override fun toBytes(): ByteArray {
        val commandByte = command.value or HIDCommand.CMD_BIT
        val lengthHigh = length.shr(8).toByte()
        val lengthLow = length.toByte()

        return ByteBuffer.allocate(MAX_PACKET_SIZE).put(channelId.value).put(commandByte)
            .put(lengthHigh).put(lengthLow).put(data).array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        if (!super.equals(other)) return false

        other as HIDInitializationPacket

        if (command != other.command) return false
        if (length != other.length) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + command.hashCode()
        result = 31 * result + length
        return result
    }

    override fun toString(): String {
        return "HIDInitializationPacket(channelId=${channelId} command=$command, length=$length, data=${
            HexUtil.encodeToString(
                data
            )
        })"
    }


}