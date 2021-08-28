package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer
import kotlin.experimental.or

class HIDInitializationPacket : HIDPacket {
    @Suppress("JoinDeclarationAndAssignment")
    val command: HIDCommand
    val length: UShort

    constructor(channelId: HIDChannelId, command: HIDCommand, length: UShort, data: ByteArray) : super(
        channelId
    ) {
//        require(data.size == MAX_INIT_PACKET_DATA_SIZE){ "HIDInitializationPacket data size must be %d bytes".format(MAX_INIT_PACKET_DATA_SIZE) }
        this.command = command
        this.length = length
        this.data = ArrayUtil.clone(data)
    }

    val data: ByteArray
        get() = ArrayUtil.clone(field)

    override fun toBytes(): ByteArray {
        val commandByte = command.value or HIDCommand.CMD_BIT

        return ByteBuffer.allocate(MAX_PACKET_SIZE)
            .put(channelId.value)
            .put(commandByte)
            .putShort(length.toShort())
            .put(data)
            .array()
    }


    override fun toString(): String {
        return "HIDInitializationPacket(channelId=${channelId} command=$command, length=$length, data=${
            HexUtil.encodeToString(
                data
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDInitializationPacket) return false
        if (!super.equals(other)) return false

        if (command != other.command) return false
        if (length != other.length) return false
        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + command.hashCode()
        result = 31 * result + length.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }


}