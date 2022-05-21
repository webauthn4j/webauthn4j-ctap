package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.data.hid.HIDMessage.Companion.MAX_PACKET_SIZE
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil
import java.nio.ByteBuffer

class HIDContinuationPacket : HIDPacket {
    @Suppress("JoinDeclarationAndAssignment")
    val sec: Byte
    val data: ByteArray
        get() = ArrayUtil.clone(field)

    @Suppress("ConvertSecondaryConstructorToPrimary")
    constructor(channelId: HIDChannelId, sec: Byte, data: ByteArray) : super(channelId) {
//        require(data.size == HIDMessage.MAX_CONT_PACKET_DATA_SIZE){ "HIDContinuationPacket data size must be %d bytes".format(HIDMessage.MAX_CONT_PACKET_DATA_SIZE) }
        this.sec = sec
        this.data = ArrayUtil.clone(data)
    }


    override fun toBytes(): ByteArray {
        return ByteBuffer.allocate(MAX_PACKET_SIZE).put(channelId.value).put(sec).put(data).array()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        if (!super.equals(other)) return false

        other as HIDContinuationPacket

        if (sec != other.sec) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + sec
        return result
    }

    override fun toString(): String {
        return "HIDContinuationPacket(channelId=${channelId} sec=$sec, data=${
            HexUtil.encodeToString(
                data
            )
        })"
    }


}
