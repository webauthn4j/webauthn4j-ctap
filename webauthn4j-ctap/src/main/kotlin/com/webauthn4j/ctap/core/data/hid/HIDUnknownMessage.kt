package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil

class HIDUnknownMessage(
    channelId: HIDChannelId,
    override val command: HIDCommand,
    data: ByteArray
) : HIDRequestMessage, HIDResponseMessage, HIDMessageBase(channelId, command) {

    override val data = data
        get() = ArrayUtil.clone(field)

    override fun toString(): String {
        return "HIDUnknownMessage(channelId=${channelId} command=$command, data=${
            HexUtil.encodeToString(
                data
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDUnknownMessage) return false
        if (!super.equals(other)) return false

        if (!data.contentEquals(other.data)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + data.contentHashCode()
        return result
    }


}