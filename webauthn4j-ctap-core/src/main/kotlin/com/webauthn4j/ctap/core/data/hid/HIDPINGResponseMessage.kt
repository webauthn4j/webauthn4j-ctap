package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.util.ArrayUtil
import com.webauthn4j.util.HexUtil

class HIDPINGResponseMessage : HIDResponseMessage, HIDMessageBase {

    constructor(channelId: HIDChannelId, data: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_PING
    ) {
        this.data = ArrayUtil.clone(data)
    }

    override val data: ByteArray
        get() = ArrayUtil.clone(field)

    override fun toString(): String {
        return "HIDPINGResponseMessage(channelId=${channelId}, command=$command, data=${
            HexUtil.encodeToString(
                data
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDPINGResponseMessage) return false
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