package com.webauthn4j.ctap.core.data.hid

import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.util.ArrayUtil

class HIDINITRequestMessage : HIDRequestMessage, HIDMessageBase {

    constructor(channelId: HIDChannelId, nonce: ByteArray) : super(
        channelId,
        HIDCommand.CTAPHID_INIT
    ) {
        this.nonce = ArrayUtil.clone(nonce)
    }

    val nonce: ByteArray
        get() = ArrayUtil.clone(field)

    override val data: ByteArray
        get() = ArrayUtil.clone(nonce)

    override fun toString(): String {
        return "HIDINITRequestMessage(channelId=${channelId}, command=$command, nonce=${
            HexUtil.encodeToString(
                nonce
            )
        })"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDINITRequestMessage) return false
        if (!super.equals(other)) return false

        if (!nonce.contentEquals(other.nonce)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + nonce.contentHashCode()
        return result
    }


}