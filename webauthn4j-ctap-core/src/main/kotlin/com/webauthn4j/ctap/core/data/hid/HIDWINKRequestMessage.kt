package com.webauthn4j.ctap.core.data.hid


class HIDWINKRequestMessage(channelId: HIDChannelId) : HIDRequestMessage,
    HIDMessageBase(channelId, HIDCommand.CTAPHID_WINK) {

    override val data: ByteArray
        get() = ByteArray(0)

    override fun toString(): String {
        return "HIDWINKRequestMessage(channelId=${channelId}, command=$command)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDWINKRequestMessage) return false
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