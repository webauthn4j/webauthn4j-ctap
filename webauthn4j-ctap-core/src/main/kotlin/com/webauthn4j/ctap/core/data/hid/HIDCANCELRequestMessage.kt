package com.webauthn4j.ctap.core.data.hid

class HIDCANCELRequestMessage(channelId: HIDChannelId) : HIDRequestMessage,
    HIDMessageBase(channelId, HIDCommand.CTAPHID_CANCEL) {
    override val data: ByteArray = ByteArray(0)
    override fun toString(): String {
        return "HIDCANCELRequestMessage(channelId=${channelId}, command=$command})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDCANCELRequestMessage) return false
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