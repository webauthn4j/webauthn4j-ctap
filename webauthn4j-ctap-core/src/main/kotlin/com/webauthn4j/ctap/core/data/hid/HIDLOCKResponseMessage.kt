package com.webauthn4j.ctap.core.data.hid

class HIDLOCKResponseMessage(channelId: HIDChannelId) : HIDResponseMessage,
    HIDMessageBase(channelId, HIDCommand.CTAPHID_LOCK) {

    override val data: ByteArray
        get() = ByteArray(0)

    override fun toString(): String {
        return "HIDLOCKResponseMessage(channelId=${channelId}, command=$command})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDLOCKResponseMessage) return false
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