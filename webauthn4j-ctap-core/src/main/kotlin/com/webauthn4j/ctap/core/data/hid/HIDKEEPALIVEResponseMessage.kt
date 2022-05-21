package com.webauthn4j.ctap.core.data.hid

class HIDKEEPALIVEResponseMessage(channelId: HIDChannelId, val statusCode: HIDStatusCode) :
    HIDResponseMessage, HIDMessageBase(channelId, HIDCommand.CTAPHID_KEEPALIVE) {

    override val data: ByteArray = byteArrayOf(statusCode.value)

    override fun toString(): String {
        return "HIDKEEPALIVEResponseMessage(channelId=${channelId}, command=${command}, statusCode=$statusCode)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDKEEPALIVEResponseMessage) return false
        if (!super.equals(other)) return false

        if (statusCode != other.statusCode) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + statusCode.hashCode()
        return result
    }


}
