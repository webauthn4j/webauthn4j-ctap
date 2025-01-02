package com.webauthn4j.ctap.core.data.hid

class HIDERRORResponseMessage(channelId: HIDChannelId, val errorCode: HIDErrorCode) :
    HIDResponseMessage, HIDMessageBase(channelId, HIDCommand.CTAPHID_ERROR) {

    override val data: ByteArray = byteArrayOf(errorCode.value)

    override fun toString(): String {
        return "HIDERRORResponseMessage(channelId=${channelId}, command=$command, errorCode=$errorCode)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDERRORResponseMessage) return false
        if (!super.equals(other)) return false

        if (errorCode != other.errorCode) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + errorCode.hashCode()
        return result
    }


}
