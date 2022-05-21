package com.webauthn4j.ctap.core.data.hid

class HIDLOCKRequestMessage : HIDRequestMessage, HIDMessageBase {

    constructor(channelId: HIDChannelId, seconds: Byte) : super(
        channelId,
        HIDCommand.CTAPHID_LOCK
    ) {
        this.seconds = seconds
    }

    var seconds: Byte
        private set

    override val data: ByteArray
        get() = byteArrayOf(seconds)

    override fun toString(): String {
        return "HIDLOCKRequestMessage(channelId=${channelId}, command=$command, seconds=${seconds})"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDLOCKRequestMessage) return false
        if (!super.equals(other)) return false

        if (seconds != other.seconds) return false

        return true
    }

    override fun hashCode(): Int {
        var result = super.hashCode()
        result = 31 * result + seconds
        return result
    }


}