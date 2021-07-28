package com.webauthn4j.ctap.core.data.hid

abstract class HIDMessageBase(
    override val channelId: HIDChannelId,
    override val command: HIDCommand
) : HIDMessage {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDMessageBase) return false

        if (channelId != other.channelId) return false
        if (command != other.command) return false

        return true
    }

    override fun hashCode(): Int {
        var result = channelId.hashCode()
        result = 31 * result + command.hashCode()
        return result
    }


}