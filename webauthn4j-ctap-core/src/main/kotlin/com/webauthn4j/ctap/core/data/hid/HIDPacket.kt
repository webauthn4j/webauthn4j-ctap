package com.webauthn4j.ctap.core.data.hid

abstract class HIDPacket(val channelId: HIDChannelId) {

    abstract fun toBytes(): ByteArray

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDPacket) return false

        if (channelId != other.channelId) return false

        return true
    }

    override fun hashCode(): Int {
        return channelId.hashCode()
    }


}