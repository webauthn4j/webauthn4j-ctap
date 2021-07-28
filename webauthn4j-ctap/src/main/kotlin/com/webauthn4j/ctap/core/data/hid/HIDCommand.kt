package com.webauthn4j.ctap.core.data.hid

import kotlin.experimental.and

class HIDCommand {
    companion object {

        const val CMD_BIT = 0b10000000.toByte()

        val CTAPHID_MSG = HIDCommand(0x03)
        val CTAPHID_CBOR = HIDCommand(0x10)
        val CTAPHID_INIT = HIDCommand(0x06)
        val CTAPHID_PING = HIDCommand(0x01)
        val CTAPHID_CANCEL = HIDCommand(0x11)
        val CTAPHID_ERROR = HIDCommand(0x3F)
        val CTAPHID_KEEPALIVE = HIDCommand(0x3B)
        val CTAPHID_WINK = HIDCommand(0x08)
        val CTAPHID_LOCK = HIDCommand(0x04)
    }

    constructor(value: Byte) {
        require((value and CMD_BIT) != CMD_BIT) { "It seems raw command byte is provided as bit 7 is set. As as HID command, bit 7 must be masked out." }
        this.value = value
    }

    val value: Byte

    override fun toString(): String {
        return when (this) {
            CTAPHID_MSG -> "CTAPHID_MSG"
            CTAPHID_CBOR -> "CTAPHID_CBOR"
            CTAPHID_INIT -> "CTAPHID_INIT"
            CTAPHID_PING -> "CTAPHID_PING"
            CTAPHID_CANCEL -> "CTAPHID_CANCEL"
            CTAPHID_ERROR -> "CTAPHID_ERROR"
            CTAPHID_KEEPALIVE -> "CTAPHID_KEEPALIVE"
            CTAPHID_WINK -> "CTAPHID_WINK"
            CTAPHID_LOCK -> "CTAPHID_LOCK"
            else -> String.format("UNKNOWN_%02X", value)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HIDCommand) return false

        if (value != other.value) return false

        return true
    }

    override fun hashCode(): Int {
        return value.hashCode()
    }


}