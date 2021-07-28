package com.webauthn4j.ctap.core.data.hid

data class HIDErrorCode(val value: Byte) {

    companion object {
        val INVALID_CMD = HIDErrorCode(0x01)
        val INVALID_PAR = HIDErrorCode(0x02)
        val INVALID_LEN = HIDErrorCode(0x03)
        val INVALID_SEQ = HIDErrorCode(0x04)
        val MSG_TIMEOUT = HIDErrorCode(0x05)
        val CHANNEL_BUSY = HIDErrorCode(0x06)
        val LOCK_REQUIRED = HIDErrorCode(0x0A)
        val INVALID_CHANNEL = HIDErrorCode(0x0B)
        val OTHER = HIDErrorCode(0x7F)
    }

    override fun toString(): String {
        return when (value) {
            INVALID_CMD.value -> "INVALID_CMD(0x01)"
            INVALID_PAR.value -> "INVALID_CMD(0x02)"
            INVALID_LEN.value -> "INVALID_CMD(0x03)"
            INVALID_SEQ.value -> "INVALID_CMD(0x04)"
            MSG_TIMEOUT.value -> "INVALID_CMD(0x05)"
            CHANNEL_BUSY.value -> "INVALID_CMD(0x06)"
            LOCK_REQUIRED.value -> "INVALID_CMD(0x0A)"
            INVALID_CHANNEL.value -> "INVALID_CMD(0x0B)"
            OTHER.value -> "OTHER(0x7F)"
            else -> "UNKNOWN(0x%02X)".format(value)
        }
    }


}
