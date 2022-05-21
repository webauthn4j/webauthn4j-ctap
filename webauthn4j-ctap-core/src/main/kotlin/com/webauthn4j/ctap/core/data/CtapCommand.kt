package com.webauthn4j.ctap.core.data

data class CtapCommand(val value: Byte) {

    companion object {
        val MAKE_CREDENTIAL = CtapCommand(0x01)
        val GET_ASSERTION = CtapCommand(0x02)
        val GET_NEXT_ASSERTION = CtapCommand(0x03)
        val GET_INFO = CtapCommand(0x04)
        val CLIENT_PIN = CtapCommand(0x06)
        val RESET = CtapCommand(0x07)
    }

    override fun toString(): String {
        return when (this) {
            MAKE_CREDENTIAL -> "MAKE_CREDENTIAL"
            GET_ASSERTION -> "GET_ASSERTION"
            GET_NEXT_ASSERTION -> "GET_NEXT_ASSERTION"
            GET_INFO -> "GET_INFO"
            CLIENT_PIN -> "CLIENT_PIN"
            RESET -> "RESET"
            else -> "UNKNOWN_%02X".format(value)
        }
    }

}