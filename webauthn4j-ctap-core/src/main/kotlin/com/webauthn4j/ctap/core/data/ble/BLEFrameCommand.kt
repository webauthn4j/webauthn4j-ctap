package com.webauthn4j.ctap.core.data.ble

data class BLEFrameCommand(val value: Byte) {

    companion object {
        @JvmField
        val PING = BLEFrameCommand(0x81.toByte())

        @JvmField
        val KEEPALIVE = BLEFrameCommand(0x82.toByte())

        @JvmField
        val MSG = BLEFrameCommand(0x83.toByte())

        @JvmField
        val CANCEL = BLEFrameCommand(0xbe.toByte())

        @JvmField
        val ERROR = BLEFrameCommand(0xbf.toByte())
    }
}