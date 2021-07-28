package com.webauthn4j.ctap.core.data.ble

data class BLEFrameError(val value: Byte) {

    companion object {
        @JvmField
        val ERR_INVALID_CMD = BLEFrameError(0x01.toByte())

        @JvmField
        val ERR_INVALID_PAR = BLEFrameError(0x02.toByte())

        @JvmField
        val ERR_INVALID_LEN = BLEFrameError(0x03.toByte())

        @JvmField
        val ERR_INVALID_SEQ = BLEFrameError(0x04.toByte())

        @JvmField
        val ERR_REQ_TIMEOUT = BLEFrameError(0x05.toByte())

        @JvmField
        val ERR_BUSY = BLEFrameError(0x06.toByte())

        @JvmField
        val ERR_OTHER = BLEFrameError(0x7f.toByte())
    }
}