package com.webauthn4j.ctap.core.data

import com.webauthn4j.ctap.core.data.nfc.ResponseAPDU

class U2FStatusCode(val sw1: Byte, val sw2: Byte) {

    @Suppress("MemberVisibilityCanBePrivate")
    companion object {

        @JvmField
        val NO_ERROR = U2FStatusCode(0x90.toByte(), 0x00.toByte())
        val CONDITION_NOT_SATISFIED = U2FStatusCode(0x69.toByte(), 0x85.toByte())
        val WRONG_DATA = U2FStatusCode(0x6A.toByte(), 0x80.toByte())
        val WRONG_LENGTH = U2FStatusCode(0x67.toByte(), 0x00.toByte())
        val CLA_NOT_SUPPORTED = U2FStatusCode(0x6E.toByte(), 0x00.toByte())
        val INS_NOT_SUPPORTED = U2FStatusCode(0x6D.toByte(), 0x00.toByte())

        private val map: Map<U2FStatusCode, String>

        init {
            val tmp: MutableMap<U2FStatusCode, String> = HashMap()
            tmp[NO_ERROR] = "NO_ERROR"
            tmp[CONDITION_NOT_SATISFIED] = "CONDITION_NOT_SATISFIED"
            tmp[WRONG_DATA] = "WRONG_DATA"
            tmp[WRONG_LENGTH] = "WRONG_LENGTH"
            tmp[CLA_NOT_SUPPORTED] = "CLA_NOT_SUPPORTED"
            tmp[INS_NOT_SUPPORTED] = "INS_NOT_SUPPORTED"
            map = HashMap(tmp)
        }

        @JvmStatic
        fun create(value: String?): U2FStatusCode {
            return when (value) {
                "NO_ERROR" -> NO_ERROR
                "CONDITION_NOT_SATISFIED" -> CONDITION_NOT_SATISFIED
                "WRONG_DATA" -> WRONG_DATA
                "WRONG_LENGTH" -> WRONG_LENGTH
                "CLA_NOT_SUPPORTED" -> CLA_NOT_SUPPORTED
                "INS_NOT_SUPPORTED" -> INS_NOT_SUPPORTED

                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }

    fun toResponseAPDU(): ResponseAPDU {
        return ResponseAPDU(sw1, sw2)
    }

}