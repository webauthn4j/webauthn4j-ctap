package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class AuthenticatorConfigSubCommandEnum(@get:JsonValue val value: UInt) {

    ENABLE_ENTERPRISE_ATTESTATION(0x01u),
    TOGGLE_ALWAYS_UV(0x02u),
    SET_MIN_PIN_LENGTH(0x03u),
    ENABLE_LONG_TOUCH_FOR_RESET(0x04u),
    VENDOR_PROTOTYPE(0xFFu);

    companion object {
        @JvmStatic
        @JsonCreator
        fun create(value: UInt): AuthenticatorConfigSubCommandEnum {
            return when (value) {
                0x01u -> ENABLE_ENTERPRISE_ATTESTATION
                0x02u -> TOGGLE_ALWAYS_UV
                0x03u -> SET_MIN_PIN_LENGTH
                0x04u -> ENABLE_LONG_TOUCH_FOR_RESET
                0xFFu -> VENDOR_PROTOTYPE
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}
