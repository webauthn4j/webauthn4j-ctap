package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class PinSubCommand(@get:JsonValue val value: UInt) {

    GET_PIN_RETRIES(0x01u),
    GET_KEY_AGREEMENT(0x02u),
    SET_PIN(0x03u),
    CHANGE_PIN(0x04u),
    GET_PIN_TOKEN(0x05u),
    GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS(0x06u),
    GET_UV_RETRIES(0x07u),
    GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS(0x09u);

    companion object {
        @JvmStatic
        @JsonCreator
        fun create(value: UInt): PinSubCommand {
            return when (value) {
                0x01u -> GET_PIN_RETRIES
                0x02u -> GET_KEY_AGREEMENT
                0x03u -> SET_PIN
                0x04u -> CHANGE_PIN
                0x05u -> GET_PIN_TOKEN
                0x06u -> GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS
                0x07u -> GET_UV_RETRIES
                0x09u -> GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}