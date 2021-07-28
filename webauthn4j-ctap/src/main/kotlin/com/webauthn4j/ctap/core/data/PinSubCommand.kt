package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class PinSubCommand(@get:JsonValue val value: Int) {

    GET_PIN_RETRIES(0x01),
    GET_KEY_AGREEMENT(0x02),
    SET_PIN(0x03),
    CHANGE_PIN(0x04),
    GET_PIN_TOKEN(0x05);

    companion object {
        @JvmStatic
        @JsonCreator
        fun create(value: Int): PinSubCommand {
            return when (value) {
                0x01 -> GET_PIN_RETRIES
                0x02 -> GET_KEY_AGREEMENT
                0x03 -> SET_PIN
                0x04 -> CHANGE_PIN
                0x05 -> GET_PIN_TOKEN
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}