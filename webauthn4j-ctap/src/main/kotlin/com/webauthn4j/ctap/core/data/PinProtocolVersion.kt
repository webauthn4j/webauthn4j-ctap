package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class PinProtocolVersion(@get:JsonValue val value: Int) {

    VERSION_1(1);

    companion object {

        @JvmStatic
        @JsonCreator
        fun create(value: Int): PinProtocolVersion {
            return when (value) {
                1 -> VERSION_1
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}