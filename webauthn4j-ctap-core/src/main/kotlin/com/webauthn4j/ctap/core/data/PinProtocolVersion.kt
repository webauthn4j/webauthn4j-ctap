package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

enum class PinProtocolVersion(@get:JsonValue val value: UInt) {

    VERSION_1(1u);

    companion object {

        @JvmStatic
        @JsonCreator
        fun create(value: UInt): PinProtocolVersion {
            return when (value) {
                1u -> VERSION_1
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}