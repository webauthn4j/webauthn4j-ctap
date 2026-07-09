package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class MakeCredUvNotRqdOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val UV_NOT_REQUIRED = MakeCredUvNotRqdOption(true)

        @JvmField
        val UV_REQUIRED = MakeCredUvNotRqdOption(false)

        @JvmField
        val NULL: MakeCredUvNotRqdOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): MakeCredUvNotRqdOption? {
            return when {
                value == null -> NULL
                value -> UV_NOT_REQUIRED
                else -> UV_REQUIRED
            }
        }
    }
}
