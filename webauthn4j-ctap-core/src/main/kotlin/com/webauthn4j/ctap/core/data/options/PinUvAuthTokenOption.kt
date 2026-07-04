package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class PinUvAuthTokenOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = PinUvAuthTokenOption(true)

        @JvmField
        val NOT_SUPPORTED = PinUvAuthTokenOption(false)

        @JvmField
        val NULL: PinUvAuthTokenOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): PinUvAuthTokenOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
