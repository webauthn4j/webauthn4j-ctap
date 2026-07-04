package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class SetMinPINLengthOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = SetMinPINLengthOption(true)

        @JvmField
        val NOT_SUPPORTED = SetMinPINLengthOption(false)

        @JvmField
        val NULL: SetMinPINLengthOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): SetMinPINLengthOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
