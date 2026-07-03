package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class MakeCredUvNotRqdOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val ENABLED = MakeCredUvNotRqdOption(true)

        @JvmField
        val DISABLED = MakeCredUvNotRqdOption(false)

        @JvmField
        val NULL: MakeCredUvNotRqdOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): MakeCredUvNotRqdOption? {
            return when {
                value == null -> NULL
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
