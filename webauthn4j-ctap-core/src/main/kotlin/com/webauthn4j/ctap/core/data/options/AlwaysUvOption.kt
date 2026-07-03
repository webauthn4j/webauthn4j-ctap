package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class AlwaysUvOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val ENABLED = AlwaysUvOption(true)

        @JvmField
        val DISABLED = AlwaysUvOption(false)

        @JvmField
        val NULL: AlwaysUvOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): AlwaysUvOption? {
            return when {
                value == null -> NULL
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
