package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class UvAcfgOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = UvAcfgOption(true)

        @JvmField
        val NOT_SUPPORTED = UvAcfgOption(false)

        @JvmField
        val NULL: UvAcfgOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): UvAcfgOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
