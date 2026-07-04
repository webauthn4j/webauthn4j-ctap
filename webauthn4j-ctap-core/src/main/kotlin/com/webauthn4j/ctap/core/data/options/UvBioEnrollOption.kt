package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class UvBioEnrollOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = UvBioEnrollOption(true)

        @JvmField
        val NOT_SUPPORTED = UvBioEnrollOption(false)

        @JvmField
        val NULL: UvBioEnrollOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): UvBioEnrollOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
