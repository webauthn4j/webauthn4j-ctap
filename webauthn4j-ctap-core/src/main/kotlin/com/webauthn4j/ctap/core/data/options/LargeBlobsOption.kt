package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class LargeBlobsOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = LargeBlobsOption(true)

        @JvmField
        val NOT_SUPPORTED = LargeBlobsOption(false)

        @JvmField
        val NULL: LargeBlobsOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): LargeBlobsOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
