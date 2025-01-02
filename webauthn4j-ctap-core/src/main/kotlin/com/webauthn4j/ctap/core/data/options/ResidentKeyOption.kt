package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonValue

data class ResidentKeyOption constructor(@get:JsonValue val value: Boolean) {


    companion object {
        @JvmField
        val SUPPORTED = ResidentKeyOption(true)

        @JvmField
        val NOT_SUPPORTED = ResidentKeyOption(false)

        @JvmField
        val NULL: ResidentKeyOption? = null

        @JvmStatic
        fun create(value: Boolean?): ResidentKeyOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}