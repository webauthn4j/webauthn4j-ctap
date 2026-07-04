package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class AuthnrCfgOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = AuthnrCfgOption(true)

        @JvmField
        val NOT_SUPPORTED = AuthnrCfgOption(false)

        @JvmField
        val NULL: AuthnrCfgOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): AuthnrCfgOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
