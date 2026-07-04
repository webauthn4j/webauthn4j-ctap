package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class CredMgmtOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = CredMgmtOption(true)

        @JvmField
        val NOT_SUPPORTED = CredMgmtOption(false)

        @JvmField
        val NULL: CredMgmtOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): CredMgmtOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
