package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class PerCredMgmtROOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = PerCredMgmtROOption(true)

        @JvmField
        val NOT_SUPPORTED = PerCredMgmtROOption(false)

        @JvmField
        val NULL: PerCredMgmtROOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): PerCredMgmtROOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
