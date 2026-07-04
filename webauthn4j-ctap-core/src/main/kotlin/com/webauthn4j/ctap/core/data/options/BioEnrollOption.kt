package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class BioEnrollOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val PROVISIONED = BioEnrollOption(true)

        @JvmField
        val NOT_PROVISIONED = BioEnrollOption(false)

        @JvmField
        val NULL: BioEnrollOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): BioEnrollOption? {
            return when {
                value == null -> NULL
                value -> PROVISIONED
                else -> NOT_PROVISIONED
            }
        }
    }
}
