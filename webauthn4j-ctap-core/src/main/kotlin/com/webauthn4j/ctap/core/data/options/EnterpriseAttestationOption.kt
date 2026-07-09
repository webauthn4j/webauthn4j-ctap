package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class EnterpriseAttestationOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val ENABLED = EnterpriseAttestationOption(true)

        @JvmField
        val DISABLED = EnterpriseAttestationOption(false)

        @JvmField
        val NOT_SUPPORTED: EnterpriseAttestationOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): EnterpriseAttestationOption? {
            return when {
                value == null -> NOT_SUPPORTED
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
