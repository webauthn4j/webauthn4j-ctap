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
        val NULL: EnterpriseAttestationOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): EnterpriseAttestationOption? {
            return when {
                value == null -> NULL
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
