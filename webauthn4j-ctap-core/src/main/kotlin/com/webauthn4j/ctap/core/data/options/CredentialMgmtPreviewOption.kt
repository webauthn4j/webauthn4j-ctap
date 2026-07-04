package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class CredentialMgmtPreviewOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = CredentialMgmtPreviewOption(true)

        @JvmField
        val NOT_SUPPORTED = CredentialMgmtPreviewOption(false)

        @JvmField
        val NULL: CredentialMgmtPreviewOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): CredentialMgmtPreviewOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}
