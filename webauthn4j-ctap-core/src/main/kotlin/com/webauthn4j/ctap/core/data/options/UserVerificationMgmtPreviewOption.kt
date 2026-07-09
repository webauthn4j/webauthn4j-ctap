package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class UserVerificationMgmtPreviewOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val PROVISIONED = UserVerificationMgmtPreviewOption(true)

        @JvmField
        val NOT_PROVISIONED = UserVerificationMgmtPreviewOption(false)

        @JvmField
        val NOT_SUPPORTED: UserVerificationMgmtPreviewOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): UserVerificationMgmtPreviewOption? {
            return when {
                value == null -> NOT_SUPPORTED
                value -> PROVISIONED
                else -> NOT_PROVISIONED
            }
        }
    }
}
