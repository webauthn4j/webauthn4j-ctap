package com.webauthn4j.ctap.authenticator.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class UserVerificationOption private constructor(@get:JsonValue val value: Boolean) {


    companion object {
        @JvmField
        val READY = UserVerificationOption(true)

        @JvmField
        val NOT_READY = UserVerificationOption(false)

        @JvmField
        val NOT_SUPPORTED: UserVerificationOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): UserVerificationOption? {
            return when {
                value == null -> NOT_SUPPORTED
                value -> READY
                else -> NOT_READY
            }
        }
    }
}