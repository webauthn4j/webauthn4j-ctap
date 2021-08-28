package com.webauthn4j.ctap.authenticator.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue

data class UserPresenceOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val SUPPORTED = UserPresenceOption(true)

        @JvmField
        val NOT_SUPPORTED = UserPresenceOption(false)

        @JvmField
        val NULL: UserPresenceOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): UserPresenceOption? {
            return when {
                value == null -> NULL
                value -> SUPPORTED
                else -> NOT_SUPPORTED
            }
        }
    }
}