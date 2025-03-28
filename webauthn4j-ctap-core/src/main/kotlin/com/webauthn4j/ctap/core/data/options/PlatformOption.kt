package com.webauthn4j.ctap.core.data.options

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonValue
import com.webauthn4j.data.AuthenticatorAttachment

data class PlatformOption constructor(@get:JsonValue val value: Boolean) {

    companion object {
        @JvmField
        val PLATFORM = PlatformOption(true)

        @JvmField
        val CROSS_PLATFORM = PlatformOption(false)

        @JvmField
        val NULL: PlatformOption? = null

        @JvmStatic
        @JsonCreator
        fun create(value: Boolean?): PlatformOption? {
            return when {
                value == null -> NULL
                value -> PLATFORM
                else -> CROSS_PLATFORM
            }
        }
    }
}
