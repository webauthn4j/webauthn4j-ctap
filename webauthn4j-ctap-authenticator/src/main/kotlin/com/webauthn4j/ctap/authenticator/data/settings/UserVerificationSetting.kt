package com.webauthn4j.ctap.authenticator.data.settings

import com.webauthn4j.ctap.core.data.options.UserVerificationOption

enum class UserVerificationSetting(val value: String) {
    READY("ready"),
    NOT_READY("not-ready"),
    NOT_SUPPORTED("not-supported");

    companion object {
        @JvmStatic
        fun create(value: String): UserVerificationSetting {
            return when (value) {
                "ready" -> READY
                "not-ready" -> NOT_READY
                "not-supported" -> NOT_SUPPORTED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }

    fun toUserVerificationOption() : UserVerificationOption?{
        return when(this){
            READY -> UserVerificationOption.READY
            NOT_READY -> UserVerificationOption.NOT_READY
            NOT_SUPPORTED -> UserVerificationOption.NOT_SUPPORTED
        }
    }
}