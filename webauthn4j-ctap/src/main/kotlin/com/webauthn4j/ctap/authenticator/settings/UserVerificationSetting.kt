package com.webauthn4j.ctap.authenticator.settings

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
}