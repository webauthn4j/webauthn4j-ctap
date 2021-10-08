package com.webauthn4j.ctap.authenticator.data.settings

enum class UserPresenceSetting(val value: String) {
    SUPPORTED("supported"),
    NOT_SUPPORTED("not-supported");

    companion object {
        @JvmStatic
        fun create(value: String): UserPresenceSetting {
            return when (value) {
                "supported" -> SUPPORTED
                "not-supported" -> NOT_SUPPORTED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}