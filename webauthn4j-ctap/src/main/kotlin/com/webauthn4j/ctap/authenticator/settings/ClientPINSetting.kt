package com.webauthn4j.ctap.authenticator.settings

enum class ClientPINSetting(val value: String) {
    ENABLED("enabled"),
    DISABLED("disabled");

    companion object {
        @JvmStatic
        fun create(value: String): ClientPINSetting {
            return when (value) {
                "enabled" -> ENABLED
                "disabled" -> DISABLED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}