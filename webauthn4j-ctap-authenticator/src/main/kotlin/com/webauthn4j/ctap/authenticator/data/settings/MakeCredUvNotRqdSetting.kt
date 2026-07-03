package com.webauthn4j.ctap.authenticator.data.settings

enum class MakeCredUvNotRqdSetting(val value: String) {
    ENABLED("enabled"),
    DISABLED("disabled");

    companion object {
        @JvmStatic
        fun create(value: String): MakeCredUvNotRqdSetting {
            return when (value) {
                "enabled" -> ENABLED
                "disabled" -> DISABLED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}
