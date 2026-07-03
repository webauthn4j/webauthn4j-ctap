package com.webauthn4j.ctap.authenticator.data.settings

enum class AlwaysUvSetting(val value: String) {
    ENABLED("enabled"),
    DISABLED("disabled");

    companion object {
        @JvmStatic
        fun create(value: String): AlwaysUvSetting {
            return when (value) {
                "enabled" -> ENABLED
                "disabled" -> DISABLED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}
