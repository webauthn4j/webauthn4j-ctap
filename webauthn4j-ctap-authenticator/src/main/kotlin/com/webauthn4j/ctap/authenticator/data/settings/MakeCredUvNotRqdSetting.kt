package com.webauthn4j.ctap.authenticator.data.settings

enum class MakeCredUvNotRqdSetting(val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): MakeCredUvNotRqdSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
