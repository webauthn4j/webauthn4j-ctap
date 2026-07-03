package com.webauthn4j.ctap.authenticator.data.settings

enum class AlwaysUvSetting(val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): AlwaysUvSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
