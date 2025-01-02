package com.webauthn4j.ctap.authenticator.data.settings

enum class ResetProtectionSetting(val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): ResetProtectionSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}