package com.webauthn4j.ctap.authenticator.data.settings

enum class ConsentCachingSetting(val value: Boolean) {
    ENABLED(true),
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): ConsentCachingSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}