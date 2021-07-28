package com.webauthn4j.ctap.authenticator.settings

enum class PlatformSetting(val value: String) {
    PLATFORM("platform"),
    CROSS_PLATFORM("cross-platform");

    companion object {
        @JvmStatic
        fun create(value: String): PlatformSetting {
            return when (value) {
                "platform" -> PLATFORM
                "cross-platform" -> CROSS_PLATFORM
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}