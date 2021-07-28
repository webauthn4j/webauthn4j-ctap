package com.webauthn4j.ctap.authenticator.settings

enum class CredentialSelectorSetting(val value: String) {
    AUTHENTICATOR("authenticator"),
    CLIENT_PLATFORM("client-platform");

    companion object {
        @JvmStatic
        fun create(value: String): CredentialSelectorSetting {
            return when (value) {
                "authenticator" -> AUTHENTICATOR
                "client-platform" -> CLIENT_PLATFORM
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}