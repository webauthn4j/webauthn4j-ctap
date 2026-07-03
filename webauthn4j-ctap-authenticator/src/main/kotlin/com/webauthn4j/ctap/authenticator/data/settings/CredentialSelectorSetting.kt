package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls which entity selects a credential when multiple credentials match a GetAssertion request.
 *
 * When [AUTHENTICATOR], the authenticator's display is used to let the user pick a credential.
 * When [CLIENT_PLATFORM], the full credential list is returned to the platform for selection.
 */
enum class CredentialSelectorSetting(val value: String) {
    /** The authenticator prompts the user to select a credential on its own display. */
    AUTHENTICATOR("authenticator"),
    /** The platform handles credential selection via authenticatorGetNextAssertion. */
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