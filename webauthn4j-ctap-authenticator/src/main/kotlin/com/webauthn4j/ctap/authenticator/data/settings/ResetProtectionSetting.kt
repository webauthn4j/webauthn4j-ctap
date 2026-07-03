package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls whether the authenticator restricts the authenticatorReset command.
 *
 * When [ENABLED], reset is only allowed within a limited time window after power-up,
 * preventing accidental or unauthorized erasure of credentials.
 */
enum class ResetProtectionSetting(val value: Boolean) {
    /** Reset is restricted to a time window after power-up. */
    ENABLED(true),
    /** Reset is allowed at any time. */
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