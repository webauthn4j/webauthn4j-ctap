package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls whether the authenticator allows the authenticatorReset command.
 *
 * When [ENABLED], the authenticator always rejects reset requests with CTAP2_ERR_OPERATION_DENIED.
 * When [DISABLED], reset clears all stored credentials and state.
 */
enum class ResetProtectionSetting(val value: Boolean) {
    /** Reset is always rejected. */
    ENABLED(true),
    /** Reset is allowed. */
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