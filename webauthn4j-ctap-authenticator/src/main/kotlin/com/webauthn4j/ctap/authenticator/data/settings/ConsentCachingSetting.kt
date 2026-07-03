package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls whether the authenticator caches user consent across operations.
 *
 * When [ENABLED], a previously granted consent may be reused for subsequent operations
 * without prompting the user again, within the consent validity period.
 */
enum class ConsentCachingSetting(val value: Boolean) {
    /** User consent is cached and may be reused. */
    ENABLED(true),
    /** Each operation requires fresh user consent. */
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