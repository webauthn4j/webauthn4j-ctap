package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls the up option reported in authenticatorGetInfo.
 *
 * Indicates whether the authenticator can test user presence (e.g., button press, touch).
 */
enum class UserPresenceSetting(val value: String) {
    /** The authenticator supports user presence testing. */
    SUPPORTED("supported"),
    /** The authenticator does not support user presence testing. */
    NOT_SUPPORTED("not-supported");

    companion object {
        @JvmStatic
        fun create(value: String): UserPresenceSetting {
            return when (value) {
                "supported" -> SUPPORTED
                "not-supported" -> NOT_SUPPORTED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}