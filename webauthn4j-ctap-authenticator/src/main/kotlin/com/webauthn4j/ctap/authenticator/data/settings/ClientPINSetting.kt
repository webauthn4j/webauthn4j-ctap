package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls whether the authenticator supports the clientPin feature.
 *
 * When [ENABLED], the authenticator accepts PIN operations (set, change, getPinToken, etc.).
 * The clientPin option in authenticatorGetInfo reports true/false depending on whether a PIN
 * has actually been configured. When [DISABLED], clientPin is absent from authenticatorGetInfo.
 */
enum class ClientPINSetting(val value: String) {
    /** The authenticator supports the clientPin feature. */
    ENABLED("enabled"),
    /** The authenticator does not support the clientPin feature. */
    DISABLED("disabled");

    companion object {
        @JvmStatic
        fun create(value: String): ClientPINSetting {
            return when (value) {
                "enabled" -> ENABLED
                "disabled" -> DISABLED
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}