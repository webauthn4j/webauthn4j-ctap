package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls how the authenticator handles discoverable (resident) credential storage.
 *
 * Maps to the rk option in authenticatorGetInfo. [ALWAYS] and [IF_REQUIRED] report rk=true;
 * [NEVER] reports rk=false.
 */
enum class ResidentKeySetting(val value: String) {
    /** Always create discoverable credentials, even if the RP does not request rk=true. */
    ALWAYS("always"),
    /** Create discoverable credentials only when the RP requests rk=true. */
    IF_REQUIRED("if-required"),
    /** Never create discoverable credentials; rk=true requests are rejected. */
    NEVER("never");

    companion object {
        @JvmStatic
        fun create(value: String): ResidentKeySetting {
            return when (value) {
                "always" -> ALWAYS
                "if-required" -> IF_REQUIRED
                "never" -> NEVER
                else -> throw IllegalArgumentException("value '$value' is out of range")
            }
        }
    }
}