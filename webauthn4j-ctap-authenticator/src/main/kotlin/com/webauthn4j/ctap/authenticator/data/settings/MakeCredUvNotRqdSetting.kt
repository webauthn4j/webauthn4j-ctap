package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls the makeCredUvNotRqd option reported in authenticatorGetInfo.
 *
 * When [UV_NOT_REQUIRED], the authenticator allows creating non-discoverable credentials
 * without user verification. Discoverable credentials (rk=true) still require UV.
 * This option is overridden to false when alwaysUv is enabled.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-feature-descriptions-makeCredUvNotRqd">CTAP 2.3 §6.1.2 Steps 7, 8, 10</a>
 */
enum class MakeCredUvNotRqdSetting(val value: Boolean) {
    /** Non-discoverable credentials can be created without user verification. */
    UV_NOT_REQUIRED(true),
    /** All credentials require user verification when the authenticator is protected. */
    UV_REQUIRED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): MakeCredUvNotRqdSetting {
            return when {
                value -> UV_NOT_REQUIRED
                else -> UV_REQUIRED
            }
        }
    }
}
