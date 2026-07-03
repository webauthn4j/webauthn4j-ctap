package com.webauthn4j.ctap.authenticator.data.settings

/**
 * Controls the alwaysUv option reported in authenticatorGetInfo.
 *
 * When [ENABLED], the authenticator requires user verification for every
 * MakeCredential and GetAssertion operation, regardless of the RP's request.
 * The makeCredUvNotRqd option is treated as false when alwaysUv is enabled.
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-feature-descriptions-alwaysUv">CTAP 2.3 §6.1.2 Step 6, §6.2.2 Step 5</a>
 */
enum class AlwaysUvSetting(val value: Boolean) {
    /** Every operation requires user verification. */
    ENABLED(true),
    /** User verification is required only when requested by the RP or platform. */
    DISABLED(false);

    companion object {
        @JvmStatic
        fun create(value: Boolean): AlwaysUvSetting {
            return when {
                value -> ENABLED
                else -> DISABLED
            }
        }
    }
}
