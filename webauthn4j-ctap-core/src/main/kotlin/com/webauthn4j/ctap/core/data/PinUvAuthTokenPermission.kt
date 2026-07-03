package com.webauthn4j.ctap.core.data

// @see <a href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#getPinUvAuthTokenUsingPinWithPermissions">6.5.5.7. Operations to Obtain a pinUvAuthToken</a>
//spec| mc (0x01): This allows the pinUvAuthToken to be used for authenticatorMakeCredential operations with the provided rpId parameter.
//spec| ga (0x02): This allows the pinUvAuthToken to be used for authenticatorGetAssertion operations with the provided rpId parameter.
//spec| cm (0x04): This allows the pinUvAuthToken to be used with the authenticatorCredentialManagement command.
//spec| be (0x08): This allows the pinUvAuthToken to be used with the authenticatorBioEnrollment command.
//spec| lbw (0x10): This allows the pinUvAuthToken to be used with the authenticatorLargeBlobs command.
//spec| acfg (0x20): This allows the pinUvAuthToken to be used with the authenticatorConfig command.
enum class PinUvAuthTokenPermission(val value: Int) {
    MC(0x01),
    GA(0x02),
    CM(0x04),
    BE(0x08),
    LBW(0x10),
    ACFG(0x20);

    companion object {
        fun fromBitfield(bitfield: Int): Set<PinUvAuthTokenPermission> =
            entries.filter { bitfield and it.value != 0 }.toSet()

        fun toBitfield(permissions: Set<PinUvAuthTokenPermission>): Int =
            permissions.fold(0) { acc, p -> acc or p.value }
    }
}
