package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorConfigRequest

class AuthenticatorConfigRequestSubCommandParamsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorConfigRequest.SubCommandParams>(
        AuthenticatorConfigRequest.SubCommandParams::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorConfigRequest.SubCommandParams::newMinPINLength),
            FieldSerializationRule(2, AuthenticatorConfigRequest.SubCommandParams::minPinLengthRPIDs),
            FieldSerializationRule(3, AuthenticatorConfigRequest.SubCommandParams::forceChangePin)
        )
    )
