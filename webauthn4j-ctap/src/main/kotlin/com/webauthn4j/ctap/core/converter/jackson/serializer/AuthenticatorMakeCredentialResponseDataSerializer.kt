package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialResponseData

class AuthenticatorMakeCredentialResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorMakeCredentialResponseData>(
        AuthenticatorMakeCredentialResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorMakeCredentialResponseData::format),
            FieldSerializationRule(2, AuthenticatorMakeCredentialResponseData::authenticatorData),
            FieldSerializationRule(3, AuthenticatorMakeCredentialResponseData::attestationStatement)
        )
    )
