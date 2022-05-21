package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponseData

class AuthenticatorGetNextAssertionResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetNextAssertionResponseData>(
        AuthenticatorGetNextAssertionResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorGetNextAssertionResponseData::credential),
            FieldSerializationRule(2, AuthenticatorGetNextAssertionResponseData::authData),
            FieldSerializationRule(3, AuthenticatorGetNextAssertionResponseData::signature),
            FieldSerializationRule(4, AuthenticatorGetNextAssertionResponseData::user)
        )
    )
