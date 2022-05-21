package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponseData

class AuthenticatorGetAssertionResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetAssertionResponseData>(
        AuthenticatorGetAssertionResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorGetAssertionResponseData::credential),
            FieldSerializationRule(2, AuthenticatorGetAssertionResponseData::authData),
            FieldSerializationRule(3, AuthenticatorGetAssertionResponseData::signature),
            FieldSerializationRule(4, AuthenticatorGetAssertionResponseData::user),
            FieldSerializationRule(5, AuthenticatorGetAssertionResponseData::numberOfCredentials)
        )
    )
