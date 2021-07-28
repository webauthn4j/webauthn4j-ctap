package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

class AuthenticatorGetAssertionCommandSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetAssertionRequest>(
        AuthenticatorGetAssertionRequest::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorGetAssertionRequest::rpId),
            FieldSerializationRule(2, AuthenticatorGetAssertionRequest::clientDataHash),
            FieldSerializationRule(3, AuthenticatorGetAssertionRequest::allowList),
            FieldSerializationRule(4, AuthenticatorGetAssertionRequest::extensions),
            FieldSerializationRule(5, AuthenticatorGetAssertionRequest::options),
            FieldSerializationRule(6, AuthenticatorGetAssertionRequest::pinAuth),
            FieldSerializationRule(7, AuthenticatorGetAssertionRequest::pinProtocol)
        )
    )
