package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest

class AuthenticatorGetAssertionCommandOptionsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetAssertionRequest.Options>(
        AuthenticatorGetAssertionRequest.Options::class.java, listOf(
            FieldSerializationRule("up", AuthenticatorGetAssertionRequest.Options::up),
            FieldSerializationRule("uv", AuthenticatorGetAssertionRequest.Options::uv)
        )
    )
