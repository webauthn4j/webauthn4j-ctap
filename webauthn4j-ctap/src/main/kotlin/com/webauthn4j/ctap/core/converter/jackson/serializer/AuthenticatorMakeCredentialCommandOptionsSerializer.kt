package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

class AuthenticatorMakeCredentialCommandOptionsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorMakeCredentialRequest.Options>(
        AuthenticatorMakeCredentialRequest.Options::class.java, listOf(
            FieldSerializationRule("rk", AuthenticatorMakeCredentialRequest.Options::rk),
            FieldSerializationRule("uv", AuthenticatorMakeCredentialRequest.Options::uv)
        )
    )