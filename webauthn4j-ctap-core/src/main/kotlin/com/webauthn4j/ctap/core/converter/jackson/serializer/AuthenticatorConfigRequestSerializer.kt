package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorConfigRequest

class AuthenticatorConfigRequestSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorConfigRequest>(
        AuthenticatorConfigRequest::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorConfigRequest::subCommand),
            FieldSerializationRule(2, AuthenticatorConfigRequest::subCommandParams),
            FieldSerializationRule(3, AuthenticatorConfigRequest::pinUvAuthProtocol),
            FieldSerializationRule(4, AuthenticatorConfigRequest::pinUvAuthParam)
        )
    )
