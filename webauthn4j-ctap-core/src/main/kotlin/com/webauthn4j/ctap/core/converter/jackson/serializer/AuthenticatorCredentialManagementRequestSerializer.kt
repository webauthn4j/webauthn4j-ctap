package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementRequest

class AuthenticatorCredentialManagementRequestSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorCredentialManagementRequest>(
        AuthenticatorCredentialManagementRequest::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorCredentialManagementRequest::subCommand),
            FieldSerializationRule(2, AuthenticatorCredentialManagementRequest::subCommandParams),
            FieldSerializationRule(3, AuthenticatorCredentialManagementRequest::pinUvAuthProtocol),
            FieldSerializationRule(4, AuthenticatorCredentialManagementRequest::pinUvAuthParam)
        )
    )
