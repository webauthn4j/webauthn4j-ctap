package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementRequest

class AuthenticatorCredentialManagementRequestSubCommandParamsSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorCredentialManagementRequest.SubCommandParams>(
        AuthenticatorCredentialManagementRequest.SubCommandParams::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorCredentialManagementRequest.SubCommandParams::rpIDHash),
            FieldSerializationRule(2, AuthenticatorCredentialManagementRequest.SubCommandParams::credentialID),
            FieldSerializationRule(3, AuthenticatorCredentialManagementRequest.SubCommandParams::user)
        )
    )
