package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest

class AuthenticatorMakeCredentialCommandSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorMakeCredentialRequest>(
        AuthenticatorMakeCredentialRequest::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorMakeCredentialRequest::clientDataHash),
            FieldSerializationRule(2, AuthenticatorMakeCredentialRequest::rp),
            FieldSerializationRule(3, AuthenticatorMakeCredentialRequest::user),
            FieldSerializationRule(4, AuthenticatorMakeCredentialRequest::pubKeyCredParams),
            FieldSerializationRule(5, AuthenticatorMakeCredentialRequest::excludeList),
            FieldSerializationRule(6, AuthenticatorMakeCredentialRequest::extensions),
            FieldSerializationRule(7, AuthenticatorMakeCredentialRequest::options),
            FieldSerializationRule(8, AuthenticatorMakeCredentialRequest::pinAuth),
            FieldSerializationRule(9, AuthenticatorMakeCredentialRequest::pinProtocol)
        )
    )
