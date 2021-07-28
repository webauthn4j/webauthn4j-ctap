package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest

class AuthenticatorClientPINCommandSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorClientPINRequest>(
        AuthenticatorClientPINRequest::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorClientPINRequest::pinProtocol),
            FieldSerializationRule(2, AuthenticatorClientPINRequest::subCommand),
            FieldSerializationRule(3, AuthenticatorClientPINRequest::keyAgreement),
            FieldSerializationRule(4, AuthenticatorClientPINRequest::pinAuth),
            FieldSerializationRule(5, AuthenticatorClientPINRequest::newPinEnc),
            FieldSerializationRule(6, AuthenticatorClientPINRequest::pinHashEnc)
        )
    )
