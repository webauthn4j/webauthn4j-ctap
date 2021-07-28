package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponseData

class AuthenticatorClientPINResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorClientPINResponseData>(
        AuthenticatorClientPINResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorClientPINResponseData::keyAgreement),
            FieldSerializationRule(2, AuthenticatorClientPINResponseData::pinToken),
            FieldSerializationRule(3, AuthenticatorClientPINResponseData::retries)
        )
    )
