package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData

class AuthenticatorGetInfoResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorGetInfoResponseData>(
        AuthenticatorGetInfoResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorGetInfoResponseData::versions),
            FieldSerializationRule(2, AuthenticatorGetInfoResponseData::extensions),
            FieldSerializationRule(3, AuthenticatorGetInfoResponseData::aaguid),
            FieldSerializationRule(4, AuthenticatorGetInfoResponseData::options),
            FieldSerializationRule(5, AuthenticatorGetInfoResponseData::maxMsgSize),
            FieldSerializationRule(6, AuthenticatorGetInfoResponseData::pinProtocols)
        )
    )
