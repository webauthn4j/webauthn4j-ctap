package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorLargeBlobsResponseData

class AuthenticatorLargeBlobsResponseDataSerializer : AbstractCtapCanonicalCborSerializer<AuthenticatorLargeBlobsResponseData>(
    AuthenticatorLargeBlobsResponseData::class.java, listOf(
        FieldSerializationRule(1, AuthenticatorLargeBlobsResponseData::config)
    )
)
