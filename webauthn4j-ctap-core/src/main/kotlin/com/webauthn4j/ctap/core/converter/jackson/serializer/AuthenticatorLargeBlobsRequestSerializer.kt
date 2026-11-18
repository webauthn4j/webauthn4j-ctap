package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorLargeBlobsRequest

class AuthenticatorLargeBlobsRequestSerializer : AbstractCtapCanonicalCborSerializer<AuthenticatorLargeBlobsRequest>(
    AuthenticatorLargeBlobsRequest::class.java, listOf(
        FieldSerializationRule(1, AuthenticatorLargeBlobsRequest::get),
        FieldSerializationRule(2, AuthenticatorLargeBlobsRequest::set),
        FieldSerializationRule(3, AuthenticatorLargeBlobsRequest::offset),
        FieldSerializationRule(4, AuthenticatorLargeBlobsRequest::length),
        FieldSerializationRule(5, AuthenticatorLargeBlobsRequest::pinUvAuthParam),
        FieldSerializationRule(6, AuthenticatorLargeBlobsRequest::pinUvAuthProtocol)
    )
)
