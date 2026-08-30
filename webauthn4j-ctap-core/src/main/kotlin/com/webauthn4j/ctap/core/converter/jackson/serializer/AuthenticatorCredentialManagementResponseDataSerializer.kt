package com.webauthn4j.ctap.core.converter.jackson.serializer

import com.webauthn4j.ctap.core.data.AuthenticatorCredentialManagementResponseData

class AuthenticatorCredentialManagementResponseDataSerializer :
    AbstractCtapCanonicalCborSerializer<AuthenticatorCredentialManagementResponseData>(
        AuthenticatorCredentialManagementResponseData::class.java, listOf(
            FieldSerializationRule(1, AuthenticatorCredentialManagementResponseData::existingResidentCredentialsCount),
            FieldSerializationRule(2, AuthenticatorCredentialManagementResponseData::maxPossibleRemainingResidentCredentialsCount),
            FieldSerializationRule(3, AuthenticatorCredentialManagementResponseData::rp),
            FieldSerializationRule(4, AuthenticatorCredentialManagementResponseData::rpIDHash),
            FieldSerializationRule(5, AuthenticatorCredentialManagementResponseData::totalRPs),
            FieldSerializationRule(6, AuthenticatorCredentialManagementResponseData::user),
            FieldSerializationRule(7, AuthenticatorCredentialManagementResponseData::credentialID),
            FieldSerializationRule(8, AuthenticatorCredentialManagementResponseData::publicKey),
            FieldSerializationRule(9, AuthenticatorCredentialManagementResponseData::totalCredentials),
            FieldSerializationRule(10, AuthenticatorCredentialManagementResponseData::credProtect)
        )
    )
