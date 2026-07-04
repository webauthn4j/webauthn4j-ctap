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
            FieldSerializationRule(6, AuthenticatorGetInfoResponseData::pinUvAuthProtocols),
            FieldSerializationRule(7, AuthenticatorGetInfoResponseData::maxCredentialCountInList),
            FieldSerializationRule(8, AuthenticatorGetInfoResponseData::maxCredentialIdLength),
            FieldSerializationRule(9, AuthenticatorGetInfoResponseData::transports),
            FieldSerializationRule(10, AuthenticatorGetInfoResponseData::algorithms),
            FieldSerializationRule(11, AuthenticatorGetInfoResponseData::maxSerializedLargeBlobArray),
            FieldSerializationRule(12, AuthenticatorGetInfoResponseData::forcePINChange),
            FieldSerializationRule(13, AuthenticatorGetInfoResponseData::minPINLength),
            FieldSerializationRule(14, AuthenticatorGetInfoResponseData::firmwareVersion),
            FieldSerializationRule(15, AuthenticatorGetInfoResponseData::maxCredBlobLength),
            FieldSerializationRule(16, AuthenticatorGetInfoResponseData::maxRPIDsForSetMinPINLength),
            FieldSerializationRule(17, AuthenticatorGetInfoResponseData::preferredPlatformUvAttempts),
            FieldSerializationRule(18, AuthenticatorGetInfoResponseData::uvModality),
            FieldSerializationRule(19, AuthenticatorGetInfoResponseData::certifications),
            FieldSerializationRule(20, AuthenticatorGetInfoResponseData::remainingDiscoverableCredentials),
            FieldSerializationRule(21, AuthenticatorGetInfoResponseData::vendorPrototypeConfigCommands),
            FieldSerializationRule(22, AuthenticatorGetInfoResponseData::attestationFormats),
            FieldSerializationRule(23, AuthenticatorGetInfoResponseData::uvCountSinceLastPinEntry),
            FieldSerializationRule(24, AuthenticatorGetInfoResponseData::longTouchForReset),
            FieldSerializationRule(25, AuthenticatorGetInfoResponseData::encIdentifier),
            FieldSerializationRule(26, AuthenticatorGetInfoResponseData::transportsForReset),
            FieldSerializationRule(27, AuthenticatorGetInfoResponseData::pinComplexityPolicy),
            FieldSerializationRule(28, AuthenticatorGetInfoResponseData::pinComplexityPolicyURL),
            FieldSerializationRule(29, AuthenticatorGetInfoResponseData::maxPINLength),
            FieldSerializationRule(30, AuthenticatorGetInfoResponseData::encCredStoreState),
            FieldSerializationRule(31, AuthenticatorGetInfoResponseData::authenticatorConfigCommands)
        )
    )
