package com.webauthn4j.ctap.core.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.ctap.authenticator.U2FKeyEnvelope
import com.webauthn4j.ctap.authenticator.options.*
import com.webauthn4j.ctap.core.converter.jackson.deserializer.*
import com.webauthn4j.ctap.core.converter.jackson.serializer.*
import com.webauthn4j.ctap.core.data.*

class CtapCBORModule : SimpleModule("WebAuthnCBORModule") {
    init {
        this.addSerializer(
            AuthenticatorClientPINRequest::class.java,
            AuthenticatorClientPINRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorClientPINResponseData::class.java,
            AuthenticatorClientPINResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionRequest::class.java,
            AuthenticatorGetAssertionRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionRequest.Options::class.java,
            AuthenticatorGetAssertionRequestOptionsSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionResponseData::class.java,
            AuthenticatorGetAssertionResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorGetInfoRequest::class.java,
            AuthenticatorGetInfoRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorGetInfoResponseData::class.java,
            AuthenticatorGetInfoResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorGetInfoResponseData.Options::class.java,
            AuthenticatorGetInfoResponseDataOptionsSerializer()
        )
        this.addSerializer(
            AuthenticatorGetNextAssertionRequest::class.java,
            AuthenticatorGetNextAssertionRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorGetNextAssertionResponseData::class.java,
            AuthenticatorGetNextAssertionResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialRequest::class.java,
            AuthenticatorMakeCredentialRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialRequest.Options::class.java,
            AuthenticatorMakeCredentialRequestOptionsSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialResponseData::class.java,
            AuthenticatorMakeCredentialResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorResetRequest::class.java,
            AuthenticatorResetRequestSerializer()
        )
        this.addSerializer(
            AuthenticatorResetResponseData::class.java,
            AuthenticatorResetResponseDataSerializer()
        )
        this.addSerializer(
            CtapPublicKeyCredentialRpEntity::class.java,
            CtapPublicKeyCredentialRpEntitySerializer()
        )
        this.addSerializer(
            CtapPublicKeyCredentialUserEntity::class.java,
            CtapPublicKeyCredentialUserEntitySerializer()
        )
        this.addSerializer(U2FKeyEnvelope::class.java, U2FKeyEnvelopeSerializer())

        this.addDeserializer(String::class.java, CoercionLessStringDeserializer())
        this.addDeserializer(ByteArray::class.java, CoercionLessByteArrayDeserializer())

        this.addDeserializer(ClientPINOption::class.java, ClientPINOptionDeserializer())
        this.addDeserializer(PlatformOption::class.java, PlatformOptionDeserializer())
        this.addDeserializer(ResidentKeyOption::class.java, ResidentKeyOptionDeserializer())
        this.addDeserializer(UserPresenceOption::class.java, UserPresenceOptionDeserializer())
        this.addDeserializer(UserVerificationOption::class.java, UserVerificationOptionDeserializer())
    }
}