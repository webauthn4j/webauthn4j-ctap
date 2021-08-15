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
            AuthenticatorClientPINCommandSerializer()
        )
        this.addSerializer(
            AuthenticatorClientPINResponseData::class.java,
            AuthenticatorClientPINResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionRequest::class.java,
            AuthenticatorGetAssertionCommandSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionRequest.Options::class.java,
            AuthenticatorGetAssertionCommandOptionsSerializer()
        )
        this.addSerializer(
            AuthenticatorGetAssertionResponseData::class.java,
            AuthenticatorGetAssertionResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorGetInfoRequest::class.java,
            AuthenticatorGetInfoCommandSerializer()
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
            AuthenticatorGetNextAssertionCommandSerializer()
        )
        this.addSerializer(
            AuthenticatorGetNextAssertionResponseData::class.java,
            AuthenticatorGetNextAssertionResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialRequest::class.java,
            AuthenticatorMakeCredentialCommandSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialRequest.Options::class.java,
            AuthenticatorMakeCredentialCommandOptionsSerializer()
        )
        this.addSerializer(
            AuthenticatorMakeCredentialResponseData::class.java,
            AuthenticatorMakeCredentialResponseDataSerializer()
        )
        this.addSerializer(
            AuthenticatorResetRequest::class.java,
            AuthenticatorResetCommandSerializer()
        )
        this.addSerializer(
            AuthenticatorResetResponseData::class.java,
            AuthenticatorResetResponseDataSerializer()
        )
        this.addSerializer(U2FKeyEnvelope::class.java, U2FKeyEnvelopeSerializer())
        addDeserializer(ClientPINOption::class.java, ClientPINOptionDeserializer())
        addDeserializer(PlatformOption::class.java, PlatformOptionDeserializer())
        addDeserializer(ResidentKeyOption::class.java, ResidentKeyOptionDeserializer())
        addDeserializer(UserPresenceOption::class.java, UserPresenceOptionDeserializer())
        addDeserializer(UserVerificationOption::class.java, UserVerificationOptionDeserializer())
    }
}