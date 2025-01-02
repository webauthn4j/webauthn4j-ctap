package com.webauthn4j.ctap.core.converter.jackson

import com.fasterxml.jackson.databind.module.SimpleModule
import com.webauthn4j.ctap.core.converter.jackson.deserializer.CoercionLessByteArrayDeserializer
import com.webauthn4j.ctap.core.converter.jackson.deserializer.CoercionLessStringDeserializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorClientPINRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorClientPINResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetAssertionRequestOptionsSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetAssertionRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetAssertionResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetInfoRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetInfoResponseDataOptionsSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetInfoResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetNextAssertionRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorGetNextAssertionResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorMakeCredentialRequestOptionsSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorMakeCredentialRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorMakeCredentialResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorResetRequestSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.AuthenticatorResetResponseDataSerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.CtapPublicKeyCredentialRpEntitySerializer
import com.webauthn4j.ctap.core.converter.jackson.serializer.CtapPublicKeyCredentialUserEntitySerializer
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINRequest
import com.webauthn4j.ctap.core.data.AuthenticatorClientPINResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetAssertionResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetInfoResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionRequest
import com.webauthn4j.ctap.core.data.AuthenticatorGetNextAssertionResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialRequest
import com.webauthn4j.ctap.core.data.AuthenticatorMakeCredentialResponseData
import com.webauthn4j.ctap.core.data.AuthenticatorResetRequest
import com.webauthn4j.ctap.core.data.AuthenticatorResetResponseData
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity

class CtapCBORModule : SimpleModule("CtapCBORModule") {
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

        this.addDeserializer(String::class.java, CoercionLessStringDeserializer())
        this.addDeserializer(ByteArray::class.java, CoercionLessByteArrayDeserializer())
    }
}