package com.unifidokey.driver.credentials.provider

import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.unifidokey.driver.converter.jackson.deserializer.json.ByteArraySerializer
import com.unifidokey.driver.converter.jackson.serializer.json.ByteArrayDeserializer
import com.webauthn4j.converter.AttestationObjectConverter
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.AuthenticatorTransport
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput
import com.webauthn4j.util.Base64UrlUtil

class AndroidCredentialsCreateResponse(
    @JsonDeserialize(using= ByteArrayDeserializer::class)
    credentialId: ByteArray,
    val response: AuthenticatorAttestationResponse,
    val authenticatorAttachment: AuthenticatorAttachment,
    val clientExtensionResults: AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput>? = null
) {

    val id: String = Base64UrlUtil.encodeToString(credentialId)
    @JsonSerialize(using= ByteArraySerializer::class)
    val rawId: ByteArray = credentialId
    val type: PublicKeyCredentialType = PublicKeyCredentialType.PUBLIC_KEY

    class AuthenticatorAttestationResponse(
        @JsonDeserialize(using= ByteArrayDeserializer::class)
        clientDataJSON: ByteArray,
        @JsonDeserialize(using= ByteArrayDeserializer::class)
        attestationObject: ByteArray,
        val transports: Set<AuthenticatorTransport>
    ) {
        @JsonSerialize(using= ByteArraySerializer::class)
        val clientDataJSON = clientDataJSON
        @JsonSerialize(using= ByteArraySerializer::class)
        val attestationObject = attestationObject

        val authenticatorData: ByteArray?
            @JsonSerialize(using= ByteArraySerializer::class)
            get() = getAuthenticatorData(ObjectConverter())

        val publicKey: ByteArray?
            @JsonSerialize(using= ByteArraySerializer::class)
            get() = getPublicKey(ObjectConverter())

        val publicKeyAlgorithm: COSEAlgorithmIdentifier?
            get() = getCOSEKey(ObjectConverter()).algorithm

        fun getAuthenticatorData(objectConverter: ObjectConverter?): ByteArray? {
            val attestationObjectConverter = AttestationObjectConverter(objectConverter!!)
            return attestationObjectConverter.extractAuthenticatorData(attestationObject)
        }

        fun getPublicKey(objectConverter: ObjectConverter): ByteArray? {
            return getCOSEKey(objectConverter).publicKey!!.encoded
        }

        fun getPublicKeyAlgorithm(objectConverter: ObjectConverter): COSEAlgorithmIdentifier? {
            return getCOSEKey(objectConverter).algorithm
        }

        private fun getCOSEKey(objectConverter: ObjectConverter): COSEKey {
            val authenticatorDataConverter = AuthenticatorDataConverter(objectConverter)
            val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
            val attestedCredentialDataBytes =
                authenticatorDataConverter.extractAttestedCredentialData(
                    this.getAuthenticatorData(objectConverter)
                )
            val attestedCredentialData =
                attestedCredentialDataConverter.convert(attestedCredentialDataBytes)
            return attestedCredentialData.coseKey
        }


    }
}