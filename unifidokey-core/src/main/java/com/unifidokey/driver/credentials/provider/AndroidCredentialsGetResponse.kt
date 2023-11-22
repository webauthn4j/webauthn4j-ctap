package com.unifidokey.driver.credentials.provider

import com.fasterxml.jackson.databind.annotation.JsonDeserialize
import com.fasterxml.jackson.databind.annotation.JsonSerialize
import com.unifidokey.driver.converter.jackson.deserializer.json.ByteArraySerializer
import com.unifidokey.driver.converter.jackson.serializer.json.ByteArrayDeserializer
import com.webauthn4j.data.AuthenticatorAttachment
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs
import com.webauthn4j.util.Base64UrlUtil

class AndroidCredentialsGetResponse(
    @JsonDeserialize(using=ByteArrayDeserializer::class)
    credentialId: ByteArray,
    val response: AuthenticatorAssertionResponse,
    val authenticatorAttachment: AuthenticatorAttachment,
    val clientExtensionResults: AuthenticationExtensionsClientOutputs<AuthenticationExtensionClientOutput>? = null
) {

    val id: String = Base64UrlUtil.encodeToString(credentialId)
    @JsonSerialize(using=ByteArraySerializer::class)
    val rawId: ByteArray = credentialId
    val type: PublicKeyCredentialType = PublicKeyCredentialType.PUBLIC_KEY

    class AuthenticatorAssertionResponse(
        @JsonDeserialize(using = ByteArrayDeserializer::class)
        authenticatorData: ByteArray,
        @JsonDeserialize(using = ByteArrayDeserializer::class)
        signature: ByteArray,
        @JsonDeserialize(using = ByteArrayDeserializer::class)
        userHandle: ByteArray
    ) {
        @JsonSerialize(using = ByteArraySerializer::class)
        val userHandle = userHandle
        @JsonSerialize(using = ByteArraySerializer::class)
        val signature = signature
        @JsonSerialize(using = ByteArraySerializer::class)
        val authenticatorData = authenticatorData
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AuthenticatorAssertionResponse

            if (!authenticatorData.contentEquals(other.authenticatorData)) return false
            if (!signature.contentEquals(other.signature)) return false
            if (!userHandle.contentEquals(other.userHandle)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = authenticatorData.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            result = 31 * result + userHandle.contentHashCode()
            return result
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AndroidCredentialsGetResponse

        if (id != other.id) return false
        if (!rawId.contentEquals(other.rawId)) return false
        if (response != other.response) return false
        if (authenticatorAttachment != other.authenticatorAttachment) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + rawId.contentHashCode()
        result = 31 * result + response.hashCode()
        result = 31 * result + authenticatorAttachment.hashCode()
        return result
    }


}
