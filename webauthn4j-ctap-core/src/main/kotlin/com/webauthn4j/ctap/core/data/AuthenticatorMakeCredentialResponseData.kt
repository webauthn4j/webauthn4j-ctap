package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.webauthn4j.data.attestation.AttestationObject
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.statement.AttestationStatement
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput

class AuthenticatorMakeCredentialResponseData : CtapResponseData {
    //~ Instance fields ================================================================================================
    val authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput>

    @JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME,
        include = JsonTypeInfo.As.EXTERNAL_PROPERTY,
        property = "1"
    )
    val attestationStatement: AttestationStatement

    @JsonCreator
    constructor(
        @JsonProperty("2") authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput>,
        @JsonProperty("3") attestationStatement: AttestationStatement
    ) {
        this.authenticatorData = authenticatorData
        this.attestationStatement = attestationStatement
    }

    constructor(attestationObject: AttestationObject) {
        authenticatorData = attestationObject.authenticatorData
        attestationStatement = attestationObject.attestationStatement
    }

    val format: String
        get() = attestationStatement.format

    @get:JsonIgnore
    val attestationObject: AttestationObject
        get() = AttestationObject(authenticatorData, attestationStatement)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorMakeCredentialResponseData

        if (authenticatorData != other.authenticatorData) return false
        if (attestationStatement != other.attestationStatement) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authenticatorData.hashCode()
        result = 31 * result + attestationStatement.hashCode()
        return result
    }

    override fun toString(): String {
        return "AuthenticatorMakeCredentialResponseData(authenticatorData=$authenticatorData, attestationStatement=$attestationStatement, format='$format', attestationObject=$attestationObject)"
    }


}