package com.unifidokey.driver.credentials.provider

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.client.challenge.Challenge
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs
import com.webauthn4j.data.extension.client.RegistrationExtensionClientInput

class AndroidCredentialsCreateRequest @JsonCreator constructor(
    @JsonProperty("rp")
    val rp: PublicKeyCredentialRpEntity,
    @JsonProperty("user")
    val user: PublicKeyCredentialUserEntity,
    @JsonProperty("challenge")
    val challenge: Challenge,
    @JsonProperty("pubKeyCredParams")
    val pubKeyCredParams: List<PublicKeyCredentialParameters>,
    @JsonProperty("timeout")
    val timeout: Long? = null,
    @JsonProperty("excludeCredentials")
    val excludeCredentials: List<PublicKeyCredentialDescriptor>? = null,
    @JsonProperty("authenticatorSelection")
    val authenticatorSelection: AuthenticatorSelectionCriteria? = null,
    @JsonProperty("attestation")
    val attestation: AttestationConveyancePreference? = null,
    @JsonProperty("extensions")
    val extensions: AuthenticationExtensionsClientInputs<RegistrationExtensionClientInput>? = null
)
