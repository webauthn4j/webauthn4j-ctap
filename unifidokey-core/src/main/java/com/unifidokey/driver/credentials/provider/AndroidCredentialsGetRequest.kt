package com.unifidokey.driver.credentials.provider

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.client.challenge.Challenge

data class AndroidCredentialsGetRequest @JsonCreator constructor(
    @JsonProperty("challenge")
    val challenge: Challenge,
    @JsonProperty("rpId")
    val rpId: String?,
    @JsonProperty("allowCredentials")
    val allowCredentials: List<PublicKeyCredentialDescriptor>?,
    @JsonProperty("userVerification")
    val userVerification: UserVerificationRequirement?
)
