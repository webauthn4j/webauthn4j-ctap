package com.webauthn4j.ctap.authenticator.store

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable
import java.time.Instant

class ResidentUserCredential @JsonCreator constructor(
    @JsonProperty("id") val id: ByteArray,
    @JsonProperty("userCredentialKey") override val userCredentialKey: ResidentUserCredentialKey,
    @JsonProperty("userHandle") override val userHandle: ByteArray,
    @JsonProperty("username") override val username: String,
    @JsonProperty("displayName") override val displayName: String,
    @JsonProperty("rpId") override val rpId: String,
    @JsonProperty("rpName") override val rpName: String,
    @JsonProperty("counter") override var counter: Long,
    @JsonProperty("createdAt") override val createdAt: Instant,
    @JsonProperty("otherUI") override val otherUI: Serializable?,
    @JsonProperty("details") override val details: Map<String, String>
) : UserCredential {

    override val credentialId: ByteArray
        get() = id
    override val isResidentKey: Boolean
        get() = true

}