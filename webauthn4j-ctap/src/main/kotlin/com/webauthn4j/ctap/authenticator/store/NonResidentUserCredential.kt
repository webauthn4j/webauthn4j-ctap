package com.webauthn4j.ctap.authenticator.store

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import java.io.Serializable
import java.time.Instant

data class NonResidentUserCredential @JsonCreator constructor(
    @JsonProperty("credentialId") override val credentialId: ByteArray,
    @JsonProperty("userCredentialKey") override val userCredentialKey: NonResidentUserCredentialKey,
    @JsonProperty("userHandle") override val userHandle: ByteArray?,
    @JsonProperty("username") override val username: String,
    @JsonProperty("displayName") override val displayName: String,
    @JsonProperty("rpId") override val rpId: String,
    @JsonProperty("rpName") override val rpName: String,
    @JsonProperty("createdAt") override val createdAt: Instant,
    @JsonProperty("otherUI") override val otherUI: Serializable?,
    @JsonProperty("details") override val details: Map<String, String>
) : UserCredential {

    override val counter: Long
        get() = 0
    override val isResidentKey: Boolean
        get() = false

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NonResidentUserCredential) return false

        if (!credentialId.contentEquals(other.credentialId)) return false
        if (userCredentialKey != other.userCredentialKey) return false
        if (userHandle != null) {
            if (other.userHandle == null) return false
            if (!userHandle.contentEquals(other.userHandle)) return false
        } else if (other.userHandle != null) return false
        if (username != other.username) return false
        if (displayName != other.displayName) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (createdAt != other.createdAt) return false
        if (otherUI != other.otherUI) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialId.contentHashCode()
        result = 31 * result + userCredentialKey.hashCode()
        result = 31 * result + (userHandle?.contentHashCode() ?: 0)
        result = 31 * result + username.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + rpName.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (otherUI?.hashCode() ?: 0)
        result = 31 * result + details.hashCode()
        return result
    }


}
