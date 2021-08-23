package com.webauthn4j.ctap.authenticator.store

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable
import java.time.Instant

class ResidentUserCredential @JsonCreator constructor(
    @JsonProperty("id") val id: ByteArray,
    @JsonProperty("credentialKey") override val credentialKey: ResidentCredentialKey,
    @JsonProperty("userHandle") override val userHandle: ByteArray,
    @JsonProperty("username") override val username: String?,
    @JsonProperty("displayName") override val displayName: String?,
    @JsonProperty("rpId") override val rpId: String,
    @JsonProperty("rpName") override val rpName: String?,
    @JsonProperty("counter") override var counter: Long,
    @JsonProperty("createdAt") override val createdAt: Instant,
    @JsonProperty("otherUI") override val otherUI: Serializable?,
    @JsonProperty("details") override val details: Map<String, String>
) : UserCredential {

    override val credentialId: ByteArray
        get() = id
    override val rpIdHash: ByteArray
        get() = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
    override val isResidentKey: Boolean
        get() = true

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is ResidentUserCredential) return false

        if (!id.contentEquals(other.id)) return false
        if (credentialKey != other.credentialKey) return false
        if (!userHandle.contentEquals(other.userHandle)) return false
        if (username != other.username) return false
        if (displayName != other.displayName) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (counter != other.counter) return false
        if (createdAt != other.createdAt) return false
        if (otherUI != other.otherUI) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + credentialKey.hashCode()
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + (username?.hashCode() ?: 0)
        result = 31 * result + (displayName?.hashCode() ?: 0)
        result = 31 * result + rpId.hashCode()
        result = 31 * result + (rpName?.hashCode() ?: 0)
        result = 31 * result + counter.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (otherUI?.hashCode() ?: 0)
        result = 31 * result + details.hashCode()
        return result
    }


}