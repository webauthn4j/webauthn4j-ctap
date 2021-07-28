package com.webauthn4j.ctap.authenticator.store

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.util.ArrayUtil
import java.io.Serializable
import java.time.Instant

/**
 * DTO for encoding [NonResidentUserCredential] into a credentialId
 */
@Suppress("CanBePrimaryConstructorProperty")
class NonResidentUserCredentialSource<T : Serializable?> @JsonCreator constructor(
    @JsonProperty("userCredentialKey") userCredentialKey: NonResidentUserCredentialKey,
    @JsonProperty("userHandle") userHandle: ByteArray?,
    @JsonProperty("username") username: String,
    @JsonProperty("displayName") displayName: String,
    @JsonProperty("rpId") rpId: String,
    @JsonProperty("rpName") rpName: String,
    @JsonProperty("createdAt") createdAt: Instant,
    @JsonProperty("otherUI") otherUI: T
) {

    val userCredentialKey = userCredentialKey
    val userHandle: ByteArray = ArrayUtil.clone(userHandle)
        get() = ArrayUtil.clone(field)
    val username: String = username
    val displayName: String = displayName
    val rpId: String = rpId
    val rpName: String = rpName
    val createdAt: Instant = createdAt
    val otherUI: T = otherUI

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NonResidentUserCredentialSource<*>

        if (userCredentialKey != other.userCredentialKey) return false
        if (!userHandle.contentEquals(other.userHandle)) return false
        if (username != other.username) return false
        if (displayName != other.displayName) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (createdAt != other.createdAt) return false
        if (otherUI != other.otherUI) return false

        return true
    }

    override fun hashCode(): Int {
        var result = userCredentialKey.hashCode()
        result = 31 * result + userHandle.contentHashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + rpName.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (otherUI?.hashCode() ?: 0)
        return result
    }


}