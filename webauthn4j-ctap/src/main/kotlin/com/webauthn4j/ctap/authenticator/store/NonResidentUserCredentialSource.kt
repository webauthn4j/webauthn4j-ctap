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
class NonResidentUserCredentialSource @JsonCreator constructor(
    @JsonProperty("userCredentialKey") userCredentialKey: NonResidentCredentialKey,
    @JsonProperty("userHandle") userHandle: ByteArray?,
    @JsonProperty("username") username: String?,
    @JsonProperty("displayName") displayName: String?,
    @JsonProperty("icon") icon: String?,
    @JsonProperty("rpId") rpId: String,
    @JsonProperty("rpName") rpName: String?,
    @JsonProperty("rpIcon") rpIcon: String?,
    @JsonProperty("createdAt") createdAt: Instant,
    @JsonProperty("otherUI") otherUI: Serializable?,
    @JsonProperty("details") details: Map<String, String>
) {

    val userCredentialKey = userCredentialKey
    val userHandle: ByteArray = ArrayUtil.clone(userHandle)
        get() = ArrayUtil.clone(field)
    val username: String? = username
    val displayName: String? = displayName
    val icon: String? = icon
    val rpId: String = rpId
    val rpName: String? = rpName
    val rpIcon: String? = rpIcon
    val createdAt: Instant = createdAt
    val otherUI: Serializable? = otherUI
    val details: Map<String, String> = details

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is NonResidentUserCredentialSource) return false
        if (userCredentialKey != other.userCredentialKey) return false
        if (username != other.username) return false
        if (displayName != other.displayName) return false
        if (icon != other.icon) return false
        if (rpId != other.rpId) return false
        if (rpName != other.rpName) return false
        if (rpIcon != other.rpIcon) return false
        if (createdAt != other.createdAt) return false
        if (otherUI != other.otherUI) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = userCredentialKey.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + displayName.hashCode()
        result = 31 * result + icon.hashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + rpName.hashCode()
        result = 31 * result + rpIcon.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + (otherUI?.hashCode() ?: 0)
        result = 31 * result + details.hashCode()
        return result
    }


}