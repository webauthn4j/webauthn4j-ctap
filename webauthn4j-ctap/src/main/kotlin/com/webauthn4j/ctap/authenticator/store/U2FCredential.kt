package com.webauthn4j.ctap.authenticator.store

import java.time.Instant

class U2FCredential(
    override val credentialId: ByteArray,
    override val rpIdHash: ByteArray,
    override val credentialKey: CredentialKey,
    override val counter: Long,
    override val createdAt: Instant,
    override val details: Map<String, String>
) : Credential {

    override val isResidentKey: Boolean
        get() = true

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is U2FCredential) return false

        if (!credentialId.contentEquals(other.credentialId)) return false
        if (!rpIdHash.contentEquals(other.rpIdHash)) return false
        if (credentialKey != other.credentialKey) return false
        if (counter != other.counter) return false
        if (createdAt != other.createdAt) return false
        if (details != other.details) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialId.contentHashCode()
        result = 31 * result + rpIdHash.contentHashCode()
        result = 31 * result + credentialKey.hashCode()
        result = 31 * result + counter.hashCode()
        result = 31 * result + createdAt.hashCode()
        result = 31 * result + details.hashCode()
        return result
    }


}