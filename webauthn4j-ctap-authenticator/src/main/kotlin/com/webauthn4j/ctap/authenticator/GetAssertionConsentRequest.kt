package com.webauthn4j.ctap.authenticator

import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable

class GetAssertionConsentRequest : Serializable{


    val applicationParameter: ByteArray
    val rpId: String?
    val isUserPresenceRequired: Boolean
    val isUserVerificationRequired: Boolean

    constructor(
        applicationParameter: ByteArray,
        isUserPresenceRequired: Boolean,
        isUserVerificationRequired: Boolean
    ) {
        this.applicationParameter = applicationParameter
        this.rpId = null
        this.isUserPresenceRequired = isUserPresenceRequired
        this.isUserVerificationRequired = isUserVerificationRequired
    }

    constructor(
        rpId: String,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
        this.applicationParameter = rpIdHash
        this.rpId = rpId
        this.isUserPresenceRequired = isUserPresence
        this.isUserVerificationRequired = isUserVerification
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GetAssertionConsentRequest) return false

        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (rpId != other.rpId) return false
        if (isUserPresenceRequired != other.isUserPresenceRequired) return false
        if (isUserVerificationRequired != other.isUserVerificationRequired) return false

        return true
    }

    override fun hashCode(): Int {
        var result = applicationParameter.contentHashCode()
        result = 31 * result + (rpId?.hashCode() ?: 0)
        result = 31 * result + isUserPresenceRequired.hashCode()
        result = 31 * result + isUserVerificationRequired.hashCode()
        return result
    }
}
