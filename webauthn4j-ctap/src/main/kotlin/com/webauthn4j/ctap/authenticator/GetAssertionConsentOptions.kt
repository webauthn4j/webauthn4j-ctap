package com.webauthn4j.ctap.authenticator

import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable

class GetAssertionConsentOptions : Serializable{


    val applicationParameter: ByteArray
    val rpId: String?
    val isUserPresence: Boolean
    val isUserVerification: Boolean

    constructor(
        applicationParameter: ByteArray,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        this.applicationParameter = applicationParameter
        this.rpId = null
        this.isUserPresence = isUserPresence
        this.isUserVerification = isUserVerification
    }

    constructor(
        rpId: String,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rpId.toByteArray())
        this.applicationParameter = rpIdHash
        this.rpId = rpId
        this.isUserPresence = isUserPresence
        this.isUserVerification = isUserVerification
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GetAssertionConsentOptions) return false

        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (rpId != other.rpId) return false
        if (isUserPresence != other.isUserPresence) return false
        if (isUserVerification != other.isUserVerification) return false

        return true
    }

    override fun hashCode(): Int {
        var result = applicationParameter.contentHashCode()
        result = 31 * result + (rpId?.hashCode() ?: 0)
        result = 31 * result + isUserPresence.hashCode()
        result = 31 * result + isUserVerification.hashCode()
        return result
    }
}
