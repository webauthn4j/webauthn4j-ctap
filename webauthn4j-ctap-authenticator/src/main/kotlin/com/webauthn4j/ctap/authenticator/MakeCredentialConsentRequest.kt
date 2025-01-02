package com.webauthn4j.ctap.authenticator

import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialRpEntity
import com.webauthn4j.ctap.core.data.CtapPublicKeyCredentialUserEntity
import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable

class MakeCredentialConsentRequest : Serializable{

    val applicationParameter: ByteArray
    val rp: CtapPublicKeyCredentialRpEntity? // rp can be null while processing FIDO-U2F request
    val user: CtapPublicKeyCredentialUserEntity? //user can be null while processing FIDO-U2F request
    val isUserPresenceRequired: Boolean
    val isUserVerificationRequired: Boolean

    constructor(
        applicationParameter: ByteArray,
        isUserPresenceRequired: Boolean,
        isUserVerificationRequired: Boolean
    ) {
        this.applicationParameter = applicationParameter
        this.rp = null
        this.user = null
        this.isUserPresenceRequired = isUserPresenceRequired
        this.isUserVerificationRequired = isUserVerificationRequired
    }

    constructor(
        rp: CtapPublicKeyCredentialRpEntity,
        user: CtapPublicKeyCredentialUserEntity?,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rp.id.toByteArray())
        this.applicationParameter = rpIdHash
        this.rp = rp
        this.user = user
        this.isUserPresenceRequired = isUserPresence
        this.isUserVerificationRequired = isUserVerification
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MakeCredentialConsentRequest) return false

        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (rp != other.rp) return false
        if (user != other.user) return false
        if (isUserPresenceRequired != other.isUserPresenceRequired) return false
        if (isUserVerificationRequired != other.isUserVerificationRequired) return false

        return true
    }

    override fun hashCode(): Int {
        var result = applicationParameter.contentHashCode()
        result = 31 * result + (rp?.hashCode() ?: 0)
        result = 31 * result + (user?.hashCode() ?: 0)
        result = 31 * result + isUserPresenceRequired.hashCode()
        result = 31 * result + isUserVerificationRequired.hashCode()
        return result
    }
}
