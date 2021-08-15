package com.webauthn4j.ctap.authenticator

import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.util.MessageDigestUtil
import java.io.Serializable

class MakeCredentialConsentOptions : Serializable{

    val applicationParameter: ByteArray
    val rp: PublicKeyCredentialRpEntity?
    val user: PublicKeyCredentialUserEntity?
    val isUserPresence: Boolean
    val isUserVerification: Boolean

    constructor(
        applicationParameter: ByteArray,
        user: PublicKeyCredentialUserEntity?,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        this.applicationParameter = applicationParameter
        this.rp = null
        this.user = user
        this.isUserPresence = isUserPresence
        this.isUserVerification = isUserVerification
    }

    constructor(
        rp: PublicKeyCredentialRpEntity,
        user: PublicKeyCredentialUserEntity?,
        isUserPresence: Boolean,
        isUserVerification: Boolean
    ) {
        val rpIdHash = MessageDigestUtil.createSHA256().digest(rp.id!!.toByteArray())
        this.applicationParameter = rpIdHash
        this.rp = rp
        this.user = user
        this.isUserPresence = isUserPresence
        this.isUserVerification = isUserVerification
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MakeCredentialConsentOptions) return false

        if (!applicationParameter.contentEquals(other.applicationParameter)) return false
        if (rp != other.rp) return false
        if (user != other.user) return false
        if (isUserPresence != other.isUserPresence) return false
        if (isUserVerification != other.isUserVerification) return false

        return true
    }

    override fun hashCode(): Int {
        var result = applicationParameter.contentHashCode()
        result = 31 * result + (rp?.hashCode() ?: 0)
        result = 31 * result + (user?.hashCode() ?: 0)
        result = 31 * result + isUserPresence.hashCode()
        result = 31 * result + isUserVerification.hashCode()
        return result
    }
}
