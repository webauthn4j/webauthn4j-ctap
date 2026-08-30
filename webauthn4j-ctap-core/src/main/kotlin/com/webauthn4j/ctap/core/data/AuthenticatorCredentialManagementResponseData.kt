package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorCredentialManagementResponseData @JsonCreator constructor(
    @JsonProperty("1") existingResidentCredentialsCount: UInt?,
    @JsonProperty("2") maxPossibleRemainingResidentCredentialsCount: UInt?,
    @JsonProperty("3") rp: PublicKeyCredentialRpEntity?,
    @JsonProperty("4") rpIDHash: ByteArray?,
    @JsonProperty("5") totalRPs: UInt?,
    @JsonProperty("6") user: PublicKeyCredentialUserEntity?,
    @JsonProperty("7") credentialID: PublicKeyCredentialDescriptor?,
    @JsonProperty("8") publicKey: COSEKey?,
    @JsonProperty("9") totalCredentials: UInt?,
    @JsonProperty("10") credProtect: UInt?
) : CtapResponseData {

    val existingResidentCredentialsCount: UInt? = existingResidentCredentialsCount
    val maxPossibleRemainingResidentCredentialsCount: UInt? = maxPossibleRemainingResidentCredentialsCount
    val rp: PublicKeyCredentialRpEntity? = rp
    val rpIDHash: ByteArray? = ArrayUtil.clone(rpIDHash)
        get() = ArrayUtil.clone(field)
    val totalRPs: UInt? = totalRPs
    val user: PublicKeyCredentialUserEntity? = user
    val credentialID: PublicKeyCredentialDescriptor? = credentialID
    val publicKey: COSEKey? = publicKey
    val totalCredentials: UInt? = totalCredentials
    val credProtect: UInt? = credProtect

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorCredentialManagementResponseData

        if (existingResidentCredentialsCount != other.existingResidentCredentialsCount) return false
        if (maxPossibleRemainingResidentCredentialsCount != other.maxPossibleRemainingResidentCredentialsCount) return false
        if (rp != other.rp) return false
        if (rpIDHash != null) {
            if (other.rpIDHash == null) return false
            if (!rpIDHash.contentEquals(other.rpIDHash)) return false
        } else if (other.rpIDHash != null) return false
        if (totalRPs != other.totalRPs) return false
        if (user != other.user) return false
        if (credentialID != other.credentialID) return false
        if (publicKey != other.publicKey) return false
        if (totalCredentials != other.totalCredentials) return false
        if (credProtect != other.credProtect) return false

        return true
    }

    override fun hashCode(): Int {
        var result = existingResidentCredentialsCount?.hashCode() ?: 0
        result = 31 * result + (maxPossibleRemainingResidentCredentialsCount?.hashCode() ?: 0)
        result = 31 * result + (rp?.hashCode() ?: 0)
        result = 31 * result + (rpIDHash?.contentHashCode() ?: 0)
        result = 31 * result + (totalRPs?.hashCode() ?: 0)
        result = 31 * result + (user?.hashCode() ?: 0)
        result = 31 * result + (credentialID?.hashCode() ?: 0)
        result = 31 * result + (publicKey?.hashCode() ?: 0)
        result = 31 * result + (totalCredentials?.hashCode() ?: 0)
        result = 31 * result + (credProtect?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorCredentialManagementResponseData(existingResidentCredentialsCount=$existingResidentCredentialsCount, maxPossibleRemainingResidentCredentialsCount=$maxPossibleRemainingResidentCredentialsCount, rp=$rp, rpIDHash=${
            HexUtil.encodeToString(rpIDHash)
        }, totalRPs=$totalRPs, user=$user, credentialID=$credentialID, publicKey=$publicKey, totalCredentials=$totalCredentials, credProtect=$credProtect)"
    }

}
