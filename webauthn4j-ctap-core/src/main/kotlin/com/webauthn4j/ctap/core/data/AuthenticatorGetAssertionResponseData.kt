package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorGetAssertionResponseData @JsonCreator constructor(
    @JsonProperty("1") credential: PublicKeyCredentialDescriptor?,
    @JsonProperty("2") authData: ByteArray,
    @JsonProperty("3") signature: ByteArray,
    @JsonProperty("4") user: PublicKeyCredentialUserEntity?,
    @JsonProperty("5") numberOfCredentials: Int?,
    @JsonProperty("6") userSelected: Boolean?
    // TODO: largeBlobKey (0x07) - "The contents of the associated largeBlobKey if present for the asserted credential,
    //  and if largeBlobKey was true in the extensions input."
    // TODO: unsignedExtensionOutputs (0x08) - "A map, keyed by extension identifiers, to unsigned outputs of extensions, if any.
    //  Authenticators SHOULD omit this field if no processed extensions define unsigned outputs."
) : CtapResponseData {

    constructor(
        credential: PublicKeyCredentialDescriptor?,
        authData: ByteArray,
        signature: ByteArray,
        user: PublicKeyCredentialUserEntity?,
        numberOfCredentials: Int?
    ) : this(credential, authData, signature, user, numberOfCredentials, null)

    val credential: PublicKeyCredentialDescriptor? = credential
    val authData: ByteArray = ArrayUtil.clone(authData)
        get() = ArrayUtil.clone(field)
    val signature: ByteArray = ArrayUtil.clone(signature)
        get() = ArrayUtil.clone(field)
    val user: PublicKeyCredentialUserEntity? = user
    val numberOfCredentials: Int? = numberOfCredentials
    val userSelected: Boolean? = userSelected

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetAssertionResponseData

        if (credential != other.credential) return false
        if (user != other.user) return false
        if (numberOfCredentials != other.numberOfCredentials) return false
        if (userSelected != other.userSelected) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credential?.hashCode() ?: 0
        result = 31 * result + (user?.hashCode() ?: 0)
        result = 31 * result + (numberOfCredentials ?: 0)
        result = 31 * result + (userSelected?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorGetAssertionResponseData(credential=$credential, authData=${
            HexUtil.encodeToString(
                authData
            )
        }, signature=${HexUtil.encodeToString(signature)}, user=$user, numberOfCredentials=$numberOfCredentials, userSelected=$userSelected)"
    }


}