package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorGetNextAssertionResponseData @JsonCreator constructor(
    @JsonProperty("1") credential: PublicKeyCredentialDescriptor?,
    @JsonProperty("2") authData: ByteArray,
    @JsonProperty("3") signature: ByteArray,
    @JsonProperty("4") user: CtapPublicKeyCredentialUserEntity?
) : AssertionResponseData {

    override val credential: PublicKeyCredentialDescriptor? = credential
    override val authData: ByteArray = ArrayUtil.clone(authData)
        get() = ArrayUtil.clone(field)
    override val signature: ByteArray = ArrayUtil.clone(signature)
        get() = ArrayUtil.clone(field)
    override val user: CtapPublicKeyCredentialUserEntity? = user

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetNextAssertionResponseData

        if (credential != other.credential) return false
        if (user != other.user) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credential?.hashCode() ?: 0
        result = 31 * result + (user?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorGetNextAssertionResponseData(credential=$credential, authData=${
            HexUtil.encodeToString(
                authData
            )
        }, signature=${HexUtil.encodeToString(signature)}, user=$user)"
    }


}