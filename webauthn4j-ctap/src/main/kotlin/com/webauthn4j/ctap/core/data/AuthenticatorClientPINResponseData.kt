package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorClientPINResponseData @JsonCreator constructor(
    @JsonProperty("1") keyAgreement: COSEKey?,
    @JsonProperty("2") pinToken: ByteArray?,
    @JsonProperty("3") retries: UInt?
) : CtapResponseData {

    val keyAgreement: COSEKey? = keyAgreement
    val pinToken: ByteArray? = pinToken
        get() = ArrayUtil.clone(field)
    val retries: UInt? = retries

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorClientPINResponseData

        if (keyAgreement != other.keyAgreement) return false
        if (retries != other.retries) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAgreement?.hashCode() ?: 0
        result = 31 * result + (retries?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorClientPINResponseData(keyAgreement=$keyAgreement, pinToken=${
            HexUtil.encodeToString(pinToken)
        }, retries=$retries)"
    }


}