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
    @JsonProperty("3") retries: UInt?,
    @JsonProperty("4") powerCycleState: Boolean?,
    @JsonProperty("5") uvRetries: UInt?
) : CtapResponseData {

    val keyAgreement: COSEKey? = keyAgreement
    val pinToken: ByteArray? = ArrayUtil.clone(pinToken)
        get() = ArrayUtil.clone(field)
    val retries: UInt? = retries
    val powerCycleState: Boolean? = powerCycleState
    val uvRetries: UInt? = uvRetries

    constructor(keyAgreement: COSEKey?, pinToken: ByteArray?, retries: UInt?) : this(keyAgreement, pinToken, retries, null, null)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorClientPINResponseData

        if (keyAgreement != other.keyAgreement) return false
        if (retries != other.retries) return false
        if (powerCycleState != other.powerCycleState) return false
        if (uvRetries != other.uvRetries) return false

        return true
    }

    override fun hashCode(): Int {
        var result = keyAgreement?.hashCode() ?: 0
        result = 31 * result + (retries?.hashCode() ?: 0)
        result = 31 * result + (powerCycleState?.hashCode() ?: 0)
        result = 31 * result + (uvRetries?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorClientPINResponseData(keyAgreement=$keyAgreement, pinToken=${
            HexUtil.encodeToString(pinToken)
        }, retries=$retries, powerCycleState=$powerCycleState, uvRetries=$uvRetries)"
    }


}
