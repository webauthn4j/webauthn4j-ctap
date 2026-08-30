package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorConfigRequest @JsonCreator constructor(
    @JsonProperty("1") subCommand: AuthenticatorConfigSubCommandEnum,
    @JsonProperty("2") subCommandParams: SubCommandParams?,
    @JsonProperty("3") pinUvAuthProtocol: PinProtocolVersion?,
    @JsonProperty("4") pinUvAuthParam: ByteArray?
) : CtapRequest {

    override val command: CtapCommand = CtapCommand.AUTHENTICATOR_CONFIG

    val subCommand: AuthenticatorConfigSubCommandEnum = subCommand
    val subCommandParams: SubCommandParams? = subCommandParams
    val pinUvAuthProtocol: PinProtocolVersion? = pinUvAuthProtocol
    val pinUvAuthParam: ByteArray? = ArrayUtil.clone(pinUvAuthParam)
        get() = ArrayUtil.clone(field)

    // SubCommandParams for authenticatorConfig
    class SubCommandParams @JsonCreator constructor(
        @JsonProperty("1") val newMinPINLength: Long?,
        @JsonProperty("2") val minPinLengthRPIDs: List<String>?,
        @JsonProperty("3") val forceChangePin: Boolean?
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as SubCommandParams

            if (newMinPINLength != other.newMinPINLength) return false
            if (minPinLengthRPIDs != other.minPinLengthRPIDs) return false
            if (forceChangePin != other.forceChangePin) return false

            return true
        }

        override fun hashCode(): Int {
            var result = newMinPINLength?.hashCode() ?: 0
            result = 31 * result + (minPinLengthRPIDs?.hashCode() ?: 0)
            result = 31 * result + (forceChangePin?.hashCode() ?: 0)
            return result
        }

        override fun toString(): String {
            return "SubCommandParams(newMinPINLength=$newMinPINLength, minPinLengthRPIDs=$minPinLengthRPIDs, forceChangePin=$forceChangePin)"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorConfigRequest

        if (subCommand != other.subCommand) return false
        if (subCommandParams != other.subCommandParams) return false
        if (pinUvAuthProtocol != other.pinUvAuthProtocol) return false
        if (pinUvAuthParam != null) {
            if (other.pinUvAuthParam == null) return false
            if (!pinUvAuthParam.contentEquals(other.pinUvAuthParam)) return false
        } else if (other.pinUvAuthParam != null) return false

        return true
    }

    override fun hashCode(): Int {
        var result = subCommand.hashCode()
        result = 31 * result + (subCommandParams?.hashCode() ?: 0)
        result = 31 * result + (pinUvAuthProtocol?.hashCode() ?: 0)
        result = 31 * result + (pinUvAuthParam?.contentHashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorConfigRequest(subCommand=$subCommand, subCommandParams=$subCommandParams, pinUvAuthProtocol=$pinUvAuthProtocol, pinUvAuthParam=${HexUtil.encodeToString(pinUvAuthParam)})"
    }
}
