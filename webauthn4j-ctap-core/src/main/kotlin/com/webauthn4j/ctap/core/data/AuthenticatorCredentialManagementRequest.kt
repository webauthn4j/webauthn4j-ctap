package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PinProtocolVersion
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorCredentialManagementRequest @JsonCreator constructor(
    @JsonProperty("1") subCommand: CredentialManagementSubCommand,
    @JsonProperty("2") subCommandParams: SubCommandParams?,
    @JsonProperty("3") pinUvAuthProtocol: PinProtocolVersion?,
    @JsonProperty("4") pinUvAuthParam: ByteArray?
) : CtapRequest {

    override val command: CtapCommand = CtapCommand.CREDENTIAL_MANAGEMENT

    val subCommand: CredentialManagementSubCommand = subCommand
    val subCommandParams: SubCommandParams? = subCommandParams
    val pinUvAuthProtocol: PinProtocolVersion? = pinUvAuthProtocol
    val pinUvAuthParam: ByteArray? = ArrayUtil.clone(pinUvAuthParam)
        get() = ArrayUtil.clone(field)

    @Suppress("CanBePrimaryConstructorProperty")
    class SubCommandParams @JsonCreator constructor(
        @JsonProperty("1") rpIDHash: ByteArray?,
        @JsonProperty("2") credentialID: PublicKeyCredentialDescriptor?,
        @JsonProperty("3") user: PublicKeyCredentialUserEntity?
    ) {

        val rpIDHash: ByteArray? = ArrayUtil.clone(rpIDHash)
            get() = ArrayUtil.clone(field)
        val credentialID: PublicKeyCredentialDescriptor? = credentialID
        val user: PublicKeyCredentialUserEntity? = user

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as SubCommandParams

            if (rpIDHash != null) {
                if (other.rpIDHash == null) return false
                if (!rpIDHash.contentEquals(other.rpIDHash)) return false
            } else if (other.rpIDHash != null) return false
            if (credentialID != other.credentialID) return false
            if (user != other.user) return false

            return true
        }

        override fun hashCode(): Int {
            var result = rpIDHash?.contentHashCode() ?: 0
            result = 31 * result + (credentialID?.hashCode() ?: 0)
            result = 31 * result + (user?.hashCode() ?: 0)
            return result
        }

        override fun toString(): String {
            return "SubCommandParams(rpIDHash=${HexUtil.encodeToString(rpIDHash)}, credentialID=$credentialID, user=$user)"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorCredentialManagementRequest

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
        return "AuthenticatorCredentialManagementRequest(subCommand=$subCommand, subCommandParams=$subCommandParams, pinUvAuthProtocol=$pinUvAuthProtocol, pinUvAuthParam=${
            HexUtil.encodeToString(pinUvAuthParam)
        })"
    }

}
