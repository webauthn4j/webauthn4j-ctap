package com.webauthn4j.ctap.core.data
import com.webauthn4j.data.PinProtocolVersion

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorClientPINRequest @JsonCreator constructor(
    @JsonProperty("1") pinProtocol: PinProtocolVersion,
    @JsonProperty("2") subCommand: PinSubCommand,
    @JsonProperty("3") keyAgreement: COSEKey?,
    @JsonProperty("4") pinAuth: ByteArray?,
    @JsonProperty("5") newPinEnc: ByteArray?,
    @JsonProperty("6") pinHashEnc: ByteArray?,
    @JsonProperty("9") permissions: PinUvAuthTokenPermissions?,
    @JsonProperty("10") rpId: String?
) : CtapRequest {

    override val command: CtapCommand = CtapCommand.CLIENT_PIN

    val pinProtocol: PinProtocolVersion = pinProtocol
    val subCommand: PinSubCommand = subCommand
    val keyAgreement: COSEKey? = keyAgreement
    val pinAuth: ByteArray? = ArrayUtil.clone(pinAuth)
        get() = ArrayUtil.clone(field)
    val newPinEnc: ByteArray? = ArrayUtil.clone(newPinEnc)
        get() = ArrayUtil.clone(field)
    val pinHashEnc: ByteArray? = ArrayUtil.clone(pinHashEnc)
        get() = ArrayUtil.clone(field)
    val permissions: PinUvAuthTokenPermissions? = permissions
    val rpId: String? = rpId


    companion object {
        fun createV1GetRetries(): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                PinProtocolVersion.VERSION_1,
                PinSubCommand.GET_PIN_RETRIES,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        fun createV1GetKeyAgreement(): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                PinProtocolVersion.VERSION_1,
                PinSubCommand.GET_KEY_AGREEMENT,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        fun createV1SetPIN(
            keyAgreement: COSEKey?,
            pinAuth: ByteArray?,
            newPinEnc: ByteArray?
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                PinProtocolVersion.VERSION_1,
                PinSubCommand.SET_PIN,
                keyAgreement,
                pinAuth,
                newPinEnc,
                null,
                null,
                null
            )
        }

        fun createV1ChangePIN(
            keyAgreement: COSEKey?,
            pinAuth: ByteArray?,
            newPinEnc: ByteArray?,
            pinHashEnc: ByteArray?
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                PinProtocolVersion.VERSION_1,
                PinSubCommand.CHANGE_PIN,
                keyAgreement,
                pinAuth,
                newPinEnc,
                pinHashEnc,
                null,
                null
            )
        }

        fun createV1getPINToken(
            keyAgreement: COSEKey?,
            pinHashEnc: ByteArray?
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                PinProtocolVersion.VERSION_1,
                PinSubCommand.GET_PIN_TOKEN,
                keyAgreement,
                null,
                null,
                pinHashEnc,
                null,
                null
            )
        }

        fun createGetPinUvAuthTokenUsingPinWithPermissions(
            pinProtocol: PinProtocolVersion,
            keyAgreement: COSEKey?,
            pinHashEnc: ByteArray?,
            permissions: PinUvAuthTokenPermissions,
            rpId: String?
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                pinProtocol,
                PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_PIN_WITH_PERMISSIONS,
                keyAgreement,
                null,
                null,
                pinHashEnc,
                permissions,
                rpId
            )
        }

        fun createGetPinUvAuthTokenUsingUvWithPermissions(
            pinProtocol: PinProtocolVersion,
            keyAgreement: COSEKey?,
            permissions: PinUvAuthTokenPermissions,
            rpId: String?
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                pinProtocol,
                PinSubCommand.GET_PIN_UV_AUTH_TOKEN_USING_UV_WITH_PERMISSIONS,
                keyAgreement,
                null,
                null,
                null,
                permissions,
                rpId
            )
        }

        fun createGetUVRetries(
            pinProtocol: PinProtocolVersion
        ): AuthenticatorClientPINRequest {
            return AuthenticatorClientPINRequest(
                pinProtocol,
                PinSubCommand.GET_UV_RETRIES,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }
    }


    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorClientPINRequest

        if (pinProtocol != other.pinProtocol) return false
        if (subCommand != other.subCommand) return false
        if (keyAgreement != other.keyAgreement) return false

        return true
    }

    override fun hashCode(): Int {
        var result = pinProtocol.hashCode()
        result = 31 * result + subCommand.hashCode()
        result = 31 * result + (keyAgreement?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorClientPINCommand(pinProtocol=$pinProtocol, subCommand=$subCommand, keyAgreement=$keyAgreement, pinAuth=${
            HexUtil.encodeToString(
                pinAuth
            )
        }, newPinEnc=${HexUtil.encodeToString(newPinEnc)}, pinHashEnc=${
            HexUtil.encodeToString(
                pinHashEnc
            )
        }, permissions=$permissions, rpId=$rpId)"
    }

}
