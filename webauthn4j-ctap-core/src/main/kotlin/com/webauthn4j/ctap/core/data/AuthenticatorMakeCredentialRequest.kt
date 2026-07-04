package com.webauthn4j.ctap.core.data
import com.webauthn4j.data.PinProtocolVersion

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorInput
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorMakeCredentialRequest @JsonCreator constructor(
    @JsonProperty("1") clientDataHash: ByteArray,
    @JsonProperty("2") rp: CtapPublicKeyCredentialRpEntity,
    @JsonProperty("3") user: CtapPublicKeyCredentialUserEntity,
    @JsonProperty("4") pubKeyCredParams: List<PublicKeyCredentialParameters>,
    @JsonProperty("5") excludeList: List<PublicKeyCredentialDescriptor>?,
    @JsonProperty("6") extensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>?,
    @JsonProperty("7") options: Options?,
    @JsonProperty("8") pinUvAuthParam: ByteArray?,
    @JsonProperty("9") pinUvAuthProtocol: PinProtocolVersion?
    // TODO: enterpriseAttestation (0x0A) - §6.1 "This is an unsigned integer or absent."
    // TODO: attestationFormatsPreference (0x0B) - §6.1 "An ordered list of preferred attestation statement formats."
) : CtapRequest {

    override val command: CtapCommand = CtapCommand.MAKE_CREDENTIAL

    val clientDataHash: ByteArray = clientDataHash
        get() = ArrayUtil.clone(field)
    val rp = rp
    val user = user
    val pubKeyCredParams: List<PublicKeyCredentialParameters> = pubKeyCredParams
        get() = field.toList()
    val excludeList: List<PublicKeyCredentialDescriptor>? = excludeList
        get() = field?.toList()
    val extensions: AuthenticationExtensionsAuthenticatorInputs<RegistrationExtensionAuthenticatorInput>? =
        extensions
    val options: Options? = options
    val pinUvAuthParam: ByteArray? = ArrayUtil.clone(pinUvAuthParam)
        get() = ArrayUtil.clone(field)
    val pinUvAuthProtocol: PinProtocolVersion? = pinUvAuthProtocol

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorMakeCredentialRequest

        if (rp != other.rp) return false
        if (user != other.user) return false
        if (extensions != other.extensions) return false
        if (options != other.options) return false
        if (pinUvAuthProtocol != other.pinUvAuthProtocol) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rp.hashCode()
        result = 31 * result + user.hashCode()
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + (options?.hashCode() ?: 0)
        result = 31 * result + (pinUvAuthProtocol?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorMakeCredentialCommand(clientDataHash=${
            HexUtil.encodeToString(
                clientDataHash
            )
        }, rp=$rp, user=$user, pubKeyCredParams=$pubKeyCredParams, excludeList=$excludeList, extensions=$extensions, options=$options, pinUvAuthParam=${
            HexUtil.encodeToString(
                pinUvAuthParam
            )
        }, pinUvAuthProtocol=$pinUvAuthProtocol)"
    }

    class Options @JsonCreator constructor(
        @param:JsonProperty("rk") val rk: Boolean?,
        @param:JsonProperty("up") val up: Boolean?,
        @param:JsonProperty("uv") val uv: Boolean?
    ) {

        constructor(rk: Boolean?, uv: Boolean?) : this(rk, null, uv)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Options) return false

            if (rk != other.rk) return false
            if (up != other.up) return false
            if (uv != other.uv) return false

            return true
        }

        override fun hashCode(): Int {
            var result = rk?.hashCode() ?: 0
            result = 31 * result + (up?.hashCode() ?: 0)
            result = 31 * result + (uv?.hashCode() ?: 0)
            return result
        }

        override fun toString(): String {
            return "Options(rk=$rk, up=$up, uv=$uv)"
        }
    }

}