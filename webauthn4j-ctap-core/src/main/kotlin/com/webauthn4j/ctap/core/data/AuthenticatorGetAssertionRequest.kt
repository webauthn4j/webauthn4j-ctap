package com.webauthn4j.ctap.core.data
import com.webauthn4j.data.PinProtocolVersion

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.core.util.internal.HexUtil
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionAuthenticatorInput
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorInputs
import com.webauthn4j.util.ArrayUtil

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorGetAssertionRequest(
    @JsonProperty("1") rpId: String,
    @JsonProperty("2") clientDataHash: ByteArray,
    @JsonProperty("3") allowList: List<PublicKeyCredentialDescriptor>?,
    @JsonProperty("4") extensions: AuthenticationExtensionsAuthenticatorInputs<AuthenticationExtensionAuthenticatorInput>?,
    @JsonProperty("5") options: Options?,
    @JsonProperty("6") pinUvAuthParam: ByteArray?,
    @JsonProperty("7") pinUvAuthProtocol: PinProtocolVersion?
) : CtapRequest {

    override val command: CtapCommand = CtapCommand.GET_ASSERTION

    val rpId = rpId
    val clientDataHash: ByteArray = ArrayUtil.clone(clientDataHash)
        get() = ArrayUtil.clone(field)
    val allowList = allowList?.toList()
    val extensions = extensions
    val options = options
    val pinUvAuthParam: ByteArray? = ArrayUtil.clone(pinUvAuthParam)
        get() = ArrayUtil.clone(field)
    val pinUvAuthProtocol = pinUvAuthProtocol

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetAssertionRequest

        if (rpId != other.rpId) return false
        if (allowList != other.allowList) return false
        if (extensions != other.extensions) return false
        if (options != other.options) return false
        if (pinUvAuthProtocol != other.pinUvAuthProtocol) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + (allowList?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + (options?.hashCode() ?: 0)
        result = 31 * result + (pinUvAuthProtocol?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorGetAssertionCommand(rpId='$rpId', clientDataHash=${
            HexUtil.encodeToString(
                clientDataHash
            )
        }, allowList=$allowList, extensions=$extensions, options=$options, pinUvAuthParam=${
            HexUtil.encodeToString(
                pinUvAuthParam
            )
        }, pinUvAuthProtocol=$pinUvAuthProtocol)"
    }


    class Options @JsonCreator constructor(
        @param:JsonProperty("rk") rk: Boolean?,
        @param:JsonProperty("up") val up: Boolean?,
        @param:JsonProperty("uv") val uv: Boolean?
    ) {
        // Not a valid GetAssertion option; detected for Step 4.4 rejection (CTAP2_ERR_UNSUPPORTED_OPTION).
        val rk: Boolean? = rk

        constructor(up: Boolean?, uv: Boolean?) : this(null, up, uv)

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Options

            if (up != other.up) return false
            if (uv != other.uv) return false

            return true
        }

        override fun hashCode(): Int {
            var result = up.hashCode()
            result = 31 * result + uv.hashCode()
            return result
        }
    }


}