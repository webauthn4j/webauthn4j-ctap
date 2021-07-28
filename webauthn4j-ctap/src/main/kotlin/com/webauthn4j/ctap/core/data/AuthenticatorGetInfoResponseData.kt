package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.ctap.authenticator.options.*
import com.webauthn4j.data.attestation.authenticator.AAGUID

@Suppress("CanBePrimaryConstructorProperty")
class AuthenticatorGetInfoResponseData @JsonCreator constructor(
    @JsonProperty("1") versions: List<String>,
    @JsonProperty("2") extensions: List<String>?,
    @JsonProperty("3") aaguid: AAGUID,
    @JsonProperty("4") options: Options?,
    @JsonProperty("5") maxMsgSize: Long?,
    @JsonProperty("6") pinProtocols: List<PinProtocolVersion>?
) : CtapResponseData {

    val versions = versions.toList()
    val extensions = extensions?.toList()
    val aaguid = aaguid
    val options = options
    val maxMsgSize = maxMsgSize
    val pinProtocols = pinProtocols?.toList()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetInfoResponseData

        if (versions != other.versions) return false
        if (extensions != other.extensions) return false
        if (aaguid != other.aaguid) return false
        if (options != other.options) return false
        if (maxMsgSize != other.maxMsgSize) return false
        if (pinProtocols != other.pinProtocols) return false

        return true
    }

    override fun hashCode(): Int {
        var result = versions.hashCode()
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + aaguid.hashCode()
        result = 31 * result + (options?.hashCode() ?: 0)
        result = 31 * result + (maxMsgSize?.hashCode() ?: 0)
        result = 31 * result + (pinProtocols?.hashCode() ?: 0)
        return result
    }

    override fun toString(): String {
        return "AuthenticatorGetInfoResponseData(versions=$versions, extensions=$extensions, aaguid=$aaguid, options=$options, maxMsgSize=$maxMsgSize, pinProtocols=$pinProtocols)"
    }

    class Options @JsonCreator constructor(
        @param:JsonProperty("plat") val plat: PlatformOption?,
        @param:JsonProperty("rk") val rk: ResidentKeyOption?,
        @param:JsonProperty("clientPin") val clientPin: ClientPINOption?,
        @param:JsonProperty("up") val up: UserPresenceOption?,
        @param:JsonProperty("uv") val uv: UserVerificationOption?
    ) {

        override fun toString(): String {
            return "Options(plat=${plat?.value}, rk=${rk?.value}, clientPin=${clientPin?.value}, up=${up?.value}, uv=${uv?.value})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Options

            if (plat != other.plat) return false
            if (rk != other.rk) return false
            if (clientPin != other.clientPin) return false
            if (up != other.up) return false
            if (uv != other.uv) return false

            return true
        }

        override fun hashCode(): Int {
            var result = plat?.hashCode() ?: 0
            result = 31 * result + (rk?.hashCode() ?: 0)
            result = 31 * result + (clientPin?.hashCode() ?: 0)
            result = 31 * result + (up?.hashCode() ?: 0)
            result = 31 * result + (uv?.hashCode() ?: 0)
            return result
        }

    }
}