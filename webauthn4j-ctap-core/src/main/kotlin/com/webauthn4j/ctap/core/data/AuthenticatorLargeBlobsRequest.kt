package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.PinProtocolVersion

class AuthenticatorLargeBlobsRequest @JsonCreator constructor(
    @JsonProperty("1") val get: Int?,
    @JsonProperty("2") val set: ByteArray?,
    @JsonProperty("3") val offset: Int?,
    @JsonProperty("4") val length: Int?,
    @JsonProperty("5") val pinUvAuthParam: ByteArray?,
    @JsonProperty("6") val pinUvAuthProtocol: PinProtocolVersion?,
) : CtapRequest {
    override val command = CtapCommand.LARGE_BLOBS
}
