package com.webauthn4j.ctap.core.data

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty

class AuthenticatorLargeBlobsResponseData @JsonCreator constructor(@JsonProperty("1") val config: ByteArray) : CtapResponseData
