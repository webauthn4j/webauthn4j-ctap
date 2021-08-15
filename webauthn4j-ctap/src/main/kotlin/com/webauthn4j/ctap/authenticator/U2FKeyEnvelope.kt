package com.webauthn4j.ctap.authenticator

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import java.time.Instant

class U2FKeyEnvelope {
    val version: Int
    val privateKey: EC2COSEKey
    val applicationParameter: ByteArray
    val createdAt: Instant

    @JsonCreator
    constructor(
        @JsonProperty("version") version: Int,
        @JsonProperty("keyPair") privateKey: EC2COSEKey,
        @JsonProperty("applicationParameter") applicationParameter: ByteArray,
        @JsonProperty("createdAt") createdAt: Instant){
        this.version = version
        this.privateKey = privateKey
        this.applicationParameter = applicationParameter
        this.createdAt = createdAt
    }

    constructor(
        privateKey: EC2COSEKey,
        applicationParameter: ByteArray,
        createdAt: Instant) {
        this.version = 1
        this.privateKey = privateKey
        this.applicationParameter = applicationParameter
        this.createdAt = createdAt
    }

}