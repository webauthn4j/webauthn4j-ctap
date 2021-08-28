package com.webauthn4j.ctap.authenticator

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import java.time.Instant

class U2FKeyEnvelope {
    companion object{
        @JvmStatic
        fun create(
            keyPair: EC2COSEKey,
            applicationParameter: ByteArray,
            createdAt: Instant): U2FKeyEnvelope {
            return U2FKeyEnvelope(1u, keyPair, applicationParameter, createdAt)
        }

        @JvmStatic
        @JsonCreator
        fun fromCbor(
            @JsonProperty("1") version: Byte,
            @JsonProperty("2") keyPair: EC2COSEKey,
            @JsonProperty("3") applicationParameter: ByteArray,
            @JsonProperty("4") createdAt: Long): U2FKeyEnvelope {
            return U2FKeyEnvelope(version.toUByte(), keyPair, applicationParameter, Instant.ofEpochSecond(createdAt))
        }
    }

    @Suppress("JoinDeclarationAndAssignment")
    val version: UByte
    val keyPair: EC2COSEKey
    val applicationParameter: ByteArray
    val createdAt: Instant

    constructor(
        version: UByte,
        keyPair: EC2COSEKey,
        applicationParameter: ByteArray,
        createdAt: Instant){
        this.version = version
        this.keyPair = keyPair
        this.applicationParameter = applicationParameter
        this.createdAt = createdAt
    }

}