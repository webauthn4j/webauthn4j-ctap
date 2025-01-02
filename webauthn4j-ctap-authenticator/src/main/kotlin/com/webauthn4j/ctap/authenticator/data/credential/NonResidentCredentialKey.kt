package com.webauthn4j.ctap.authenticator.data.credential

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.SignatureAlgorithm
import java.io.Serializable
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

class NonResidentCredentialKey : CredentialKey, Serializable {
    @JsonProperty("alg")
    override var alg: SignatureAlgorithm
        private set

    @JsonProperty("publicKey")
    private var publicKey: PublicKey

    @JsonProperty("privateKey")
    private var privateKey: PrivateKey

    constructor(
        alg: SignatureAlgorithm, keyPair: KeyPair
    ) {
        this.alg = alg
        publicKey = keyPair.public
        privateKey = keyPair.private
    }

    @JsonCreator
    constructor(
        @JsonProperty("alg") alg: SignatureAlgorithm,
        @JsonProperty("publicKey") publicKey: PublicKey,
        @JsonProperty("privateKey") privateKey: PrivateKey
    ) {
        this.alg = alg
        this.publicKey = publicKey
        this.privateKey = privateKey
    }

    override val keyPair: KeyPair
        @JsonIgnore
        get() = KeyPair(publicKey, privateKey)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as NonResidentCredentialKey

        if (alg != other.alg) return false
        if (publicKey != other.publicKey) return false
        if (privateKey != other.privateKey) return false

        return true
    }

    override fun hashCode(): Int {
        var result = alg.hashCode()
        result = 31 * result + publicKey.hashCode()
        result = 31 * result + privateKey.hashCode()
        return result
    }


}