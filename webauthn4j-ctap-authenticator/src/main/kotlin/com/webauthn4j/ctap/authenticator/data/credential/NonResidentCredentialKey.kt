package com.webauthn4j.ctap.authenticator.data.credential

import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.io.Serializable
import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class NonResidentCredentialKey @JsonCreator constructor(
    @JsonProperty("key") val coseKey: COSEKey
) : CredentialKey, Serializable {

    @get:JsonIgnore
    override val alg: SignatureAlgorithm
        get() = coseKey.algorithm!!.toSignatureAlgorithm()

    @get:JsonIgnore
    override val keyPair: KeyPair
        get() = KeyPair(coseKey.publicKey, coseKey.privateKey)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false
        other as NonResidentCredentialKey
        return coseKey == other.coseKey
    }

    override fun hashCode(): Int = coseKey.hashCode()

    companion object {
        fun create(algorithmIdentifier: COSEAlgorithmIdentifier, keyPair: KeyPair): NonResidentCredentialKey {
            val coseKey: COSEKey = when (keyPair.public) {
                is ECPublicKey -> EC2COSEKey.create(keyPair, algorithmIdentifier)
                is RSAPublicKey -> RSACOSEKey.create(keyPair, algorithmIdentifier)
                else -> throw IllegalArgumentException("Unsupported key type: ${keyPair.public.javaClass}")
            }
            return NonResidentCredentialKey(coseKey)
        }
    }
}
