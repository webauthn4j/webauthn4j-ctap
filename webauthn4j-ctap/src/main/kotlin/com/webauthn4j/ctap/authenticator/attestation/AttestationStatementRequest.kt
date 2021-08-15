package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.ctap.authenticator.store.CredentialKey
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.authenticator.COSEKey
import com.webauthn4j.data.attestation.authenticator.EC2COSEKey
import com.webauthn4j.data.attestation.authenticator.RSACOSEKey
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.util.ArrayUtil
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

class AttestationStatementRequest(
    rpIdHash: ByteArray?,
    algorithmIdentifier: COSEAlgorithmIdentifier,
    credentialId: ByteArray?,
    clientDataHash: ByteArray?,
    residentKey: Boolean,
    credentialKey: CredentialKey,
    authenticatorDataProvider: AuthenticatorDataProvider
) {


    val rpIdHash: ByteArray
        get() = ArrayUtil.clone(field)
    val algorithmIdentifier: COSEAlgorithmIdentifier
    val credentialId: ByteArray
        get() = ArrayUtil.clone(field)
    val clientDataHash: ByteArray
        get() = ArrayUtil.clone(field)
    val residentKey: Boolean
    private val authenticatorDataProvider: AuthenticatorDataProvider
    val credentialKey: CredentialKey

    init {
        this.rpIdHash = ArrayUtil.clone(rpIdHash)
        this.algorithmIdentifier = algorithmIdentifier
        this.credentialId = ArrayUtil.clone(credentialId)
        this.clientDataHash = ArrayUtil.clone(clientDataHash)
        this.residentKey = residentKey
        this.credentialKey = credentialKey
        this.authenticatorDataProvider = authenticatorDataProvider
    }

    val authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput>
        get() {
            val credentialPublicKey: COSEKey
            val keyPair =
                credentialKey.keyPair ?: throw IllegalStateException("keyPair must not be null")
            keyPair.let {
                val alg = it.public.algorithm
                credentialPublicKey = when (alg) {
                    "EC" -> EC2COSEKey.create((it.public as ECPublicKey), algorithmIdentifier)
                    "RSA" -> RSACOSEKey.create((it.public as RSAPublicKey), algorithmIdentifier)
                    else -> throw IllegalArgumentException(
                        String.format(
                            "algorithm %s of userCredentialKey is not supported.",
                            alg
                        )
                    )
                }
                return authenticatorDataProvider.provide(credentialId, credentialPublicKey)
            }
        }

    interface AuthenticatorDataProvider {
        fun provide(
            credentialId: ByteArray,
            credentialPublicKey: COSEKey
        ): AuthenticatorData<RegistrationExtensionAuthenticatorOutput>
    }

}