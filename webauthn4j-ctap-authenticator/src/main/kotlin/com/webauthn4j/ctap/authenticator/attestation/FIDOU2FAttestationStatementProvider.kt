package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import java.security.interfaces.ECPublicKey

interface FIDOU2FAttestationStatementProvider : AttestationStatementProvider {

    override suspend fun provide(attestationStatementRequest: AttestationStatementRequest): FIDOU2FAttestationStatement {

        val publicKey = attestationStatementRequest.credentialKey.keyPair!!.public
        if (publicKey !is ECPublicKey) {
            throw IllegalArgumentException("attestationStatementRequest.userCredentialKey.keyPair must be Elliptic Curve key pair.")
        }

        val request = FIDOU2FAttestationStatementRequest(
            credentialKey = attestationStatementRequest.credentialKey.keyPair!!,
            keyHandle = attestationStatementRequest.credentialId,
            applicationParameter = attestationStatementRequest.rpIdHash,
            challengeParameter = attestationStatementRequest.clientDataHash
        )
        return generate(request)
    }

    suspend fun generate(attestationStatementRequest: FIDOU2FAttestationStatementRequest): FIDOU2FAttestationStatement
}