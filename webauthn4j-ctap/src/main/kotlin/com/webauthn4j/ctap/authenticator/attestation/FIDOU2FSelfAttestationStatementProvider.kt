package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import com.webauthn4j.util.ECUtil
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.interfaces.ECPublicKey

class FIDOU2FSelfAttestationStatementProvider(
    private val subjectDN: String
) : FIDOU2FAttestationStatementProvider {

    override suspend fun generate(attestationStatementRequest: FIDOU2FAttestationStatementRequest): FIDOU2FAttestationStatement {
        val rfu: Byte = 0x00
        val toBeSigned = ByteBuffer.allocate(1 + 32 + 32 + attestationStatementRequest.keyHandle.size + 65)
            .put(rfu)
            .put(attestationStatementRequest.applicationParameter)
            .put(attestationStatementRequest.challengeParameter)
            .put(attestationStatementRequest.keyHandle)
            .put(ECUtil.createUncompressedPublicKey(attestationStatementRequest.credentialKey.public as ECPublicKey))
            .array()
        val sig = SignatureCalculator.calculate(
            SignatureAlgorithm.ES256,
            attestationStatementRequest.credentialKey.private,
            toBeSigned
        )
        val credentialKey = attestationStatementRequest.credentialKey
        val x509Certificate = AttestationCertificateBuilder(subjectDN, credentialKey.public, subjectDN, credentialKey.private, SignatureAlgorithm.ES256).build()
        val attestationCertificatePath = AttestationCertificatePath(x509Certificate, emptyList())
        return FIDOU2FAttestationStatement(attestationCertificatePath, sig)
    }
}
