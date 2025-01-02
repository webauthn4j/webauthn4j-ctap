package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.FIDOU2FAttestationStatement
import com.webauthn4j.util.ECUtil
import java.nio.ByteBuffer
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey

class FIDOU2FBasicAttestationStatementProvider(
    private val attestationPrivateKey: PrivateKey,
    private val attestationCertificate: X509Certificate
) : FIDOU2FAttestationStatementProvider {

    override suspend fun generate(attestationStatementRequest: FIDOU2FAttestationStatementRequest): FIDOU2FAttestationStatement {
        val rfu: Byte = 0x00
        val toBeSigned =
            ByteBuffer.allocate(1 + 32 + 32 + attestationStatementRequest.keyHandle.size + 65)
                .put(rfu)
                .put(attestationStatementRequest.applicationParameter)
                .put(attestationStatementRequest.challengeParameter)
                .put(attestationStatementRequest.keyHandle)
                .put(ECUtil.createUncompressedPublicKey(attestationStatementRequest.credentialKey.public as ECPublicKey))
                .array()
        val sig = SignatureCalculator.calculate(
            SignatureAlgorithm.ES256,
            attestationPrivateKey,
            toBeSigned
        )
        return FIDOU2FAttestationStatement(
            AttestationCertificatePath(
                attestationCertificate,
                emptyList()
            ), sig
        )
    }

    companion object {
        /**
         * DO NOT USE for production use-case as the certificates are signed with hard coded private keys
         */
        @JvmStatic
        fun createWithDemoAttestationKey(): FIDOU2FBasicAttestationStatementProvider {
            return FIDOU2FBasicAttestationStatementProvider(
                DemoAttestationConstants.DEMO_ROOT_CA_PRIVATE_KEY,
                DemoAttestationConstants.DEMO_ROOT_CA_CERTIFICATE
            )
        }
    }

}
