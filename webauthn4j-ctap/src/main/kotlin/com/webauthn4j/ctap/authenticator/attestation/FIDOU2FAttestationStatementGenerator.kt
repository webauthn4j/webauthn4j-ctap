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

class FIDOU2FAttestationStatementGenerator(
    private val attestationPrivateKey: PrivateKey,
    attestationCertificate: X509Certificate
) : AttestationStatementGenerator {

    companion object {
        /**
         * DO NOT USE for production use-case as the certificates are signed with hard coded private keys
         */
        @JvmStatic
        fun createWithDemoAttestation(): FIDOU2FAttestationStatementGenerator {
            return FIDOU2FAttestationStatementGenerator(
                DemoAttestationConstants.DEMO_ROOT_CA_PRIVATE_KEY,
                DemoAttestationConstants.DEMO_ROOT_CA_CERTIFICATE
            )
        }
    }

    private val attestationCertificatePath: AttestationCertificatePath =
        AttestationCertificatePath(attestationCertificate, emptyList())

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): FIDOU2FAttestationStatement {

        val publicKey = attestationStatementRequest.userCredentialKey.keyPair!!.public
        if(publicKey !is ECPublicKey){
            throw IllegalArgumentException("attestationStatementRequest.userCredentialKey.keyPair must be Elliptic Curve key pair.")
        }

        val request = FIDOU2FAttestationStatementRequest(
            userPublicKey = attestationStatementRequest.userCredentialKey.keyPair!!.public as ECPublicKey,
            keyHandle = attestationStatementRequest.credentialId,
            applicationParameter = attestationStatementRequest.rpIdHash,
            challengeParameter = attestationStatementRequest.clientDataHash
        )
        return generate(request)
    }

    suspend fun generate(attestationStatementRequest: FIDOU2FAttestationStatementRequest): FIDOU2FAttestationStatement {
        val rfu: Byte = 0x00
        val signedData = ByteBuffer.allocate(1 + 32 + 32 + attestationStatementRequest.keyHandle.size + 65)
            .put(rfu)
            .put(attestationStatementRequest.applicationParameter)
            .put(attestationStatementRequest.challengeParameter)
            .put(attestationStatementRequest.keyHandle)
            .put(ECUtil.createUncompressedPublicKey(attestationStatementRequest.userPublicKey))
            .array()
        val sig = SignatureCalculator.calculate(
            SignatureAlgorithm.ES256,
            attestationPrivateKey,
            signedData
        )
        return FIDOU2FAttestationStatement(attestationCertificatePath, sig)
    }
}
