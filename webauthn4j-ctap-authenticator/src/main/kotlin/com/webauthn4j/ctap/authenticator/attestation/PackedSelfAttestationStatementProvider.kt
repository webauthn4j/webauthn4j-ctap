package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import java.security.KeyPair

class PackedSelfAttestationStatementProvider(
    private val subjectDN: String,
    objectConverter: ObjectConverter
) : PackedAttestationStatementProviderBase(objectConverter) {

    override fun sign(credentialKey: KeyPair, toBeSigned: ByteArray, alg: COSEAlgorithmIdentifier): ByteArray {
        return SignatureCalculator.calculate(
            alg.toSignatureAlgorithm(),
            credentialKey.private,
            toBeSigned
        )
    }

    override fun createAttestationCertificatePath(attestationStatementRequest: AttestationStatementRequest): AttestationCertificatePath {
        val signatureAlgorithm = attestationStatementRequest.alg.toSignatureAlgorithm()
        val x509Certificate = AttestationCertificateBuilder(
            subjectDN,
            attestationStatementRequest.credentialKey.keyPair!!.public,
            subjectDN,
            attestationStatementRequest.credentialKey.keyPair!!.private,
            signatureAlgorithm
        )
            .aaguid(attestationStatementRequest.authenticatorData.attestedCredentialData!!.aaguid)
            .build()
        return AttestationCertificatePath(x509Certificate, emptyList())
    }
}
