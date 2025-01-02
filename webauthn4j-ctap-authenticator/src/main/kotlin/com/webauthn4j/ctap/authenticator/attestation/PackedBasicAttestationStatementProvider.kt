package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate

class PackedBasicAttestationStatementProvider(
    private val subjectDN: String,
    private val attestationKeyPair: KeyPair,
    private val issuerPrivateKey: PrivateKey,
    private val signatureAlgorithm: SignatureAlgorithm,
    private val caCertificates: List<X509Certificate>,
    objectConverter: ObjectConverter
) : PackedAttestationStatementProviderBase(objectConverter) {

    override fun sign(credentialKey: KeyPair, toBeSigned: ByteArray): ByteArray {
        return SignatureCalculator.calculate(
            SignatureAlgorithm.ES256,
            attestationKeyPair.private,
            toBeSigned
        )
    }

    override fun createAttestationCertificatePath(attestationStatementRequest: AttestationStatementRequest): AttestationCertificatePath {
        val builder = AttestationCertificateBuilder(
            subjectDN,
            attestationKeyPair.public,
            caCertificates.first().subjectX500Principal.name,
            issuerPrivateKey,
            signatureAlgorithm,
        ).aaguid(attestationStatementRequest.authenticatorData.attestedCredentialData!!.aaguid)
        return AttestationCertificatePath(builder.build(), caCertificates)
    }

    companion object {
        /**
         * DO NOT USE for production use-case as the certificates are signed with hard coded private keys
         */
        @JvmStatic
        fun createWithDemoAttestationKey(): PackedBasicAttestationStatementProvider {
            return PackedBasicAttestationStatementProvider(
                DemoAttestationConstants.DEMO_ATTESTATION_NAME,
                KeyPair(
                    DemoAttestationConstants.DEMO_ATTESTATION_PUBLIC_KEY,
                    DemoAttestationConstants.DEMO_ATTESTATION_PRIVATE_KEY
                ),
                DemoAttestationConstants.DEMO_INTERMEDIATE_CA_PRIVATE_KEY,
                SignatureAlgorithm.ES256,
                listOf(DemoAttestationConstants.DEMO_INTERMEDIATE_CA_CERTIFICATE),
                ObjectConverter()
            )
        }
    }
}