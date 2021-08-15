package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator.calculate
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.util.function.Function

class PackedAttestationStatementGenerator : AttestationStatementGenerator {

    private var attestationPrivateKey: PrivateKey
    private var attestationCertificatePathGenerator: Function<AAGUID?, AttestationCertificatePath>
    private var authenticatorDataConverter: AuthenticatorDataConverter

    constructor(
        attestationPrivateKey: PrivateKey,
        attestationCertificatePath: AttestationCertificatePath,
        objectConverter: ObjectConverter
    ) {
        this.attestationPrivateKey = attestationPrivateKey
        attestationCertificatePathGenerator = Function { attestationCertificatePath }
        authenticatorDataConverter = AuthenticatorDataConverter(objectConverter)
    }

    constructor(
        subjectDN: String,
        attestationKeyPair: KeyPair,
        issuerPrivateKey: PrivateKey,
        caCertificates: List<X509Certificate>,
        objectConverter: ObjectConverter
    ) {
        attestationPrivateKey = attestationKeyPair.private
        attestationCertificatePathGenerator = Function { aaguid ->
            val attestationPublicKey = attestationKeyPair.public
            val attestationCertificate = createAttestationCertificate(
                subjectDN,
                attestationPublicKey,
                caCertificates.first().subjectDN.name,
                issuerPrivateKey,
                aaguid
            )
            AttestationCertificatePath(attestationCertificate, caCertificates)
        }
        authenticatorDataConverter = AuthenticatorDataConverter(objectConverter)
    }

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): PackedAttestationStatement {
        val authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput> =
            attestationStatementRequest.authenticatorData
        val authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData)
        val clientDataHash = attestationStatementRequest.clientDataHash
        val signedData = ByteBuffer.allocate(authenticatorDataBytes.size + clientDataHash.size)
            .put(authenticatorDataBytes).put(clientDataHash).array()
        val alg: COSEAlgorithmIdentifier = attestationStatementRequest.algorithmIdentifier
        val sig = calculate(
            SignatureAlgorithm.ES256,
            attestationPrivateKey,
            signedData
        ) //TODO revisit alg
        val aaguid = authenticatorData.attestedCredentialData!!.aaguid
        return PackedAttestationStatement(
            alg,
            sig,
            attestationCertificatePathGenerator.apply(aaguid)
        )
    }

    private fun createAttestationCertificate(
        subjectDN: String,
        attestationPublicKey: PublicKey,
        issuerDN: String,
        issuerPrivateKey: PrivateKey,
        aaguid: AAGUID?
    ): X509Certificate {
        val builder = AttestationCertificateBuilder(
            subjectDN,
            attestationPublicKey,
            issuerDN,
            issuerPrivateKey,
            aaguid!!
        )
        return builder.build()
    }

    companion object {
        /**
         * DO NOT USE for production use-case as the certificates are signed with hard coded private keys
         */
        @JvmStatic
        fun createWithDemoAttestation(): PackedAttestationStatementGenerator {
            return PackedAttestationStatementGenerator(
                DemoAttestationConstants.DEMO_ATTESTATION_NAME,
                KeyPair(
                    DemoAttestationConstants.DEMO_ATTESTATION_PUBLIC_KEY,
                    DemoAttestationConstants.DEMO_ATTESTATION_PRIVATE_KEY
                ),
                DemoAttestationConstants.DEMO_INTERMEDIATE_CA_PRIVATE_KEY,
                listOf(DemoAttestationConstants.DEMO_INTERMEDIATE_CA_CERTIFICATE),
                ObjectConverter()
            )
        }
    }
}