package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.data.SignatureAlgorithm
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import java.security.KeyPair

class PackedSelfAttestationStatementProvider(
    objectConverter: ObjectConverter
) : PackedAttestationStatementProviderBase(objectConverter) {

    override fun sign(credentialKey: KeyPair, toBeSigned: ByteArray): ByteArray {
        return SignatureCalculator.calculate(
            SignatureAlgorithm.ES256,
            credentialKey.private,
            toBeSigned
        )
    }

    override fun createAttestationCertificatePath(attestationStatementRequest: AttestationStatementRequest): AttestationCertificatePath? {
        return null
    }
}
