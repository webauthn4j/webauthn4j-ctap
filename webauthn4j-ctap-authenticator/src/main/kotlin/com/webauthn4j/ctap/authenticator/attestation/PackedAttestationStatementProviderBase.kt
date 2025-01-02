package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import com.webauthn4j.data.attestation.statement.AttestationCertificatePath
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.attestation.statement.PackedAttestationStatement
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import java.nio.ByteBuffer
import java.security.KeyPair

abstract class PackedAttestationStatementProviderBase(
    objectConverter: ObjectConverter
) : AttestationStatementProvider {

    private var authenticatorDataConverter: AuthenticatorDataConverter =
        AuthenticatorDataConverter(objectConverter)

    override suspend fun provide(attestationStatementRequest: AttestationStatementRequest): PackedAttestationStatement {

        val authenticatorData: AuthenticatorData<RegistrationExtensionAuthenticatorOutput> =
            attestationStatementRequest.authenticatorData
        val authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData)
        val clientDataHash = attestationStatementRequest.clientDataHash
        val toBeSigned = ByteBuffer.allocate(authenticatorDataBytes.size + clientDataHash.size)
            .put(authenticatorDataBytes).put(clientDataHash).array()
        val alg: COSEAlgorithmIdentifier = attestationStatementRequest.alg
        val sig = sign(attestationStatementRequest.credentialKey.keyPair!!, toBeSigned)
        return PackedAttestationStatement(
            alg,
            sig,
            createAttestationCertificatePath(attestationStatementRequest)
        )
    }

    protected abstract fun sign(credentialKey: KeyPair, toBeSigned: ByteArray): ByteArray
    protected abstract fun createAttestationCertificatePath(attestationStatementRequest: AttestationStatementRequest): AttestationCertificatePath

}