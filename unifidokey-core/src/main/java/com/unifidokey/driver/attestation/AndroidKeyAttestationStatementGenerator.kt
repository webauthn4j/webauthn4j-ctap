package com.unifidokey.driver.attestation

import com.unifidokey.driver.persistence.dao.KeyStoreResidentCredentialKey
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.ctap.authenticator.store.CredentialKey
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement
import java.nio.ByteBuffer

class AndroidKeyAttestationStatementGenerator(objectConverter: ObjectConverter) :
    AttestationStatementGenerator {

    private val authenticatorDataConverter: AuthenticatorDataConverter =
        AuthenticatorDataConverter(objectConverter)

    override suspend fun generate(attestationStatementRequest: AttestationStatementRequest): AndroidKeyAttestationStatement {
        val clientDataHash = attestationStatementRequest.clientDataHash
        val authenticatorData = attestationStatementRequest.authenticatorData
        val authenticatorDataBytes = authenticatorDataConverter.convert(authenticatorData)
        val signedData = ByteBuffer.allocate(authenticatorDataBytes.size + clientDataHash.size)
            .put(authenticatorDataBytes).put(clientDataHash).array()
        val alg = attestationStatementRequest.alg
        require(supports(attestationStatementRequest.credentialKey)) { "provided userCredentialKey is not supported." }
        val keyStoreResidentUserCredentialKey =
            attestationStatementRequest.credentialKey as KeyStoreResidentCredentialKey
        val sig = SignatureCalculator.calculate(
            keyStoreResidentUserCredentialKey.alg,
            keyStoreResidentUserCredentialKey.keyPair.private,
            signedData
        )
        val attestationCertificatePath =
            keyStoreResidentUserCredentialKey.credentialAttestationCertificatePath
        return AndroidKeyAttestationStatement(alg, sig, attestationCertificatePath)
    }

    fun supports(credentialKey: CredentialKey): Boolean {
        return credentialKey is KeyStoreResidentCredentialKey
    }

}