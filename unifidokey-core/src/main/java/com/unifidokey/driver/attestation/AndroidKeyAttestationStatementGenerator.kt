package com.unifidokey.driver.attestation

import com.unifidokey.driver.persistence.dao.KeyStoreResidentUserCredentialKey
import com.webauthn4j.converter.AuthenticatorDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.ctap.authenticator.SignatureCalculator
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementGenerator
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.ctap.authenticator.store.UserCredentialKey
import com.webauthn4j.data.attestation.statement.AndroidKeyAttestationStatement
import com.webauthn4j.data.attestation.statement.AttestationStatement
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
        val alg = attestationStatementRequest.algorithmIdentifier
        require(supports(attestationStatementRequest.userCredentialKey)) { "provided userCredentialKey is not supported." }
        val keyStoreResidentUserCredentialKey =
            attestationStatementRequest.userCredentialKey as KeyStoreResidentUserCredentialKey
        val sig = SignatureCalculator.calculate(
            keyStoreResidentUserCredentialKey.alg,
            keyStoreResidentUserCredentialKey.keyPair.private,
            signedData
        )
        val attestationCertificatePath =
            keyStoreResidentUserCredentialKey.credentialAttestationCertificatePath
        return AndroidKeyAttestationStatement(alg, sig, attestationCertificatePath)
    }

    fun supports(userCredentialKey: UserCredentialKey): Boolean {
        return userCredentialKey is KeyStoreResidentUserCredentialKey
    }

}