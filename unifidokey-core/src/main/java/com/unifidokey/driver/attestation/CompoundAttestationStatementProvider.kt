package com.unifidokey.driver.attestation

import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementProvider
import com.webauthn4j.ctap.authenticator.attestation.AttestationStatementRequest
import com.webauthn4j.data.attestation.statement.CompoundAttestationStatement

class CompoundAttestationStatementProvider(
    private val androidKeyAttestationStatementProvider: AndroidKeyAttestationStatementProvider,
    private val androidSafetyNetAttestationStatementProvider: AndroidSafetyNetAttestationStatementProvider) : AttestationStatementProvider {
    override suspend fun provide(attestationStatementRequest: AttestationStatementRequest): CompoundAttestationStatement {
        val androidKeyAttestationStatement = androidKeyAttestationStatementProvider.provide(attestationStatementRequest)
        val androidSafetyNetAttestationStatement = androidSafetyNetAttestationStatementProvider.provide(attestationStatementRequest)
        return CompoundAttestationStatement(androidKeyAttestationStatement, androidSafetyNetAttestationStatement)
    }


}