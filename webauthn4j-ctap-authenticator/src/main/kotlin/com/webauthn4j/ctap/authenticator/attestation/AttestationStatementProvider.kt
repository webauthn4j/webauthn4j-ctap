package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.AttestationStatement


interface AttestationStatementProvider {
    /**
     * Provides attestation statement
     */
    suspend fun provide(attestationStatementRequest: AttestationStatementRequest): AttestationStatement
}
