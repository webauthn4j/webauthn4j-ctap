package com.webauthn4j.ctap.authenticator.attestation

import com.webauthn4j.data.attestation.statement.AttestationStatement

/**
 * Provides attestation statement
 */
interface AttestationStatementProvider {
    suspend fun provide(attestationStatementRequest: AttestationStatementRequest): AttestationStatement
}
